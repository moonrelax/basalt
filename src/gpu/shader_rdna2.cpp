#include "gpu/shader_rdna2.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace emu::gpu {
namespace {

constexpr int kSgpr = 106;

uint32_t load32(const uint8_t* p) {
    uint32_t w = 0;
    for (int b = 0; b < 4; ++b) w |= static_cast<uint32_t>(p[b]) << (8 * b);
    return w;
}

uint32_t f2u(float f) { uint32_t u; std::memcpy(&u, &f, 4); return u; }
float u2f(uint32_t u) { float f; std::memcpy(&f, &u, 4); return f; }

uint32_t src_bits(uint32_t src, const uint32_t v[], const uint32_t s[], uint32_t lit) {
    if (src < static_cast<uint32_t>(kSgpr)) return s[src];
    if (src >= 256 && src < 256u + static_cast<uint32_t>(kVgprCount)) return v[src - 256];
    if (src == 128) return 0;
    if (src >= 129 && src <= 192) return src - 128;
    if (src >= 193 && src <= 208) return static_cast<uint32_t>(static_cast<int32_t>(192 - static_cast<int>(src)));
    if (src == 255) return lit;
    float f = 0.f;
    switch (src) {
        case 240: f = 0.5f; break;
        case 241: f = -0.5f; break;
        case 242: f = 1.f; break;
        case 243: f = -1.f; break;
        case 244: f = 2.f; break;
        case 245: f = -2.f; break;
        case 246: f = 4.f; break;
        case 247: f = -4.f; break;
        case 248: f = 0.15915494f; break; // 1/(2*pi)
        default: return 0;
    }
    return f2u(f);
}

uint32_t vgpr(uint32_t idx, const uint32_t v[]) {
    return idx < static_cast<uint32_t>(kVgprCount) ? v[idx] : 0;
}

void store_v(uint32_t dst, uint32_t bits, uint32_t v[]) {
    if (dst < static_cast<uint32_t>(kVgprCount)) v[dst] = bits;
}

float as_float(uint32_t bits) { return u2f(bits); }

uint32_t apply_vop2(uint32_t op, uint32_t s0, uint32_t s1, uint32_t dst_bits, bool vcc) {
    const float a = as_float(s0);
    const float b = as_float(s1);
    const float d = as_float(dst_bits);
    switch (op) {
        case 0: return vcc ? s1 : s0;                              // v_cndmask_b32
        case 1: return f2u(a + b);                                 // v_add_f32
        case 2: return f2u(a - b);                                 // v_sub_f32
        case 3: return f2u(b - a);                                 // v_subrev_f32
        case 4: return f2u(a * b);                                 // v_mul_legacy_f32
        case 5: return f2u(a * b);                                 // v_mul_f32
        case 10: return f2u(std::fmin(a, b));                      // v_min_f32
        case 11: return f2u(std::fmax(a, b));                      // v_max_f32
        case 12: return static_cast<uint32_t>(std::min(static_cast<int32_t>(s0), static_cast<int32_t>(s1)));
        case 13: return static_cast<uint32_t>(std::max(static_cast<int32_t>(s0), static_cast<int32_t>(s1)));
        case 14: return std::min(s0, s1);
        case 15: return std::max(s0, s1);
        case 16: return s1 >> (s0 & 31);                           // v_lshrrev_b32
        case 17: return static_cast<uint32_t>(static_cast<int32_t>(s1) >> (s0 & 31));
        case 18: return s1 << (s0 & 31);                           // v_lshlrev_b32
        case 19: return s0 & s1;                                   // v_and_b32
        case 20: return s0 | s1;
        case 21: return s0 ^ s1;
        case 22: return f2u(a * b + d);                            // v_mac_f32
        default: return dst_bits;
    }
}

bool vopc(uint32_t op, uint32_t s0, uint32_t s1) {
    const float a = as_float(s0);
    const float b = as_float(s1);
    switch (op) {
        case 0x01: return a < b;                                   // v_cmp_lt_f32
        case 0x02: return a == b;
        case 0x03: return a <= b;
        case 0x04: return a > b;
        case 0x05: return a != b;
        case 0x06: return a >= b;
        case 0x07: return true;                                    // v_cmp_tru_f32
        case 0x81: return static_cast<int32_t>(s0) < static_cast<int32_t>(s1);
        case 0x82: return s0 == s1;
        case 0x83: return static_cast<int32_t>(s0) <= static_cast<int32_t>(s1);
        case 0x84: return static_cast<int32_t>(s0) > static_cast<int32_t>(s1);
        case 0xC1: return s0 < s1;
        case 0xC2: return s0 == s1;
        default: return false;
    }
}

float madd(float a, float b, float c) { return a * b + c; }

float clamp01(float x, bool clamp) {
    if (!clamp) return x;
    if (x < 0.f) return 0.f;
    if (x > 1.f) return 1.f;
    return x;
}

} // namespace

bool exec_rdna2(const uint8_t* code, uint32_t size, float v_in[kVgprCount], RdnaOut& out) {
    if (!code || size < 4 || !v_in) return false;
    uint32_t v[kVgprCount] = {};
    uint32_t s[kSgpr] = {};
    for (int i = 0; i < kVgprCount; ++i) v[i] = f2u(v_in[i]);
    bool vcc = false;
    bool scc = false;
    uint32_t pc = 0;
    int steps = 0;
    while (pc + 4 <= size && steps++ < 100000) {
        const uint32_t w = load32(code + pc);
        const uint32_t enc7 = w >> 25;
        uint32_t lit = 0;
        auto take_lit = [&](bool need) {
            if (!need) return;
            if (pc + 8 <= size) lit = load32(code + pc + 4);
        };

        if (enc7 == 0x3E || enc7 == 0x3F || (w & 0x80000000u) == 0) {
            const uint32_t src0 = w & 0x1FF;
            const bool has_lit = src0 == 255;
            take_lit(has_lit);
            const uint32_t next = pc + 4 + (has_lit ? 4 : 0);
            if (enc7 == 0x3E) {
                const uint32_t op = (w >> 9) & 0xFF;
                const uint32_t vsrc1 = (w >> 17) & 0xFF;
                vcc = vopc(op, src_bits(src0, v, s, lit), vgpr(vsrc1, v));
                scc = vcc;
            } else if (enc7 == 0x3F) {
                const uint32_t op = (w >> 9) & 0xFF;
                const uint32_t dst = (w >> 17) & 0xFF;
                const uint32_t bits = src_bits(src0, v, s, lit);
                const float a = as_float(bits);
                uint32_t r = bits;
                switch (op) {
                    case 1: r = bits; break;                                    // v_mov_b32
                    case 5: r = f2u(static_cast<float>(static_cast<int32_t>(bits))); break;
                    case 6: r = f2u(static_cast<float>(bits)); break;           // v_cvt_f32_u32
                    case 7: r = static_cast<uint32_t>(a); break;                // v_cvt_u32_f32
                    case 8: r = static_cast<uint32_t>(static_cast<int32_t>(a)); break;
                    case 9: r = bits; break;                                    // v_mov_fed_b32
                    case 32: r = f2u(a - std::floor(a)); break;                 // v_fract_f32
                    case 33: r = f2u(std::trunc(a)); break;
                    case 34: r = f2u(std::ceil(a)); break;
                    case 35: r = f2u(std::round(a)); break;                     // v_rndne_f32
                    case 36: r = f2u(std::floor(a)); break;
                    case 37: r = f2u(std::exp2(a)); break;
                    case 39: r = (a > 0.f) ? f2u(std::log2(a)) : 0; break;
                    case 42: r = (a != 0.f) ? f2u(1.f / a) : 0; break;          // v_rcp_f32
                    case 46: r = (a > 0.f) ? f2u(1.f / std::sqrt(a)) : 0; break;
                    case 51: r = (a >= 0.f) ? f2u(std::sqrt(a)) : 0; break;
                    case 53: r = f2u(std::sin(a)); break;
                    case 54: r = f2u(std::cos(a)); break;
                    case 55: r = ~bits; break;                                  // v_not_b32
                    default: pc = next; continue;
                }
                store_v(dst, r, v);
            } else {
                const uint32_t op = (w >> 25) & 0x3F;
                const uint32_t dst = (w >> 17) & 0xFF;
                const uint32_t vsrc1 = (w >> 9) & 0xFF;
                const uint32_t s0 = src_bits(src0, v, s, lit);
                const uint32_t s1 = vgpr(vsrc1, v);
                const uint32_t cur = vgpr(dst, v);
                store_v(dst, apply_vop2(op, s0, s1, cur, vcc), v);
            }
            pc = next;
            continue;
        }

        const uint32_t enc6 = w >> 26;
        if (enc6 == 0x3E) {
            if (pc + 8 > size) return out.color_written;
            const uint32_t hi = load32(code + pc + 4);
            const uint32_t en = w & 0xF;
            const uint32_t target = (w >> 4) & 0x3F;
            const uint32_t ch[4] = {hi & 0xFF, (hi >> 8) & 0xFF, (hi >> 16) & 0xFF, (hi >> 24) & 0xFF};
            float* dest = nullptr;
            bool* flag = nullptr;
            if (target == 0) { dest = out.color; flag = &out.color_written; }
            else if (target == 12) { dest = out.pos; flag = &out.pos_written; }
            if (dest) {
                for (int c = 0; c < 4; ++c) {
                    if ((en & (1u << c)) && ch[c] < static_cast<uint32_t>(kVgprCount))
                        dest[c] = as_float(v[ch[c]]);
                }
                *flag = true;
            }
            pc += 8;
            continue;
        }
        if (enc6 == 0x34) {
            if (pc + 8 > size) return out.color_written;
            const uint32_t hi = load32(code + pc + 4);
            const uint32_t s0i = hi & 0x1FF;
            const uint32_t s1i = (hi >> 9) & 0x1FF;
            const uint32_t s2i = (hi >> 18) & 0x1FF;
            const bool has_lit = s0i == 255 || s1i == 255 || s2i == 255;
            if (has_lit && pc + 12 <= size) lit = load32(code + pc + 8);
            const uint32_t op = (w >> 16) & 0x3FF;
            const uint32_t dst = w & 0xFF;
            const bool clamp = ((w >> 15) & 1) != 0;
            const uint32_t absm = (w >> 8) & 7;
            const uint32_t negm = (hi >> 29) & 7;
            auto operand = [&](uint32_t src, int lane) {
                float f = as_float(src_bits(src, v, s, lit));
                if ((absm >> lane) & 1) f = std::fabs(f);
                if ((negm >> lane) & 1) f = -f;
                return f;
            };
            const float a = operand(s0i, 0);
            const float b = operand(s1i, 1);
            const float c = operand(s2i, 2);
            float r = as_float(vgpr(dst, v));
            bool wrote = true;
            if (op < 0x40) {
                store_v(dst, apply_vop2(op, f2u(a), f2u(b), vgpr(dst, v), vcc), v);
                wrote = false;
            } else if (op == 0x1C1 || op == 0x1CB) {
                r = madd(a, b, c);                                      // v_mad_f32 / v_fma_f32
            } else if (op == 0x1D0) {
                r = std::fmax(a, std::fmax(b, c));                      // v_max3_f32
            } else if (op == 0x1D1) {
                r = std::fmin(a, std::fmin(b, c));
            } else if (op == 0x1D2) {
                r = std::fmax(std::fmin(a, b), std::fmin(std::fmax(a, b), c));
            } else {
                wrote = false;
            }
            if (wrote) store_v(dst, f2u(clamp01(r, clamp)), v);
            pc += 8 + (has_lit ? 4 : 0);
            continue;
        }
        if ((w >> 23) == 0x17F) {
            const uint32_t op = (w >> 16) & 0x7F;
            const int32_t simm = static_cast<int16_t>(w & 0xFFFF);
            const uint32_t next = pc + 4;
            auto branch = [&](bool take) {
                if (!take) { pc = next; return; }
                const int32_t dest = static_cast<int32_t>(next) + simm * 4;
                if (dest < 0 || static_cast<uint32_t>(dest) + 4 > size) pc = size;
                else pc = static_cast<uint32_t>(dest);
            };
            if (op == 1) break;                                         // s_endpgm
            if (op == 2) branch(true);                                  // s_branch
            else if (op == 4) branch(!scc);
            else if (op == 5) branch(scc);
            else if (op == 6) branch(!vcc);
            else if (op == 7) branch(vcc);
            else if (op == 8) branch(false);                            // exec is live on this lane
            else if (op == 9) branch(true);
            else pc = next;
            continue;
        }
        if ((w >> 23) == 0x17D) {
            const uint32_t dst = (w >> 16) & 0x7F;
            const uint32_t op = (w >> 8) & 0xFF;
            const uint32_t src = w & 0xFF;
            const bool has_lit = src == 255;
            take_lit(has_lit);
            if (op == 3 && dst < static_cast<uint32_t>(kSgpr))          // s_mov_b32
                s[dst] = src_bits(src, v, s, lit);
            pc += 4 + (has_lit ? 4 : 0);
            continue;
        }
        if ((w >> 28) == 0xB) {
            pc += 4;
            continue;
        }
        if ((w & 0xC0000000u) == 0x80000000u) {
            const uint32_t op = (w >> 23) & 0x7F;
            const uint32_t dst = (w >> 16) & 0x7F;
            const uint32_t s1 = (w >> 8) & 0xFF;
            const uint32_t s0 = w & 0xFF;
            const bool has_lit = s0 == 255 || s1 == 255;
            take_lit(has_lit);
            if (dst < static_cast<uint32_t>(kSgpr)) {
                const uint32_t a = src_bits(s0, v, s, lit);
                const uint32_t b = src_bits(s1, v, s, lit);
                if (op == 0) {                                          // s_add_u32
                    const uint64_t sum = static_cast<uint64_t>(a) + b;
                    s[dst] = static_cast<uint32_t>(sum);
                    scc = sum > 0xffffffffu;
                } else if (op == 1) {                                   // s_sub_u32
                    s[dst] = a - b;
                    scc = a < b;
                } else if (op == 14) {                                  // s_and_b32
                    s[dst] = a & b;
                    scc = s[dst] != 0;
                }
            }
            pc += 4 + (has_lit ? 4 : 0);
            continue;
        }
        if (enc6 == 0x30 || enc6 == 0x36 || enc6 == 0x37 || enc6 == 0x38) {
            pc += 8;
            continue;
        }
        pc += 4;
    }
    for (int i = 0; i < kVgprCount; ++i) v_in[i] = as_float(v[i]);
    return out.color_written;
}

} // namespace emu::gpu
