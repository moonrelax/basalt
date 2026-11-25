#include "gpu/shader_rdna2.h"

namespace emu::gpu {
namespace {

float src_f(uint32_t src, const float v[kVgprCount]) {
    if (src >= 256 && src < 256 + kVgprCount) return v[src - 256];
    if (src == 128) return 0.f;
    if (src == 240) return 0.5f;
    if (src == 242) return 1.f;
    return 0.f;
}

} // namespace

bool exec_rdna2(const uint8_t* code, uint32_t size, float v[kVgprCount], float exported[4]) {
    if (!code || size < 4) return false;
    bool exported_any = false;
    uint32_t i = 0;
    while (i + 4 <= size) {
        uint32_t w = 0;
        for (int b = 0; b < 4; ++b) w |= static_cast<uint32_t>(code[i + b]) << (8 * b);
        const uint32_t enc = w >> 25;
        if (enc == 0x3F) {
            const uint32_t op = (w >> 9) & 0xFF;
            const uint32_t dst = (w >> 17) & 0xFF;
            const uint32_t src = w & 0x1FF;
            if (op != 1 || dst >= kVgprCount) return false;
            v[dst] = src_f(src, v);
            i += 4;
            continue;
        }
        if ((w >> 26) == 0x3E) {
            if (i + 8 > size) return false;
            uint32_t hi = 0;
            for (int b = 0; b < 4; ++b) hi |= static_cast<uint32_t>(code[i + 4 + b]) << (8 * b);
            const uint32_t en = w & 0xF;
            const uint32_t target = (w >> 4) & 0x3F;
            if (target == 0) {
                const uint32_t ch[4] = {hi & 0xFF, (hi >> 8) & 0xFF, (hi >> 16) & 0xFF, (hi >> 24) & 0xFF};
                for (int c = 0; c < 4; ++c) {
                    if ((en & (1u << c)) && ch[c] < kVgprCount) exported[c] = v[ch[c]];
                }
                exported_any = true;
            }
            i += 8;
            continue;
        }
        if ((w & 0x80000000u) == 0 && enc != 0x3E) {
            const uint32_t op = (w >> 25) & 0x3F;
            const uint32_t dst = (w >> 17) & 0xFF;
            const uint32_t src1 = (w >> 9) & 0xFF;
            const uint32_t src0 = w & 0x1FF;
            if (dst >= kVgprCount || src1 >= kVgprCount) return false;
            if (op == 3) v[dst] = src_f(src0, v) + v[src1];
            else if (op == 8) v[dst] = src_f(src0, v) * v[src1];
            else return false;
            i += 4;
            continue;
        }
        return false;
    }
    return exported_any;
}

} // namespace emu::gpu
