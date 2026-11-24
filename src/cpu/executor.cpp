#include "cpu/cpu.h"
#include "cpu/decoder.h"
#include <stdexcept>
#include <cstring>
#include <cmath>
#include <climits>
#include <bit>

namespace emu::cpu {

// ── helpers ──────────────────────────────────────────────────────────────────

static inline uint64_t size_mask(int sz) {
    if (sz >= 8) return ~0ULL;
    return (1ULL << (sz * 8)) - 1;
}

static inline uint64_t& gpr64(Registers& r, int idx) {
    switch (idx & 15) {
        case  0: return r.rax; case  1: return r.rcx;
        case  2: return r.rdx; case  3: return r.rbx;
        case  4: return r.rsp; case  5: return r.rbp;
        case  6: return r.rsi; case  7: return r.rdi;
        case  8: return r.r8;  case  9: return r.r9;
        case 10: return r.r10; case 11: return r.r11;
        case 12: return r.r12; case 13: return r.r13;
        case 14: return r.r14; default: return r.r15;
    }
}

static inline uint64_t read_gpr(const Registers& r, int idx, int sz) {
    uint64_t v = const_cast<uint64_t&>(gpr64(const_cast<Registers&>(r), idx));
    return v & size_mask(sz);
}

static inline void write_gpr(Registers& r, int idx, int sz, uint64_t val) {
    uint64_t& reg = gpr64(r, idx);
    if (sz == 4) {
        reg = val & 0xFFFFFFFFULL; // zero-extend to 64
    } else if (sz == 8) {
        reg = val;
    } else {
        uint64_t mask = size_mask(sz);
        reg = (reg & ~mask) | (val & mask);
    }
}

static inline bool flag_cf(const Registers& r) { return (r.rflags >> 0) & 1; }
static inline bool flag_pf(const Registers& r) { return (r.rflags >> 2) & 1; }
static inline bool flag_af(const Registers& r) { return (r.rflags >> 4) & 1; }
static inline bool flag_zf(const Registers& r) { return (r.rflags >> 6) & 1; }
static inline bool flag_sf(const Registers& r) { return (r.rflags >> 7) & 1; }
static inline bool flag_of(const Registers& r) { return (r.rflags >> 11) & 1; }
static inline bool flag_df(const Registers& r) { return (r.rflags >> 10) & 1; }

static inline void set_flag(Registers& r, int bit, bool v) {
    if (v) r.rflags |= (1ULL << bit);
    else   r.rflags &= ~(1ULL << bit);
}

static inline void update_pzs(Registers& r, uint64_t result, int sz) {
    uint64_t m = size_mask(sz);
    uint64_t v = result & m;
    set_flag(r, 6, v == 0);                             // ZF
    set_flag(r, 7, (v >> (sz * 8 - 1)) & 1);            // SF
    set_flag(r, 2, !(__builtin_parityll(v & 0xFF)));     // PF
}

static uint64_t flags_add(Registers& r, uint64_t dst, uint64_t src, uint64_t cin, int sz) {
    uint64_t m = size_mask(sz);
    uint64_t d = dst & m, s = src & m;
    unsigned __int128 sum = static_cast<unsigned __int128>(d) + static_cast<unsigned __int128>(s) + (cin & 1);
    uint64_t result = static_cast<uint64_t>(sum) & m;
    update_pzs(r, result, sz);
    set_flag(r, 0,  sum > m);                                                       // CF
    set_flag(r, 4,  ((d ^ s ^ result) >> 4) & 1);                                   // AF
    set_flag(r, 11, ((~(d ^ s) & (d ^ result)) >> (sz * 8 - 1)) & 1);              // OF
    return result;
}

static uint64_t flags_sub(Registers& r, uint64_t dst, uint64_t src, uint64_t bin, int sz) {
    uint64_t m = size_mask(sz);
    uint64_t d = dst & m, s = src & m;
    unsigned __int128 subtrahend = static_cast<unsigned __int128>(s) + (bin & 1);
    uint64_t result = (d - s - (bin & 1)) & m;
    update_pzs(r, result, sz);
    set_flag(r, 0,  static_cast<unsigned __int128>(d) < subtrahend);                // CF
    set_flag(r, 4,  ((d ^ s ^ result) >> 4) & 1);                                   // AF
    set_flag(r, 11, (((d ^ s) & (d ^ result)) >> (sz * 8 - 1)) & 1);               // OF
    return result;
}

static void flags_logic(Registers& r, uint64_t res, int sz) {
    update_pzs(r, res, sz);
    set_flag(r, 0,  false); // CF=0
    set_flag(r, 11, false); // OF=0
}

static bool eval_cc(const Registers& r, Mnemonic m) {
    switch (m) {
        case Mnemonic::JO:   case Mnemonic::CMOVO:  case Mnemonic::SETO:   return  flag_of(r);
        case Mnemonic::JNO:  case Mnemonic::CMOVNO: case Mnemonic::SETNO:  return !flag_of(r);
        case Mnemonic::JB:   case Mnemonic::CMOVB:  case Mnemonic::SETB:   return  flag_cf(r);
        case Mnemonic::JNB:  case Mnemonic::CMOVNB: case Mnemonic::SETNB:  return !flag_cf(r);
        case Mnemonic::JZ:   case Mnemonic::CMOVZ:  case Mnemonic::SETZ:   return  flag_zf(r);
        case Mnemonic::JNZ:  case Mnemonic::CMOVNZ: case Mnemonic::SETNZ:  return !flag_zf(r);
        case Mnemonic::JBE:  case Mnemonic::CMOVBE: case Mnemonic::SETBE:  return  flag_cf(r) || flag_zf(r);
        case Mnemonic::JA:   case Mnemonic::CMOVA:  case Mnemonic::SETA:   return !flag_cf(r) && !flag_zf(r);
        case Mnemonic::JS:   case Mnemonic::CMOVS:  case Mnemonic::SETS:   return  flag_sf(r);
        case Mnemonic::JNS:  case Mnemonic::CMOVNS: case Mnemonic::SETNS:  return !flag_sf(r);
        case Mnemonic::JP:   case Mnemonic::CMOVP:  case Mnemonic::SETP:   return  flag_pf(r);
        case Mnemonic::JNP:  case Mnemonic::CMOVNP: case Mnemonic::SETNP:  return !flag_pf(r);
        case Mnemonic::JL:   case Mnemonic::CMOVL:  case Mnemonic::SETL:   return  flag_sf(r) != flag_of(r);
        case Mnemonic::JGE:  case Mnemonic::CMOVGE: case Mnemonic::SETGE:  return  flag_sf(r) == flag_of(r);
        case Mnemonic::JLE:  case Mnemonic::CMOVLE: case Mnemonic::SETLE:  return  flag_zf(r) || (flag_sf(r) != flag_of(r));
        case Mnemonic::JG:   case Mnemonic::CMOVG:  case Mnemonic::SETG:   return !flag_zf(r) && (flag_sf(r) == flag_of(r));
        default: return false;
    }
}

// ── CPU member helpers ────────────────────────────────────────────────────────

uint64_t CPU::eff_addr(const Operand& op) {
    uint64_t addr = 0;
    if (op.rip_rel) {
        addr = regs_.rip + static_cast<uint64_t>(op.disp);
    } else {
        if (op.base  >= 0) addr += gpr64(regs_, op.base);
        if (op.index >= 0) addr += gpr64(regs_, op.index) * op.scale;
        addr += static_cast<uint64_t>(op.disp);
    }
    return addr + seg_base_;
}

uint64_t CPU::read_operand(const Operand& op) {
    switch (op.type) {
        case OperandType::Reg:
            return read_gpr(regs_, op.reg, op.size);
        case OperandType::Mem: {
            uint64_t a = eff_addr(op);
            return mem_read_(a, op.size) & size_mask(op.size);
        }
        case OperandType::Imm:
        case OperandType::Rel:
            return static_cast<uint64_t>(op.imm);
        case OperandType::Moffs:
            return mem_read_(static_cast<uint64_t>(op.imm), op.size) & size_mask(op.size);
        default:
            return 0;
    }
}

void CPU::write_operand(const Operand& op, uint64_t val) {
    switch (op.type) {
        case OperandType::Reg:
            write_gpr(regs_, op.reg, op.size, val);
            break;
        case OperandType::Mem:
            mem_write_(eff_addr(op), val & size_mask(op.size), op.size);
            break;
        case OperandType::Moffs:
            mem_write_(static_cast<uint64_t>(op.imm), val & size_mask(op.size), op.size);
            break;
        default:
            break;
    }
}

void CPU::push_val(uint64_t val, int sz) {
    regs_.rsp -= sz;
    mem_write_(regs_.rsp, val, sz);
}

uint64_t CPU::pop_val(int sz) {
    uint64_t v = mem_read_(regs_.rsp, sz);
    regs_.rsp += sz;
    return v;
}

// ── main execute switch ───────────────────────────────────────────────────────

XMMRegister CPU::xsrc(const Operand& op) {
    if (op.type == OperandType::Reg) return regs_.ymm[op.reg & 31].lo;
    XMMRegister r{};
    uint64_t a = eff_addr(op);
    r.q[0] = mem_read_(a, 8);
    r.q[1] = mem_read_(a + 8, 8);
    return r;
}

XMMRegister CPU::xsrc_hi(const Operand& op) {
    if (op.type == OperandType::Reg) return regs_.ymm[op.reg & 31].hi;
    XMMRegister r{};
    uint64_t a = eff_addr(op) + 16;
    r.q[0] = mem_read_(a, 8);
    r.q[1] = mem_read_(a + 8, 8);
    return r;
}

float CPU::read_f32(const Operand& op) {
    if (op.type == OperandType::Reg) return regs_.ymm[op.reg & 31].lo.f[0];
    uint32_t bits = static_cast<uint32_t>(mem_read_(eff_addr(op), 4));
    return std::bit_cast<float>(bits);
}

double CPU::read_f64(const Operand& op) {
    if (op.type == OperandType::Reg) return regs_.ymm[op.reg & 31].lo.df[0];
    uint64_t bits = mem_read_(eff_addr(op), 8);
    return std::bit_cast<double>(bits);
}

void CPU::write_xmm_mem(uint64_t addr, const XMMRegister& v) {
    mem_write_(addr,     v.q[0], 8);
    mem_write_(addr + 8, v.q[1], 8);
}

static inline int32_t cvtt_f64_to_i32(double v) {
    if (std::isnan(v) || v >= 2147483648.0 || v < -2147483648.0) return INT32_MIN;
    return static_cast<int32_t>(v);
}

static inline int64_t cvtt_f64_to_i64(double v) {
    if (std::isnan(v) || v >= 9223372036854775808.0 || v < -9223372036854775808.0) return INT64_MIN;
    return static_cast<int64_t>(v);
}

static inline int32_t cvt_f64_to_i32(double v) {
    if (std::isnan(v)) return INT32_MIN;
    double r = std::nearbyint(v);
    if (r >= 2147483648.0 || r < -2147483648.0) return INT32_MIN;
    return static_cast<int32_t>(r);
}

static inline int64_t cvt_f64_to_i64(double v) {
    if (std::isnan(v)) return INT64_MIN;
    double r = std::nearbyint(v);
    if (r >= 9223372036854775808.0 || r < -9223372036854775808.0) return INT64_MIN;
    return static_cast<int64_t>(r);
}

static inline void fp_ucomi(Registers& r, double a, double b) {
    set_flag(r, 4,  false); // AF = 0
    set_flag(r, 7,  false); // SF = 0
    set_flag(r, 11, false); // OF = 0
    if (std::isnan(a) || std::isnan(b)) {
        set_flag(r, 6, true);  // ZF = 1
        set_flag(r, 2, true);  // PF = 1
        set_flag(r, 0, true);  // CF = 1
    } else if (a > b) {
        set_flag(r, 6, false);
        set_flag(r, 2, false);
        set_flag(r, 0, false);
    } else if (a < b) {
        set_flag(r, 6, false);
        set_flag(r, 2, false);
        set_flag(r, 0, true);
    } else {
        set_flag(r, 6, true);
        set_flag(r, 2, false);
        set_flag(r, 0, false);
    }
}

static inline bool fp_cmp_pred(double a, double b, uint8_t imm, bool is_vex) {
    uint8_t pred = is_vex ? (imm & 15) : (imm & 7);
    bool unord = std::isnan(a) || std::isnan(b);
    switch (pred) {
        case 0:  return !unord && (a == b); // EQ_OQ
        case 1:  return !unord && (a <  b); // LT_OS
        case 2:  return !unord && (a <= b); // LE_OS
        case 3:  return  unord;             // UNORD_Q
        case 4:  return  unord || (a != b); // NEQ_UQ
        case 5:  return  unord || !(a < b); // NLT_US
        case 6:  return  unord || !(a <= b);// NLE_US
        case 7:  return !unord;             // ORD_Q
        case 8:  return  unord || (a == b); // EQ_UQ
        case 9:  return  unord || !(a >= b);// NGE_US
        case 10: return  unord || !(a > b); // NGT_US
        case 11: return false;              // FALSE_OQ
        case 12: return !unord && (a != b); // NEQ_OQ
        case 13: return !unord && (a >= b); // GE_OS
        case 14: return !unord && (a >  b); // GT_OS
        case 15: return true;               // TRUE_UQ
        default: return false;
    }
}

static inline uint16_t f32_to_f16(float f, uint8_t imm8) {
    uint32_t bits = std::bit_cast<uint32_t>(f);
    uint16_t sign = static_cast<uint16_t>((bits >> 16) & 0x8000u);
    int      exp  = static_cast<int>((bits >> 23) & 0xFFu);
    uint32_t mant = bits & 0x7FFFFFu;
    uint8_t  mode = (imm8 & 4) ? 0 : (imm8 & 3); // 0=nearest-even, 1=down, 2=up, 3=trunc

    if (exp == 0xFF) {
        if (mant == 0) return static_cast<uint16_t>(sign | 0x7C00u); // Inf
        return static_cast<uint16_t>(sign | 0x7E00u | (mant >> 13)); // QNaN
    }

    int e = exp - 127;
    if (e > 15) {
        bool clamp_max = (mode == 3) || (mode == 1 && !sign) || (mode == 2 && sign);
        return static_cast<uint16_t>(sign | (clamp_max ? 0x7BFFu : 0x7C00u));
    }
    if (e < -25) {
        bool round_min = (mode == 1 && sign && (exp || mant)) || (mode == 2 && !sign && (exp || mant));
        return static_cast<uint16_t>(sign | (round_min ? 1u : 0u));
    }

    uint32_t sig = (exp == 0) ? mant : (mant | 0x800000u);
    int shift = (e < -14) ? (13 + (-14 - e)) : 13;
    uint32_t hexp = (e < -14) ? 0u : static_cast<uint32_t>(e + 15);
    uint32_t hmant = sig >> shift;
    uint32_t rem = sig & ((1u << shift) - 1u);
    uint32_t half = 1u << (shift - 1);

    bool inc = false;
    if      (mode == 0) inc = (rem > half) || (rem == half && (hmant & 1u));
    else if (mode == 1) inc = (sign != 0) && (rem != 0);
    else if (mode == 2) inc = (sign == 0) && (rem != 0);

    if (inc) {
        hmant++;
        if (hexp == 0 && hmant == 0x400u) { hexp = 1; hmant = 0; }
        else if (hmant == 0x800u) { hexp++; hmant = 0; }
    }
    if (hexp >= 31) return static_cast<uint16_t>(sign | 0x7C00u);
    return static_cast<uint16_t>(sign | (hexp << 10) | (hmant & 0x3FFu));
}

static inline float f16_to_f32(uint16_t h) {
    uint32_t sign = static_cast<uint32_t>(h & 0x8000u) << 16;
    uint32_t exp  = (h >> 10) & 0x1Fu;
    uint32_t mant = h & 0x3FFu;
    if (exp == 0) {
        if (mant == 0) return std::bit_cast<float>(sign);
        int e = -14;
        while ((mant & 0x400u) == 0) { mant <<= 1; --e; }
        mant &= 0x3FFu;
        return std::bit_cast<float>(sign | (static_cast<uint32_t>(e + 127) << 23) | (mant << 13));
    }
    if (exp == 31) {
        return std::bit_cast<float>(sign | 0x7F800000u | (mant ? (0x00400000u | (mant << 13)) : 0u));
    }
    return std::bit_cast<float>(sign | ((exp + 112u) << 23) | (mant << 13));
}

void CPU::execute(const DecodedInsn& insn) {
    int sz = insn.op_size;

    // ── VEX / SSE execution wrappers (use ymm[16] as scratch) ─────────────────
    auto exec_packed_bin = [&](auto&& fn) {
        const bool is_vex = insn.prefixes.vex;
        const bool is_256 = is_vex && insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;

        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        const XMMRegister s_lo = xsrc(insn.src);
        fn(regs_.ymm[16].lo, s_lo, 0);

        if (is_256) {
            regs_.ymm[16].hi = regs_.ymm[src1_r].hi;
            const XMMRegister s_hi = xsrc_hi(insn.src);
            fn(regs_.ymm[16].hi, s_hi, 1);
            regs_.ymm[dst_r] = regs_.ymm[16];
        } else {
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        }
    };

    auto exec_packed_un = [&](auto&& fn) {
        const bool is_vex = insn.prefixes.vex;
        const bool is_256 = is_vex && insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;

        const XMMRegister s_lo = xsrc(insn.src);
        regs_.ymm[16].lo = {};
        fn(regs_.ymm[16].lo, s_lo);

        if (is_256) {
            const XMMRegister s_hi = xsrc_hi(insn.src);
            regs_.ymm[16].hi = {};
            fn(regs_.ymm[16].hi, s_hi);
            regs_.ymm[dst_r] = regs_.ymm[16];
        } else {
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        }
    };

    auto exec_scalar_ss = [&](auto&& fn) {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;

        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        float b = read_f32(insn.src);
        regs_.ymm[16].lo.f[0] = fn(regs_.ymm[16].lo.f[0], b);
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
    };

    auto exec_scalar_sd = [&](auto&& fn) {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;

        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        double b = read_f64(insn.src);
        regs_.ymm[16].lo.df[0] = fn(regs_.ymm[16].lo.df[0], b);
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
    };

    switch (insn.mnemonic) {

    // ── NOP / HLT / PAUSE ────────────────────────────────────────────────────
    case Mnemonic::NOP:
    case Mnemonic::PAUSE:
        break;

    case Mnemonic::HLT:
        halted_ = true;
        break;

    // ── Flag ops ─────────────────────────────────────────────────────────────
    case Mnemonic::CLI: regs_.rflags &= ~(1ULL << 9);  break;
    case Mnemonic::STI: regs_.rflags |=  (1ULL << 9);  break;
    case Mnemonic::CLC: regs_.rflags &= ~(1ULL << 0);  break;
    case Mnemonic::STC: regs_.rflags |=  (1ULL << 0);  break;
    case Mnemonic::CMC: regs_.rflags ^=  (1ULL << 0);  break;
    case Mnemonic::CLD: regs_.rflags &= ~(1ULL << 10); break;
    case Mnemonic::STD: regs_.rflags |=  (1ULL << 10); break;
    case Mnemonic::CLTS: regs_.cr0 &= ~(1ULL << 3); break;

    // ── MOV ──────────────────────────────────────────────────────────────────
    case Mnemonic::MOV:
        write_operand(insn.dst, read_operand(insn.src));
        break;

    case Mnemonic::MOVZX: {
        uint64_t v = read_operand(insn.src) & size_mask(insn.src.size);
        write_operand(insn.dst, v);
        break;
    }

    case Mnemonic::MOVSX:
    case Mnemonic::MOVSXD: {
        int src_sz = insn.src.size;
        uint64_t v = read_operand(insn.src) & size_mask(src_sz);
        int sign_bit = src_sz * 8 - 1;
        if ((v >> sign_bit) & 1)
            v |= ~size_mask(src_sz);
        write_operand(insn.dst, v);
        break;
    }

    case Mnemonic::LEA: {
        uint64_t addr = eff_addr(insn.src);
        write_operand(insn.dst, addr & size_mask(sz));
        break;
    }

    case Mnemonic::XCHG: {
        uint64_t a = read_operand(insn.dst);
        uint64_t b = read_operand(insn.src);
        write_operand(insn.dst, b);
        write_operand(insn.src, a);
        break;
    }

    case Mnemonic::XADD: {
        uint64_t dst = read_operand(insn.dst);
        uint64_t src = read_operand(insn.src);
        uint64_t res = flags_add(regs_, dst, src, 0, sz);
        write_operand(insn.src, dst);
        write_operand(insn.dst, res);
        break;
    }

    case Mnemonic::CMPXCHG: {
        uint64_t acc = read_gpr(regs_, 0, sz); // AL/AX/EAX/RAX
        uint64_t dst = read_operand(insn.dst);
        flags_sub(regs_, acc, dst, 0, sz);
        if ((acc & size_mask(sz)) == (dst & size_mask(sz))) {
            write_operand(insn.dst, read_operand(insn.src));
        } else {
            write_gpr(regs_, 0, sz, dst);
        }
        break;
    }

    case Mnemonic::BSWAP: {
        uint64_t v = read_operand(insn.dst);
        if (sz == 4) {
            v = __builtin_bswap32(static_cast<uint32_t>(v));
        } else {
            v = __builtin_bswap64(v);
        }
        write_operand(insn.dst, v);
        break;
    }

    case Mnemonic::MOVBE: {
        uint64_t v = read_operand(insn.src);
        if      (sz == 2) v = __builtin_bswap16(static_cast<uint16_t>(v));
        else if (sz == 4) v = __builtin_bswap32(static_cast<uint32_t>(v));
        else if (sz == 8) v = __builtin_bswap64(v);
        write_operand(insn.dst, v);
        break;
    }

    case Mnemonic::CMPXCHG8B: {
        uint64_t a = eff_addr(insn.dst);
        uint32_t mlo = static_cast<uint32_t>(mem_read_(a, 4));
        uint32_t mhi = static_cast<uint32_t>(mem_read_(a + 4, 4));
        if (mlo == static_cast<uint32_t>(regs_.rax) && mhi == static_cast<uint32_t>(regs_.rdx)) {
            set_flag(regs_, 6, true);
            mem_write_(a,     static_cast<uint32_t>(regs_.rbx), 4);
            mem_write_(a + 4, static_cast<uint32_t>(regs_.rcx), 4);
        } else {
            set_flag(regs_, 6, false);
            write_gpr(regs_, 0, 4, mlo);
            write_gpr(regs_, 2, 4, mhi);
        }
        break;
    }

    case Mnemonic::CMPXCHG16B: {
        uint64_t a = eff_addr(insn.dst);
        uint64_t mlo = mem_read_(a, 8);
        uint64_t mhi = mem_read_(a + 8, 8);
        if (mlo == regs_.rax && mhi == regs_.rdx) {
            set_flag(regs_, 6, true);
            mem_write_(a,     regs_.rbx, 8);
            mem_write_(a + 8, regs_.rcx, 8);
        } else {
            set_flag(regs_, 6, false);
            regs_.rax = mlo;
            regs_.rdx = mhi;
        }
        break;
    }

    // ── PUSH / POP ───────────────────────────────────────────────────────────
    case Mnemonic::PUSH: {
        const Operand& op = (insn.src.type != OperandType::None) ? insn.src : insn.dst;
        push_val(read_operand(op), 8);
        break;
    }

    case Mnemonic::POP:
        write_operand(insn.dst, pop_val(8));
        break;

    case Mnemonic::CDQE: {
        if (sz == 2)      write_gpr(regs_, 0, 2, static_cast<uint16_t>(static_cast<int16_t>(static_cast<int8_t>(regs_.rax & 0xFF))));
        else if (sz == 4) write_gpr(regs_, 0, 4, static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(regs_.rax & 0xFFFF))));
        else              regs_.rax = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(regs_.rax & 0xFFFFFFFFu)));
        break;
    }

    case Mnemonic::CQO: {
        if (sz == 2)      write_gpr(regs_, 2, 2, (regs_.rax & 0x8000u) ? 0xFFFFu : 0u);
        else if (sz == 4) write_gpr(regs_, 2, 4, (regs_.rax & 0x80000000u) ? 0xFFFFFFFFu : 0u);
        else              regs_.rdx = (regs_.rax >> 63) ? ~0ULL : 0ULL;
        break;
    }

    case Mnemonic::PUSHF:
        push_val(regs_.rflags & 0xFCFFFF, 8);
        break;

    case Mnemonic::POPF:
        regs_.rflags = pop_val(8) | 0x2;
        break;

    // ── ALU ──────────────────────────────────────────────────────────────────
    case Mnemonic::ADD: {
        uint64_t d = read_operand(insn.dst), s = read_operand(insn.src);
        uint64_t r = flags_add(regs_, d, s, 0, sz);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::ADC: {
        uint64_t d = read_operand(insn.dst), s = read_operand(insn.src);
        uint64_t c = flag_cf(regs_) ? 1 : 0;
        uint64_t r = flags_add(regs_, d, s, c, sz);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::ADCX: case Mnemonic::ADOX: {
        // only CF (ADCX) or OF (ADOX) is read and written; other flags untouched
        int bit = insn.mnemonic == Mnemonic::ADCX ? 0 : 11;
        uint64_t d = read_operand(insn.dst), s = read_operand(insn.src);
        uint64_t c = (regs_.rflags >> bit) & 1;
        uint64_t r; bool co;
        if (sz == 8) {
            unsigned __int128 t = (unsigned __int128)d + s + c;
            r = (uint64_t)t; co = (t >> 64) != 0;
        } else {
            uint64_t t = (d & 0xFFFFFFFFull) + (s & 0xFFFFFFFFull) + c;
            r = t & 0xFFFFFFFFull; co = (t >> 32) != 0;
        }
        set_flag(regs_, bit, co);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::SUB: {
        uint64_t d = read_operand(insn.dst), s = read_operand(insn.src);
        uint64_t r = flags_sub(regs_, d, s, 0, sz);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::SBB: {
        uint64_t d = read_operand(insn.dst), s = read_operand(insn.src);
        uint64_t c = flag_cf(regs_) ? 1 : 0;
        uint64_t r = flags_sub(regs_, d, s, c, sz);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::AND: {
        uint64_t r = read_operand(insn.dst) & read_operand(insn.src);
        flags_logic(regs_, r, sz);
        write_operand(insn.dst, r & size_mask(sz));
        break;
    }

    case Mnemonic::OR: {
        uint64_t r = read_operand(insn.dst) | read_operand(insn.src);
        flags_logic(regs_, r, sz);
        write_operand(insn.dst, r & size_mask(sz));
        break;
    }

    case Mnemonic::XOR: {
        uint64_t r = read_operand(insn.dst) ^ read_operand(insn.src);
        flags_logic(regs_, r, sz);
        write_operand(insn.dst, r & size_mask(sz));
        break;
    }

    case Mnemonic::NOT: {
        write_operand(insn.dst, (~read_operand(insn.dst)) & size_mask(sz));
        break;
    }

    case Mnemonic::NEG: {
        uint64_t s = read_operand(insn.dst) & size_mask(sz);
        uint64_t r = flags_sub(regs_, 0, s, 0, sz);
        set_flag(regs_, 0, s != 0);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::INC: {
        uint64_t d = read_operand(insn.dst);
        bool cf = flag_cf(regs_); // INC doesn't touch CF
        uint64_t r = flags_add(regs_, d, 1, 0, sz);
        set_flag(regs_, 0, cf);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::DEC: {
        uint64_t d = read_operand(insn.dst);
        bool cf = flag_cf(regs_); // DEC doesn't touch CF
        uint64_t r = flags_sub(regs_, d, 1, 0, sz);
        set_flag(regs_, 0, cf);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::CMP: {
        uint64_t d = read_operand(insn.dst), s = read_operand(insn.src);
        flags_sub(regs_, d, s, 0, sz);
        break;
    }

    case Mnemonic::TEST: {
        uint64_t r = read_operand(insn.dst) & read_operand(insn.src);
        flags_logic(regs_, r, sz);
        break;
    }

    // ── MUL / IMUL / DIV / IDIV ──────────────────────────────────────────────
    case Mnemonic::MUL: {
        const Operand& op = (insn.src.type != OperandType::None) ? insn.src : insn.dst;
        uint64_t a = read_gpr(regs_, 0, sz) & size_mask(sz);
        uint64_t s = read_operand(op) & size_mask(sz);
        if (sz == 8) {
            unsigned __int128 r = (unsigned __int128)a * s;
            write_gpr(regs_, 0, 8, (uint64_t)r);
            write_gpr(regs_, 2, 8, (uint64_t)(r >> 64));
            bool hi = (uint64_t)(r >> 64) != 0;
            set_flag(regs_, 0, hi); set_flag(regs_, 11, hi);
        } else if (sz == 1) {
            uint64_t r = a * s;
            write_gpr(regs_, 0, 2, r & 0xFFFF);
            bool ov = (r >> 8) != 0;
            set_flag(regs_, 0, ov); set_flag(regs_, 11, ov);
        } else {
            uint64_t r = a * s;
            uint64_t lo = r & size_mask(sz);
            uint64_t hi = (r >> (sz * 8)) & size_mask(sz);
            write_gpr(regs_, 0, sz, lo);
            write_gpr(regs_, 2, sz, hi);
            bool ov = hi != 0;
            set_flag(regs_, 0, ov); set_flag(regs_, 11, ov);
        }
        break;
    }

    case Mnemonic::IMUL: {
        auto sext = [](uint64_t v, int s_sz) -> int64_t {
            if (s_sz >= 8) return static_cast<int64_t>(v);
            int shift = 64 - s_sz * 8;
            return (static_cast<int64_t>(v) << shift) >> shift;
        };
        if (insn.src2.type != OperandType::None) {
            // 3-op: dst = src * src2
            int64_t a = sext(read_operand(insn.src), sz);
            int64_t b = sext(read_operand(insn.src2), sz);
            __int128 prod = static_cast<__int128>(a) * static_cast<__int128>(b);
            uint64_t res = static_cast<uint64_t>(prod) & size_mask(sz);
            bool ov = (prod != static_cast<__int128>(sext(res, sz)));
            set_flag(regs_, 0, ov); set_flag(regs_, 11, ov);
            write_operand(insn.dst, res);
        } else if (insn.src.type != OperandType::None) {
            // 2-op: dst *= src
            int64_t a = sext(read_operand(insn.dst), sz);
            int64_t b = sext(read_operand(insn.src), sz);
            __int128 prod = static_cast<__int128>(a) * static_cast<__int128>(b);
            uint64_t res = static_cast<uint64_t>(prod) & size_mask(sz);
            bool ov = (prod != static_cast<__int128>(sext(res, sz)));
            set_flag(regs_, 0, ov); set_flag(regs_, 11, ov);
            write_operand(insn.dst, res);
        } else {
            // 1-op: RDX:RAX = RAX * src
            int64_t a = sext(read_gpr(regs_, 0, sz), sz);
            int64_t s = sext(read_operand(insn.dst), sz);
            __int128 prod = static_cast<__int128>(a) * static_cast<__int128>(s);
            uint64_t lo = static_cast<uint64_t>(prod) & size_mask(sz);
            bool ov = (prod != static_cast<__int128>(sext(lo, sz)));
            set_flag(regs_, 0, ov); set_flag(regs_, 11, ov);
            if (sz == 8) {
                write_gpr(regs_, 0, 8, static_cast<uint64_t>(prod));
                write_gpr(regs_, 2, 8, static_cast<uint64_t>(static_cast<unsigned __int128>(prod) >> 64));
            } else if (sz == 1) {
                write_gpr(regs_, 0, 2, static_cast<uint64_t>(prod) & 0xFFFF);
            } else {
                write_gpr(regs_, 0, sz, lo);
                write_gpr(regs_, 2, sz, (static_cast<uint64_t>(prod) >> (sz * 8)) & size_mask(sz));
            }
        }
        break;
    }

    case Mnemonic::DIV: {
        const Operand& op = (insn.src.type != OperandType::None) ? insn.src : insn.dst;
        uint64_t s = read_operand(op) & size_mask(sz);
        if (s == 0) { handle_interrupt(0); break; }
        if (sz == 8) {
            unsigned __int128 num = ((unsigned __int128)(regs_.rdx) << 64) | regs_.rax;
            write_gpr(regs_, 0, 8, (uint64_t)(num / s));
            write_gpr(regs_, 2, 8, (uint64_t)(num % s));
        } else if (sz == 1) {
            uint64_t num = read_gpr(regs_, 0, 2);
            write_gpr(regs_, 0, 2, ((num % s) << 8) | ((num / s) & 0xFF));
        } else {
            uint64_t hi = read_gpr(regs_, 2, sz);
            uint64_t lo = read_gpr(regs_, 0, sz);
            uint64_t num = (hi << (sz * 8)) | lo;
            write_gpr(regs_, 0, sz, num / s);
            write_gpr(regs_, 2, sz, num % s);
        }
        break;
    }

    case Mnemonic::IDIV: {
        const Operand& op = (insn.src.type != OperandType::None) ? insn.src : insn.dst;
        int64_t s = static_cast<int64_t>(read_operand(op));
        if (sz < 8) { int shift = 64 - sz * 8; s = (s << shift) >> shift; }
        if (s == 0) { handle_interrupt(0); break; }
        if (sz == 8) {
            __int128 num = ((__int128)(int64_t)regs_.rdx << 64) | (uint64_t)regs_.rax;
            write_gpr(regs_, 0, 8, (uint64_t)((int64_t)(num / s)));
            write_gpr(regs_, 2, 8, (uint64_t)((int64_t)(num % s)));
        } else if (sz == 1) {
            int16_t num = static_cast<int16_t>(read_gpr(regs_, 0, 2));
            uint8_t q = static_cast<uint8_t>(num / s);
            uint8_t rem = static_cast<uint8_t>(num % s);
            write_gpr(regs_, 0, 2, (static_cast<uint16_t>(rem) << 8) | q);
        } else {
            int shift = 64 - sz * 8;
            int64_t hi = static_cast<int64_t>(read_gpr(regs_, 2, sz));
            hi = (hi << shift) >> shift;
            uint64_t lo = read_gpr(regs_, 0, sz) & size_mask(sz);
            int64_t num = (hi << (sz * 8)) | static_cast<int64_t>(lo);
            write_gpr(regs_, 0, sz, static_cast<uint64_t>(num / s) & size_mask(sz));
            write_gpr(regs_, 2, sz, static_cast<uint64_t>(num % s) & size_mask(sz));
        }
        break;
    }

    // ── Shifts / Rotates ─────────────────────────────────────────────────────
    case Mnemonic::SHL:
    case Mnemonic::SAL: {
        uint64_t d = read_operand(insn.dst) & size_mask(sz);
        int cnt = static_cast<int>(insn.src.type != OperandType::None
            ? read_operand(insn.src) : 1) & (sz == 8 ? 63 : 31);
        if (cnt == 0) break;
        int bits = sz * 8;
        uint64_t r = (cnt >= bits) ? 0ULL : ((d << cnt) & size_mask(sz));
        bool cf = (cnt > bits) ? false : ((d >> (bits - cnt)) & 1);
        set_flag(regs_, 0, cf);
        if (cnt == 1) set_flag(regs_, 11, (((r >> (bits - 1)) & 1) != 0) ^ cf);
        update_pzs(regs_, r, sz);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::SHR: {
        uint64_t d = read_operand(insn.dst) & size_mask(sz);
        int cnt = static_cast<int>(insn.src.type != OperandType::None
            ? read_operand(insn.src) : 1) & (sz == 8 ? 63 : 31);
        if (cnt == 0) break;
        int bits = sz * 8;
        bool cf = (cnt > bits) ? false : ((d >> (cnt - 1)) & 1);
        set_flag(regs_, 0, cf);
        if (cnt == 1) set_flag(regs_, 11, (d >> (bits - 1)) & 1);
        uint64_t r = (cnt >= bits) ? 0ULL : (d >> cnt);
        update_pzs(regs_, r, sz);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::SAR: {
        int64_t d = static_cast<int64_t>(read_operand(insn.dst));
        if (sz < 8) { int shift = 64 - sz*8; d = (d << shift) >> shift; }
        int cnt = static_cast<int>(insn.src.type != OperandType::None
            ? read_operand(insn.src) : 1) & (sz == 8 ? 63 : 31);
        if (cnt == 0) break;
        set_flag(regs_, 0, (d >> (cnt - 1)) & 1);
        if (cnt == 1) set_flag(regs_, 11, false);
        int64_t r = d >> cnt;
        update_pzs(regs_, static_cast<uint64_t>(r), sz);
        write_operand(insn.dst, static_cast<uint64_t>(r) & size_mask(sz));
        break;
    }

    case Mnemonic::ROL: {
        uint64_t d = read_operand(insn.dst) & size_mask(sz);
        int bits = sz * 8;
        int raw_cnt = static_cast<int>(insn.src.type != OperandType::None
            ? read_operand(insn.src) : 1) & (sz == 8 ? 63 : 31);
        if (raw_cnt == 0) break;
        int cnt = raw_cnt % bits;
        uint64_t r = (cnt == 0) ? d : (((d << cnt) | (d >> (bits - cnt))) & size_mask(sz));
        bool cf = (r & 1) != 0;
        set_flag(regs_, 0, cf);
        if (raw_cnt == 1) set_flag(regs_, 11, (((r >> (bits - 1)) & 1) != 0) ^ cf);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::ROR: {
        uint64_t d = read_operand(insn.dst) & size_mask(sz);
        int bits = sz * 8;
        int raw_cnt = static_cast<int>(insn.src.type != OperandType::None
            ? read_operand(insn.src) : 1) & (sz == 8 ? 63 : 31);
        if (raw_cnt == 0) break;
        int cnt = raw_cnt % bits;
        uint64_t r = (cnt == 0) ? d : (((d >> cnt) | (d << (bits - cnt))) & size_mask(sz));
        bool cf = ((r >> (bits - 1)) & 1) != 0;
        set_flag(regs_, 0, cf);
        if (raw_cnt == 1) set_flag(regs_, 11, cf ^ (((r >> (bits - 2)) & 1) != 0));
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::RCL: {
        uint64_t d = read_operand(insn.dst) & size_mask(sz);
        int bits = sz * 8;
        int raw_cnt = static_cast<int>(insn.src.type != OperandType::None
            ? read_operand(insn.src) : 1) & (sz == 8 ? 63 : 31);
        int cnt = raw_cnt % (bits + 1);
        if (cnt == 0) break;
        bool cf = flag_cf(regs_);
        for (int i = 0; i < cnt; ++i) {
            bool msb = ((d >> (bits - 1)) & 1) != 0;
            d = ((d << 1) | (cf ? 1ULL : 0ULL)) & size_mask(sz);
            cf = msb;
        }
        set_flag(regs_, 0, cf);
        if (raw_cnt == 1) set_flag(regs_, 11, (((d >> (bits - 1)) & 1) != 0) ^ cf);
        write_operand(insn.dst, d);
        break;
    }

    case Mnemonic::RCR: {
        uint64_t d = read_operand(insn.dst) & size_mask(sz);
        int bits = sz * 8;
        int raw_cnt = static_cast<int>(insn.src.type != OperandType::None
            ? read_operand(insn.src) : 1) & (sz == 8 ? 63 : 31);
        int cnt = raw_cnt % (bits + 1);
        if (cnt == 0) break;
        bool cf = flag_cf(regs_);
        if (raw_cnt == 1) set_flag(regs_, 11, (((d >> (bits - 1)) & 1) != 0) ^ cf);
        for (int i = 0; i < cnt; ++i) {
            bool lsb = (d & 1) != 0;
            d = ((d >> 1) | (cf ? (1ULL << (bits - 1)) : 0ULL)) & size_mask(sz);
            cf = lsb;
        }
        set_flag(regs_, 0, cf);
        write_operand(insn.dst, d);
        break;
    }

    case Mnemonic::SHLD: {
        uint64_t d = read_operand(insn.dst) & size_mask(sz);
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        int cnt = static_cast<int>(read_operand(insn.src2)) & (sz == 8 ? 63 : 31);
        if (cnt == 0) break;
        int bits = sz * 8;
        uint64_t r = ((d << cnt) | (s >> (bits - cnt))) & size_mask(sz);
        bool cf = ((d >> (bits - cnt)) & 1) != 0;
        set_flag(regs_, 0, cf);
        if (cnt == 1) set_flag(regs_, 11, ((r >> (bits - 1)) & 1) != ((d >> (bits - 1)) & 1));
        update_pzs(regs_, r, sz);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::SHRD: {
        uint64_t d = read_operand(insn.dst) & size_mask(sz);
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        int cnt = static_cast<int>(read_operand(insn.src2)) & (sz == 8 ? 63 : 31);
        if (cnt == 0) break;
        int bits = sz * 8;
        uint64_t r = ((d >> cnt) | (s << (bits - cnt))) & size_mask(sz);
        bool cf = ((d >> (cnt - 1)) & 1) != 0;
        set_flag(regs_, 0, cf);
        if (cnt == 1) set_flag(regs_, 11, ((r >> (bits - 1)) & 1) != ((d >> (bits - 1)) & 1));
        update_pzs(regs_, r, sz);
        write_operand(insn.dst, r);
        break;
    }

    // ── Bit manipulation ─────────────────────────────────────────────────────
    case Mnemonic::BT: case Mnemonic::BTS: case Mnemonic::BTR: case Mnemonic::BTC: {
        int bit_idx = static_cast<int>(read_operand(insn.src));
        if (insn.dst.type == OperandType::Mem && insn.src.type == OperandType::Reg) {
            int64_t sbit = static_cast<int64_t>(read_operand(insn.src));
            if (sz < 8) { int shift = 64 - sz * 8; sbit = (sbit << shift) >> shift; }
            int64_t elem_bits = sz * 8;
            int64_t elem_off = (sbit >= 0) ? (sbit / elem_bits) : ((sbit - elem_bits + 1) / elem_bits);
            int bit = static_cast<int>(sbit - elem_off * elem_bits);
            uint64_t addr = eff_addr(insn.dst) + static_cast<uint64_t>(elem_off * sz);
            uint64_t base = mem_read_(addr, sz) & size_mask(sz);
            set_flag(regs_, 0, (base >> bit) & 1);
            if (insn.mnemonic == Mnemonic::BTS) base |=  (1ULL << bit);
            if (insn.mnemonic == Mnemonic::BTR) base &= ~(1ULL << bit);
            if (insn.mnemonic == Mnemonic::BTC) base ^=  (1ULL << bit);
            if (insn.mnemonic != Mnemonic::BT)
                mem_write_(addr, base & size_mask(sz), sz);
        } else {
            uint64_t base = read_operand(insn.dst) & size_mask(sz);
            int bit = bit_idx & (sz * 8 - 1);
            set_flag(regs_, 0, (base >> bit) & 1);
            if (insn.mnemonic == Mnemonic::BTS) base |=  (1ULL << bit);
            if (insn.mnemonic == Mnemonic::BTR) base &= ~(1ULL << bit);
            if (insn.mnemonic == Mnemonic::BTC) base ^=  (1ULL << bit);
            if (insn.mnemonic != Mnemonic::BT)
                write_operand(insn.dst, base & size_mask(sz));
        }
        break;
    }

    case Mnemonic::BSF: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        set_flag(regs_, 6, s == 0);
        if (s) write_operand(insn.dst, __builtin_ctzll(s));
        break;
    }

    case Mnemonic::BSR: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        set_flag(regs_, 6, s == 0);
        if (s) write_operand(insn.dst, 63 - __builtin_clzll(s));
        break;
    }

    case Mnemonic::LZCNT: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        uint64_t r = s ? (uint64_t)__builtin_clzll(s) - (64 - sz * 8) : (uint64_t)(sz * 8);
        set_flag(regs_, 0, s == 0);
        set_flag(regs_, 6, r == 0);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::TZCNT: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        uint64_t r = s ? (uint64_t)__builtin_ctzll(s) : (uint64_t)(sz * 8);
        set_flag(regs_, 0, s == 0);
        set_flag(regs_, 6, r == 0);
        write_operand(insn.dst, r);
        break;
    }

    case Mnemonic::POPCNT: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        uint64_t r = __builtin_popcountll(s);
        set_flag(regs_, 6, r == 0);  // ZF
        set_flag(regs_, 0, false);   // CF = 0
        set_flag(regs_, 7, false);   // SF = 0
        set_flag(regs_, 11, false);  // OF = 0
        set_flag(regs_, 4, false);   // AF = 0
        set_flag(regs_, 2, false);   // PF = 0
        write_operand(insn.dst, r);
        break;
    }

    // ── BMI1 / BMI2 ──────────────────────────────────────────────────────────
    case Mnemonic::ANDN: {
        uint64_t a = read_operand(insn.src) & size_mask(sz);
        uint64_t b = read_operand(insn.src2) & size_mask(sz);
        uint64_t r = (~a & b) & size_mask(sz);
        set_flag(regs_, 6, r == 0);
        set_flag(regs_, 7, (r >> (sz * 8 - 1)) & 1);
        set_flag(regs_, 0, false);
        set_flag(regs_, 11, false);
        write_operand(insn.dst, r);
        break;
    }
    case Mnemonic::BLSR: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        uint64_t r = (s & (s - 1)) & size_mask(sz);
        set_flag(regs_, 6, r == 0);
        set_flag(regs_, 7, (r >> (sz * 8 - 1)) & 1);
        set_flag(regs_, 0, s == 0);
        set_flag(regs_, 11, false);
        write_operand(insn.dst, r);
        break;
    }
    case Mnemonic::BLSMSK: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        uint64_t r = (s ^ (s - 1)) & size_mask(sz);
        set_flag(regs_, 6, false);
        set_flag(regs_, 7, (r >> (sz * 8 - 1)) & 1);
        set_flag(regs_, 0, s == 0);
        set_flag(regs_, 11, false);
        write_operand(insn.dst, r);
        break;
    }
    case Mnemonic::BLSI: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        uint64_t r = (s & (~s + 1)) & size_mask(sz);
        set_flag(regs_, 6, r == 0);
        set_flag(regs_, 7, (r >> (sz * 8 - 1)) & 1);
        set_flag(regs_, 0, s != 0);
        set_flag(regs_, 11, false);
        write_operand(insn.dst, r);
        break;
    }
    case Mnemonic::BZHI: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        uint8_t idx = static_cast<uint8_t>(read_operand(insn.src2));
        int bits = sz * 8;
        uint64_t r = (idx >= bits) ? s : (idx == 0 ? 0ULL : (s & ((1ULL << idx) - 1)));
        set_flag(regs_, 0, idx >= bits);
        set_flag(regs_, 6, r == 0);
        set_flag(regs_, 7, (r >> (bits - 1)) & 1);
        set_flag(regs_, 11, false);
        write_operand(insn.dst, r);
        break;
    }
    case Mnemonic::BEXTR: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        uint64_t ctrl = read_operand(insn.src2);
        int start = static_cast<int>(ctrl & 0xFF);
        int len   = static_cast<int>((ctrl >> 8) & 0xFF);
        int bits  = sz * 8;
        uint64_t r = 0;
        if (start < bits && len > 0) {
            r = s >> start;
            if (len < bits) r &= (1ULL << len) - 1;
            r &= size_mask(sz);
        }
        set_flag(regs_, 6, r == 0);
        set_flag(regs_, 0, false);
        set_flag(regs_, 11, false);
        write_operand(insn.dst, r);
        break;
    }
    case Mnemonic::SHLX: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        int cnt = static_cast<int>(read_operand(insn.src2)) & (sz == 8 ? 63 : 31);
        write_operand(insn.dst, (s << cnt) & size_mask(sz));
        break;
    }
    case Mnemonic::SHRX: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        int cnt = static_cast<int>(read_operand(insn.src2)) & (sz == 8 ? 63 : 31);
        write_operand(insn.dst, s >> cnt);
        break;
    }
    case Mnemonic::SARX: {
        int64_t s = static_cast<int64_t>(read_operand(insn.src));
        if (sz < 8) { int shift = 64 - sz * 8; s = (s << shift) >> shift; }
        int cnt = static_cast<int>(read_operand(insn.src2)) & (sz == 8 ? 63 : 31);
        write_operand(insn.dst, static_cast<uint64_t>(s >> cnt) & size_mask(sz));
        break;
    }
    case Mnemonic::RORX: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        int bits = sz * 8;
        int cnt = static_cast<int>(insn.src2.imm) & (bits - 1);
        uint64_t r = (cnt == 0) ? s : (((s >> cnt) | (s << (bits - cnt))) & size_mask(sz));
        write_operand(insn.dst, r);
        break;
    }
    case Mnemonic::MULX: {
        uint64_t a = read_gpr(regs_, 2, sz) & size_mask(sz); // RDX/EDX
        uint64_t b = read_operand(insn.src2) & size_mask(sz);
        if (sz == 8) {
            unsigned __int128 prod = static_cast<unsigned __int128>(a) * b;
            write_operand(insn.src, static_cast<uint64_t>(prod));
            write_operand(insn.dst, static_cast<uint64_t>(prod >> 64));
        } else {
            uint64_t prod = a * b;
            write_operand(insn.src, prod & 0xFFFFFFFFULL);
            write_operand(insn.dst, (prod >> 32) & 0xFFFFFFFFULL);
        }
        break;
    }
    case Mnemonic::PEXT: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        uint64_t mask = read_operand(insn.src2) & size_mask(sz);
        uint64_t r = 0;
        int k = 0;
        for (int i = 0; i < sz * 8; ++i) {
            if ((mask >> i) & 1) {
                if ((s >> i) & 1) r |= (1ULL << k);
                ++k;
            }
        }
        write_operand(insn.dst, r);
        break;
    }
    case Mnemonic::PDEP: {
        uint64_t s = read_operand(insn.src) & size_mask(sz);
        uint64_t mask = read_operand(insn.src2) & size_mask(sz);
        uint64_t r = 0;
        int k = 0;
        for (int i = 0; i < sz * 8; ++i) {
            if ((mask >> i) & 1) {
                if ((s >> k) & 1) r |= (1ULL << i);
                ++k;
            }
        }
        write_operand(insn.dst, r);
        break;
    }

    // ── Control flow ─────────────────────────────────────────────────────────
    case Mnemonic::JMP: {
        int64_t rel = static_cast<int64_t>(read_operand(insn.dst));
        if (insn.dst.type == OperandType::Rel)
            regs_.rip = regs_.rip + static_cast<uint64_t>(rel);  // already advanced past insn
        else
            regs_.rip = static_cast<uint64_t>(read_operand(insn.dst));
        break;
    }

    case Mnemonic::JO: case Mnemonic::JNO: case Mnemonic::JB:  case Mnemonic::JNB:
    case Mnemonic::JZ: case Mnemonic::JNZ: case Mnemonic::JBE: case Mnemonic::JA:
    case Mnemonic::JS: case Mnemonic::JNS: case Mnemonic::JP:  case Mnemonic::JNP:
    case Mnemonic::JL: case Mnemonic::JGE: case Mnemonic::JLE: case Mnemonic::JG: {
        if (eval_cc(regs_, insn.mnemonic)) {
            int64_t rel = static_cast<int64_t>(insn.dst.imm);
            regs_.rip = static_cast<uint64_t>(static_cast<int64_t>(regs_.rip) + rel);
        }
        break;
    }

    case Mnemonic::JRCXZ: {
        if (regs_.rcx == 0) {
            int64_t rel = static_cast<int64_t>(insn.dst.imm);
            regs_.rip = static_cast<uint64_t>(static_cast<int64_t>(regs_.rip) + rel);
        }
        break;
    }

    case Mnemonic::LOOP: {
        --regs_.rcx;
        if (regs_.rcx != 0) {
            int64_t rel = static_cast<int64_t>(insn.dst.imm);
            regs_.rip = static_cast<uint64_t>(static_cast<int64_t>(regs_.rip) + rel);
        }
        break;
    }

    case Mnemonic::LOOPE: {
        --regs_.rcx;
        if (regs_.rcx != 0 && flag_zf(regs_)) {
            int64_t rel = static_cast<int64_t>(insn.dst.imm);
            regs_.rip = static_cast<uint64_t>(static_cast<int64_t>(regs_.rip) + rel);
        }
        break;
    }

    case Mnemonic::LOOPNE: {
        --regs_.rcx;
        if (regs_.rcx != 0 && !flag_zf(regs_)) {
            int64_t rel = static_cast<int64_t>(insn.dst.imm);
            regs_.rip = static_cast<uint64_t>(static_cast<int64_t>(regs_.rip) + rel);
        }
        break;
    }

    case Mnemonic::CALL: {
        push_val(regs_.rip, 8);
        if (insn.dst.type == OperandType::Rel) {
            int64_t rel = static_cast<int64_t>(insn.dst.imm);
            regs_.rip = static_cast<uint64_t>(static_cast<int64_t>(regs_.rip) + rel);
        } else {
            regs_.rip = read_operand(insn.dst);
        }
        break;
    }

    case Mnemonic::RET: {
        regs_.rip = pop_val(8);
        if (insn.dst.type == OperandType::Imm)
            regs_.rsp += insn.dst.imm;
        break;
    }

    case Mnemonic::IRET:
    case Mnemonic::IRETQ: {
        regs_.rip    = pop_val(8);
        regs_.cs     = static_cast<uint16_t>(pop_val(8));
        regs_.rflags = pop_val(8) | 0x2;
        break;
    }

    // ── CMOVcc ───────────────────────────────────────────────────────────────
    case Mnemonic::CMOVO: case Mnemonic::CMOVNO: case Mnemonic::CMOVB:  case Mnemonic::CMOVNB:
    case Mnemonic::CMOVZ: case Mnemonic::CMOVNZ: case Mnemonic::CMOVBE: case Mnemonic::CMOVA:
    case Mnemonic::CMOVS: case Mnemonic::CMOVNS: case Mnemonic::CMOVP:  case Mnemonic::CMOVNP:
    case Mnemonic::CMOVL: case Mnemonic::CMOVGE: case Mnemonic::CMOVLE: case Mnemonic::CMOVG:
        if (eval_cc(regs_, insn.mnemonic))
            write_operand(insn.dst, read_operand(insn.src));
        break;

    // ── SETcc ────────────────────────────────────────────────────────────────
    case Mnemonic::SETO:  case Mnemonic::SETNO: case Mnemonic::SETB:  case Mnemonic::SETNB:
    case Mnemonic::SETZ:  case Mnemonic::SETNZ: case Mnemonic::SETBE: case Mnemonic::SETA:
    case Mnemonic::SETS:  case Mnemonic::SETNS: case Mnemonic::SETP:  case Mnemonic::SETNP:
    case Mnemonic::SETL:  case Mnemonic::SETGE: case Mnemonic::SETLE: case Mnemonic::SETG:
        write_operand(insn.dst, eval_cc(regs_, insn.mnemonic) ? 1 : 0);
        break;

    // ── String ops ───────────────────────────────────────────────────────────
    case Mnemonic::MOVS: {
        int step = flag_df(regs_) ? -sz : sz;
        uint64_t reps = insn.prefixes.rep ? regs_.rcx : 1;
        while (reps--) {
            mem_write_(regs_.rdi, mem_read_(regs_.rsi, sz), sz);
            regs_.rsi += step;
            regs_.rdi += step;
        }
        if (insn.prefixes.rep) regs_.rcx = 0;
        break;
    }

    case Mnemonic::STOS: {
        int step = flag_df(regs_) ? -sz : sz;
        uint64_t acc = read_gpr(regs_, 0, sz);
        uint64_t reps = insn.prefixes.rep ? regs_.rcx : 1;
        while (reps--) {
            mem_write_(regs_.rdi, acc, sz);
            regs_.rdi += step;
        }
        if (insn.prefixes.rep) regs_.rcx = 0;
        break;
    }

    case Mnemonic::LODS: {
        int step = flag_df(regs_) ? -sz : sz;
        write_gpr(regs_, 0, sz, mem_read_(regs_.rsi, sz));
        regs_.rsi += step;
        break;
    }

    case Mnemonic::SCAS: {
        int step = flag_df(regs_) ? -sz : sz;
        uint64_t acc = read_gpr(regs_, 0, sz);
        auto do_one = [&]() {
            uint64_t mem = mem_read_(regs_.rdi, sz);
            flags_sub(regs_, acc, mem, 0, sz);
            regs_.rdi += step;
        };
        if (insn.prefixes.rep) {
            while (regs_.rcx--) { do_one(); if (!flag_zf(regs_)) break; }
        } else if (insn.prefixes.repne) {
            while (regs_.rcx--) { do_one(); if (flag_zf(regs_)) break; }
        } else {
            do_one();
        }
        break;
    }

    case Mnemonic::CMPS: {
        int step = flag_df(regs_) ? -sz : sz;
        auto do_one = [&]() {
            uint64_t a = mem_read_(regs_.rsi, sz);
            uint64_t b = mem_read_(regs_.rdi, sz);
            flags_sub(regs_, a, b, 0, sz);
            regs_.rsi += step; regs_.rdi += step;
        };
        if (insn.prefixes.rep) {
            while (regs_.rcx--) { do_one(); if (!flag_zf(regs_)) break; }
        } else if (insn.prefixes.repne) {
            while (regs_.rcx--) { do_one(); if (flag_zf(regs_)) break; }
        } else {
            do_one();
        }
        break;
    }

    // ── System instructions ───────────────────────────────────────────────────
    case Mnemonic::SYSCALL: {
        regs_.rcx = regs_.rip;      // save RIP
        uint64_t saved_rflags = regs_.rflags;
        regs_.rflags &= ~regs_.msr_sfmask;
        regs_.r11    = saved_rflags;
        regs_.rip    = regs_.msr_lstar;
        regs_.cs     = static_cast<uint16_t>((regs_.msr_star >> 32) & 0xFFFF);
        regs_.ss     = static_cast<uint16_t>(((regs_.msr_star >> 32) & 0xFFFF) + 8);
        break;
    }

    case Mnemonic::SYSRET: {
        regs_.rip    = regs_.rcx;
        regs_.rflags = regs_.r11 | 0x202;
        regs_.cs     = static_cast<uint16_t>((regs_.msr_star >> 48) | 3);
        regs_.ss     = static_cast<uint16_t>(((regs_.msr_star >> 48) + 8) | 3);
        break;
    }

    case Mnemonic::INT:
    case Mnemonic::INT3:
        handle_interrupt(insn.mnemonic == Mnemonic::INT3 ? 3
            : static_cast<uint8_t>(insn.dst.imm));
        break;

    case Mnemonic::INTO:
        if (flag_of(regs_)) handle_interrupt(4);
        break;

    case Mnemonic::CPUID: {
        uint32_t leaf = static_cast<uint32_t>(regs_.rax);
        uint32_t subleaf = static_cast<uint32_t>(regs_.rcx);
        // Minimal CPUID to satisfy Xbox GameCore boot
        switch (leaf) {
            case 0: // max leaf + vendor
                regs_.rax = 0x0000001F;
                regs_.rbx = 0x68747541; // "Auth"
                regs_.rcx = 0x444D4163; // "cAMD"
                regs_.rdx = 0x69746E65; // "enti"
                break;
            case 1: // family/model/stepping + features
                // Zen 2: Family 23, Model 113
                regs_.rax = 0x00870F10;
                regs_.rbx = 0x08100800;
                regs_.rcx = 0xFEDA3223; // SSE4.2, POPCNT, AES, AVX, ...
                regs_.rdx = 0x178BFBFF; // FPU, VME, DE, PSE, TSC, MSR, PAE, ...
                break;
            case 7: // extended features
                (void)subleaf;
                regs_.rax = 0;
                regs_.rbx = 0x029C67AF; // BMI1/2, AVX2, ...
                regs_.rcx = 0;
                regs_.rdx = 0;
                break;
            case 0x80000000:
                regs_.rax = 0x80000008;
                regs_.rbx = regs_.rcx = regs_.rdx = 0;
                break;
            case 0x80000001:
                regs_.rax = 0x00870F10;
                regs_.rbx = 0;
                regs_.rcx = 0x35C233FF; // LAHF, CMP8B, ABM, ...
                regs_.rdx = 0x2FD3FBFF; // NX, MMXEXT, ...
                break;
            case 0x80000008:
                regs_.rax = 0x00003030; // 48 virt, 48 phys
                regs_.rbx = regs_.rcx = regs_.rdx = 0;
                break;
            default:
                regs_.rax = regs_.rbx = regs_.rcx = regs_.rdx = 0;
                break;
        }
        break;
    }

    case Mnemonic::RDTSC: {
        static uint64_t tsc = 0;
        tsc += 100;
        regs_.rax = tsc & 0xFFFFFFFF;
        regs_.rdx = tsc >> 32;
        break;
    }

    case Mnemonic::RDTSCP: {
        static uint64_t tsc2 = 0;
        tsc2 += 100;
        regs_.rax = tsc2 & 0xFFFFFFFF;
        regs_.rdx = tsc2 >> 32;
        regs_.rcx = 0; // IA32_TSC_AUX
        break;
    }

    case Mnemonic::RDMSR: {
        uint32_t msr = static_cast<uint32_t>(regs_.rcx);
        uint64_t val = 0;
        switch (msr) {
            case 0xC0000080: val = regs_.msr_efer; break;
            case 0xC0000081: val = regs_.msr_star; break;
            case 0xC0000082: val = regs_.msr_lstar; break;
            case 0xC0000083: val = regs_.msr_cstar; break;
            case 0xC0000084: val = regs_.msr_sfmask; break;
            case 0xC0000100: val = regs_.msr_fs_base; break;
            case 0xC0000101: val = regs_.msr_gs_base; break;
            case 0xC0000102: val = regs_.msr_kernel_gs_base; break;
            default: break;
        }
        regs_.rax = val & 0xFFFFFFFF;
        regs_.rdx = val >> 32;
        break;
    }

    case Mnemonic::WRMSR: {
        uint32_t msr = static_cast<uint32_t>(regs_.rcx);
        uint64_t val = ((regs_.rdx & 0xFFFFFFFF) << 32) | (regs_.rax & 0xFFFFFFFF);
        switch (msr) {
            case 0xC0000080: regs_.msr_efer = val; break;
            case 0xC0000081: regs_.msr_star = val; break;
            case 0xC0000082: regs_.msr_lstar = val; break;
            case 0xC0000083: regs_.msr_cstar = val; break;
            case 0xC0000084: regs_.msr_sfmask = val; break;
            case 0xC0000100: regs_.msr_fs_base = val; break;
            case 0xC0000101: regs_.msr_gs_base = val; break;
            case 0xC0000102: regs_.msr_kernel_gs_base = val; break;
            default: break;
        }
        break;
    }

    case Mnemonic::SWAPGS: {
        uint64_t tmp = regs_.msr_gs_base;
        regs_.msr_gs_base = regs_.msr_kernel_gs_base;
        regs_.msr_kernel_gs_base = tmp;
        break;
    }

    case Mnemonic::XGETBV: {
        // return XCR0 = AVX state management
        regs_.rax = 0x07; // FP/SSE/YMM enabled
        regs_.rdx = 0;
        break;
    }

    // ── Control-register MOVs ─────────────────────────────────────────────────
    case Mnemonic::MOV_CR: {
        // dst.reg = CR index, src = GPR (or vice versa)
        // Direction is encoded by which operand is Reg vs which has the CR
        // For simplicity: dst = CR reg field, src = GPR
        uint8_t cr = insn.dst.reg;
        uint64_t val = read_operand(insn.src);
        switch (cr) {
            case 0: regs_.cr0 = val; break;
            case 2: regs_.cr2 = val; break;
            case 3: regs_.cr3 = val; break;
            case 4: regs_.cr4 = val; break;
            case 8: regs_.cr8 = val; break;
        }
        break;
    }

    // ── Descriptor-table ops (stub — just advance) ────────────────────────────
    case Mnemonic::LGDT: case Mnemonic::LIDT: case Mnemonic::LLDT:
    case Mnemonic::LTR:  case Mnemonic::SGDT: case Mnemonic::SIDT:
    case Mnemonic::SLDT: case Mnemonic::STR:
    case Mnemonic::INVLPG: case Mnemonic::INVPCID:
    case Mnemonic::WBINVD: case Mnemonic::CLFLUSH: case Mnemonic::CLFLUSHOPT:
        break;

    // ── Memory fences / prefetch ──────────────────────────────────────────────
    case Mnemonic::FENCE: case Mnemonic::MFENCE:
    case Mnemonic::SFENCE: case Mnemonic::LFENCE:
    case Mnemonic::PREFETCHT0: case Mnemonic::PREFETCHT1:
    case Mnemonic::PREFETCHT2: case Mnemonic::PREFETCHNTA:
        break;
    case Mnemonic::STMXCSR: write_operand(insn.dst, regs_.mxcsr); break;
    case Mnemonic::LDMXCSR: regs_.mxcsr = uint32_t(read_operand(insn.src)); break;

    case Mnemonic::UD2:
        handle_interrupt(6); // #UD
        break;

    // ── SSE / AVX moves ──────────────────────────────────────────────────────
    case Mnemonic::MOVAPS: case Mnemonic::MOVUPS:
    case Mnemonic::MOVAPD: case Mnemonic::MOVUPD:
    case Mnemonic::MOVDQA: case Mnemonic::MOVDQU:
    case Mnemonic::VMOVAPS: case Mnemonic::VMOVUPS:
    case Mnemonic::VMOVDQA: case Mnemonic::VMOVDQU: {
        const bool is_vex = insn.prefixes.vex ||
            insn.mnemonic == Mnemonic::VMOVAPS || insn.mnemonic == Mnemonic::VMOVUPS ||
            insn.mnemonic == Mnemonic::VMOVDQA || insn.mnemonic == Mnemonic::VMOVDQU;
        const bool is_256 = is_vex && insn.prefixes.vex_len == 1;
        if (insn.dst.type == OperandType::Reg) {
            const int dst_r = insn.dst.reg & 15;
            const XMMRegister lo = xsrc(insn.src);
            if (is_256) {
                const XMMRegister hi = xsrc_hi(insn.src);
                regs_.ymm[dst_r].lo = lo;
                regs_.ymm[dst_r].hi = hi;
            } else {
                regs_.ymm[dst_r].lo = lo;
                if (is_vex) regs_.ymm[dst_r].hi = {};
            }
        } else if (insn.dst.type == OperandType::Mem && insn.src.type == OperandType::Reg) {
            const int src_r = insn.src.reg & 15;
            uint64_t addr = eff_addr(insn.dst);
            write_xmm_mem(addr, regs_.ymm[src_r].lo);
            if (is_256) write_xmm_mem(addr + 16, regs_.ymm[src_r].hi);
        }
        break;
    }

    case Mnemonic::MOVSS: {
        const bool is_vex = insn.prefixes.vex;
        if (insn.dst.type == OperandType::Reg && insn.src.type == OperandType::Reg) {
            const int dst_r  = insn.dst.reg & 15;
            const int src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
            regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
            regs_.ymm[16].lo.d[0] = regs_.ymm[insn.src.reg & 15].lo.d[0];
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        } else if (insn.dst.type == OperandType::Reg && insn.src.type == OperandType::Mem) {
            const int dst_r = insn.dst.reg & 15;
            uint32_t v = static_cast<uint32_t>(mem_read_(eff_addr(insn.src), 4));
            regs_.ymm[dst_r].lo = {};
            regs_.ymm[dst_r].lo.d[0] = v;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        } else if (insn.dst.type == OperandType::Mem) {
            mem_write_(eff_addr(insn.dst), regs_.ymm[insn.src.reg & 15].lo.d[0], 4);
        }
        break;
    }

    case Mnemonic::MOVSD: {
        const bool is_vex = insn.prefixes.vex;
        if (insn.dst.type == OperandType::Reg && insn.src.type == OperandType::Reg) {
            const int dst_r  = insn.dst.reg & 15;
            const int src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
            regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
            regs_.ymm[16].lo.q[0] = regs_.ymm[insn.src.reg & 15].lo.q[0];
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        } else if (insn.dst.type == OperandType::Reg && insn.src.type == OperandType::Mem) {
            const int dst_r = insn.dst.reg & 15;
            uint64_t v = mem_read_(eff_addr(insn.src), 8);
            regs_.ymm[dst_r].lo = {};
            regs_.ymm[dst_r].lo.q[0] = v;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        } else if (insn.dst.type == OperandType::Mem) {
            mem_write_(eff_addr(insn.dst), regs_.ymm[insn.src.reg & 15].lo.q[0], 8);
        }
        break;
    }

    case Mnemonic::MOVQ: {
        const bool is_vex = insn.prefixes.vex;
        if (insn.dst.type == OperandType::Reg) {
            const int dst_r = insn.dst.reg & 15;
            uint64_t v = (insn.src.type == OperandType::Reg)
                ? regs_.ymm[insn.src.reg & 15].lo.q[0]
                : mem_read_(eff_addr(insn.src), 8);
            regs_.ymm[dst_r].lo.q[0] = v;
            regs_.ymm[dst_r].lo.q[1] = 0;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        } else if (insn.dst.type == OperandType::Mem) {
            mem_write_(eff_addr(insn.dst), regs_.ymm[insn.src.reg & 15].lo.q[0], 8);
        }
        break;
    }

    case Mnemonic::MOVLPS: case Mnemonic::MOVLPD: {
        const bool is_vex = insn.prefixes.vex;
        if (insn.dst.type == OperandType::Reg) {
            const int dst_r  = insn.dst.reg & 15;
            const int src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
            regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
            regs_.ymm[16].lo.q[0] = mem_read_(eff_addr(insn.src), 8);
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        } else if (insn.dst.type == OperandType::Mem) {
            mem_write_(eff_addr(insn.dst), regs_.ymm[insn.src.reg & 15].lo.q[0], 8);
        }
        break;
    }

    case Mnemonic::MOVHPS: case Mnemonic::MOVHPD: {
        const bool is_vex = insn.prefixes.vex;
        if (insn.dst.type == OperandType::Reg) {
            const int dst_r  = insn.dst.reg & 15;
            const int src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
            regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
            regs_.ymm[16].lo.q[1] = mem_read_(eff_addr(insn.src), 8);
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        } else if (insn.dst.type == OperandType::Mem) {
            mem_write_(eff_addr(insn.dst), regs_.ymm[insn.src.reg & 15].lo.q[1], 8);
        }
        break;
    }

    case Mnemonic::MOVHLPS: {
        const bool is_vex = insn.prefixes.vex;
        const int dst_r  = insn.dst.reg & 15;
        const int src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        regs_.ymm[16].lo.q[0] = regs_.ymm[insn.src.reg & 15].lo.q[1];
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }

    case Mnemonic::MOVLHPS: {
        const bool is_vex = insn.prefixes.vex;
        const int dst_r  = insn.dst.reg & 15;
        const int src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        regs_.ymm[16].lo.q[1] = regs_.ymm[insn.src.reg & 15].lo.q[0];
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }

    case Mnemonic::MOVSLDUP:
        exec_packed_un([](XMMRegister& d, const XMMRegister& s) {
            d.f[0] = s.f[0]; d.f[1] = s.f[0]; d.f[2] = s.f[2]; d.f[3] = s.f[2];
        });
        break;

    case Mnemonic::MOVSHDUP:
        exec_packed_un([](XMMRegister& d, const XMMRegister& s) {
            d.f[0] = s.f[1]; d.f[1] = s.f[1]; d.f[2] = s.f[3]; d.f[3] = s.f[3];
        });
        break;

    case Mnemonic::MOVDDUP: {
        const bool is_vex = insn.prefixes.vex;
        const bool is_256 = is_vex && insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        if (is_256) {
            const XMMRegister lo = xsrc(insn.src);
            const XMMRegister hi = xsrc_hi(insn.src);
            regs_.ymm[dst_r].lo.q[0] = regs_.ymm[dst_r].lo.q[1] = lo.q[0];
            regs_.ymm[dst_r].hi.q[0] = regs_.ymm[dst_r].hi.q[1] = hi.q[0];
        } else {
            uint64_t q = (insn.src.type == OperandType::Reg)
                ? regs_.ymm[insn.src.reg & 15].lo.q[0]
                : mem_read_(eff_addr(insn.src), 8);
            regs_.ymm[dst_r].lo.q[0] = regs_.ymm[dst_r].lo.q[1] = q;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        }
        break;
    }

    // ── VZEROUPPER / VZEROALL ─────────────────────────────────────────────────
    case Mnemonic::VZEROUPPER:
        for (int i = 0; i < 16; ++i) regs_.ymm[i].hi = {};
        break;

    case Mnemonic::VZEROALL:
        for (int i = 0; i < 16; ++i) regs_.ymm[i] = {};
        break;

    // ── SSE / AVX scalar FP ops ──────────────────────────────────────────────
    case Mnemonic::ADDSS: exec_scalar_ss([](float a, float b) { return a + b; }); break;
    case Mnemonic::SUBSS: exec_scalar_ss([](float a, float b) { return a - b; }); break;
    case Mnemonic::MULSS: exec_scalar_ss([](float a, float b) { return a * b; }); break;
    case Mnemonic::DIVSS: exec_scalar_ss([](float a, float b) { return a / b; }); break;
    case Mnemonic::MINSS: exec_scalar_ss([](float a, float b) { return (a < b) ? a : b; }); break;
    case Mnemonic::MAXSS: exec_scalar_ss([](float a, float b) { return (a > b) ? a : b; }); break;
    case Mnemonic::SQRTSS:  exec_scalar_ss([](float, float b) { return std::sqrt(b); }); break;
    case Mnemonic::RSQRTSS: exec_scalar_ss([](float, float b) { return 1.0f / std::sqrt(b); }); break;
    case Mnemonic::RCPSS:   exec_scalar_ss([](float, float b) { return 1.0f / b; }); break;

    case Mnemonic::ADDSD: exec_scalar_sd([](double a, double b) { return a + b; }); break;
    case Mnemonic::SUBSD: exec_scalar_sd([](double a, double b) { return a - b; }); break;
    case Mnemonic::MULSD: exec_scalar_sd([](double a, double b) { return a * b; }); break;
    case Mnemonic::DIVSD: exec_scalar_sd([](double a, double b) { return a / b; }); break;
    case Mnemonic::MINSD: exec_scalar_sd([](double a, double b) { return (a < b) ? a : b; }); break;
    case Mnemonic::MAXSD: exec_scalar_sd([](double a, double b) { return (a > b) ? a : b; }); break;
    case Mnemonic::SQRTSD: exec_scalar_sd([](double, double b) { return std::sqrt(b); }); break;

    // ── SSE / AVX packed FP arithmetic & unary ops ───────────────────────────
    case Mnemonic::ADDPS: case Mnemonic::VADDPS:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i) d.f[i] += s.f[i];
        });
        break;
    case Mnemonic::SUBPS: case Mnemonic::VSUBPS:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i) d.f[i] -= s.f[i];
        });
        break;
    case Mnemonic::MULPS: case Mnemonic::VMULPS:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i) d.f[i] *= s.f[i];
        });
        break;
    case Mnemonic::DIVPS: case Mnemonic::VDIVPS:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i) d.f[i] /= s.f[i];
        });
        break;
    case Mnemonic::MINPS:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i) d.f[i] = (d.f[i] < s.f[i]) ? d.f[i] : s.f[i];
        });
        break;
    case Mnemonic::MAXPS:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i) d.f[i] = (d.f[i] > s.f[i]) ? d.f[i] : s.f[i];
        });
        break;

    case Mnemonic::ADDPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 2; ++i) d.df[i] += s.df[i];
        });
        break;
    case Mnemonic::SUBPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 2; ++i) d.df[i] -= s.df[i];
        });
        break;
    case Mnemonic::MULPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 2; ++i) d.df[i] *= s.df[i];
        });
        break;
    case Mnemonic::DIVPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 2; ++i) d.df[i] /= s.df[i];
        });
        break;
    case Mnemonic::MINPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 2; ++i) d.df[i] = (d.df[i] < s.df[i]) ? d.df[i] : s.df[i];
        });
        break;
    case Mnemonic::MAXPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 2; ++i) d.df[i] = (d.df[i] > s.df[i]) ? d.df[i] : s.df[i];
        });
        break;

    case Mnemonic::SQRTPS:
        exec_packed_un([](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 4; ++i) d.f[i] = std::sqrt(s.f[i]);
        });
        break;
    case Mnemonic::SQRTPD:
        exec_packed_un([](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 2; ++i) d.df[i] = std::sqrt(s.df[i]);
        });
        break;
    case Mnemonic::RSQRTPS:
        exec_packed_un([](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 4; ++i) d.f[i] = 1.0f / std::sqrt(s.f[i]);
        });
        break;
    case Mnemonic::RCPPS:
        exec_packed_un([](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 4; ++i) d.f[i] = 1.0f / s.f[i];
        });
        break;

    // ── SSE / AVX bitwise ops ────────────────────────────────────────────────
    case Mnemonic::PXOR: case Mnemonic::VPXOR:
    case Mnemonic::XORPS: case Mnemonic::XORPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            d.q[0] ^= s.q[0]; d.q[1] ^= s.q[1];
        });
        break;
    case Mnemonic::PAND: case Mnemonic::VPAND:
    case Mnemonic::ANDPS: case Mnemonic::ANDPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            d.q[0] &= s.q[0]; d.q[1] &= s.q[1];
        });
        break;
    case Mnemonic::PANDN:
    case Mnemonic::ANDNPS: case Mnemonic::ANDNPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            d.q[0] = ~d.q[0] & s.q[0]; d.q[1] = ~d.q[1] & s.q[1];
        });
        break;
    case Mnemonic::POR: case Mnemonic::VPOR:
    case Mnemonic::ORPS: case Mnemonic::ORPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            d.q[0] |= s.q[0]; d.q[1] |= s.q[1];
        });
        break;

    // ── SSE / AVX FP compare & mask ──────────────────────────────────────────
    case Mnemonic::CMPPS: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        bool is_vex = insn.prefixes.vex;
        exec_packed_bin([imm, is_vex](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i)
                d.d[i] = fp_cmp_pred(d.f[i], s.f[i], imm, is_vex) ? 0xFFFFFFFFu : 0u;
        });
        break;
    }
    case Mnemonic::CMPPD: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        bool is_vex = insn.prefixes.vex;
        exec_packed_bin([imm, is_vex](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 2; ++i)
                d.q[i] = fp_cmp_pred(d.df[i], s.df[i], imm, is_vex) ? ~0ULL : 0ULL;
        });
        break;
    }
    case Mnemonic::CMPSS: {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        float b = read_f32(insn.src);
        regs_.ymm[16].lo.d[0] = fp_cmp_pred(regs_.ymm[16].lo.f[0], b, imm, is_vex) ? 0xFFFFFFFFu : 0u;
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }
    case Mnemonic::CMPSD: {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        double b = read_f64(insn.src);
        regs_.ymm[16].lo.q[0] = fp_cmp_pred(regs_.ymm[16].lo.df[0], b, imm, is_vex) ? ~0ULL : 0ULL;
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }

    case Mnemonic::COMISS:
    case Mnemonic::UCOMISS: {
        float a = regs_.ymm[insn.dst.reg & 15].lo.f[0];
        float b = read_f32(insn.src);
        fp_ucomi(regs_, static_cast<double>(a), static_cast<double>(b));
        break;
    }
    case Mnemonic::COMISD:
    case Mnemonic::UCOMISD: {
        double a = regs_.ymm[insn.dst.reg & 15].lo.df[0];
        double b = read_f64(insn.src);
        fp_ucomi(regs_, a, b);
        break;
    }

    case Mnemonic::MOVMSKPS: {
        const bool is_256 = insn.prefixes.vex && insn.prefixes.vex_len == 1;
        const int  src_r  = insn.src.reg & 15;
        uint32_t mask = 0;
        for (int i = 0; i < 4; ++i)
            if (regs_.ymm[src_r].lo.d[i] & 0x80000000u) mask |= (1u << i);
        if (is_256) {
            for (int i = 0; i < 4; ++i)
                if (regs_.ymm[src_r].hi.d[i] & 0x80000000u) mask |= (1u << (i + 4));
        }
        write_operand(insn.dst, mask);
        break;
    }
    case Mnemonic::MOVMSKPD: {
        const bool is_256 = insn.prefixes.vex && insn.prefixes.vex_len == 1;
        const int  src_r  = insn.src.reg & 15;
        uint32_t mask = 0;
        for (int i = 0; i < 2; ++i)
            if (regs_.ymm[src_r].lo.q[i] >> 63) mask |= (1u << i);
        if (is_256) {
            for (int i = 0; i < 2; ++i)
                if (regs_.ymm[src_r].hi.q[i] >> 63) mask |= (1u << (i + 2));
        }
        write_operand(insn.dst, mask);
        break;
    }

    // ── SSE / AVX shuffles & unpacks ─────────────────────────────────────────
    case Mnemonic::SHUFPS: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_bin([imm](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.d[0] = d.d[(imm >> 0) & 3];
            r.d[1] = d.d[(imm >> 2) & 3];
            r.d[2] = s.d[(imm >> 4) & 3];
            r.d[3] = s.d[(imm >> 6) & 3];
            d = r;
        });
        break;
    }
    case Mnemonic::SHUFPD: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_bin([imm](XMMRegister& d, const XMMRegister& s, int lane) {
            uint8_t sel = static_cast<uint8_t>(imm >> (lane * 2));
            XMMRegister r{};
            r.q[0] = d.q[(sel >> 0) & 1];
            r.q[1] = s.q[(sel >> 1) & 1];
            d = r;
        });
        break;
    }
    case Mnemonic::UNPCKLPS:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.d[0] = d.d[0]; r.d[1] = s.d[0]; r.d[2] = d.d[1]; r.d[3] = s.d[1];
            d = r;
        });
        break;
    case Mnemonic::UNPCKHPS:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.d[0] = d.d[2]; r.d[1] = s.d[2]; r.d[2] = d.d[3]; r.d[3] = s.d[3];
            d = r;
        });
        break;
    case Mnemonic::UNPCKLPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.q[0] = d.q[0]; r.q[1] = s.q[0];
            d = r;
        });
        break;
    case Mnemonic::UNPCKHPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.q[0] = d.q[1]; r.q[1] = s.q[1];
            d = r;
        });
        break;

    // ── SSE / AVX integer ops ────────────────────────────────────────────────
    case Mnemonic::PADDB:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 16; ++i) d.b[i] += s.b[i];
        });
        break;
    case Mnemonic::PADDW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 8; ++i) d.w[i] += s.w[i];
        });
        break;
    case Mnemonic::PADDD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i) d.d[i] += s.d[i];
        });
        break;
    case Mnemonic::PADDQ:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            d.q[0] += s.q[0]; d.q[1] += s.q[1];
        });
        break;
    case Mnemonic::PSUBB:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 16; ++i) d.b[i] -= s.b[i];
        });
        break;
    case Mnemonic::PSUBW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 8; ++i) d.w[i] -= s.w[i];
        });
        break;
    case Mnemonic::PSUBD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i) d.d[i] -= s.d[i];
        });
        break;
    case Mnemonic::PSUBQ:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            d.q[0] -= s.q[0]; d.q[1] -= s.q[1];
        });
        break;

    case Mnemonic::PCMPEQB:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 16; ++i) d.b[i] = (d.b[i] == s.b[i]) ? 0xFF : 0;
        });
        break;
    case Mnemonic::PCMPEQW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 8; ++i) d.w[i] = (d.w[i] == s.w[i]) ? 0xFFFF : 0;
        });
        break;
    case Mnemonic::PCMPEQD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i) d.d[i] = (d.d[i] == s.d[i]) ? 0xFFFFFFFFu : 0;
        });
        break;

    // movd/movq between GPR/mem and xmm; xmm destination zero-extends
    case Mnemonic::MOVD: {
        int msz = insn.op_size == 8 ? 8 : 4;
        if (insn.dst.type == OperandType::Reg && insn.dst.size >= 16) {
            uint64_t v = (insn.src.type == OperandType::Reg) ? read_operand(insn.src)
                                                             : mem_read_(eff_addr(insn.src), msz);
            if (msz == 4) v &= 0xFFFFFFFFull;
            const int dst_r = insn.dst.reg & 15;
            regs_.ymm[dst_r].lo.q[0] = v;
            regs_.ymm[dst_r].lo.q[1] = 0;
            if (insn.prefixes.vex) regs_.ymm[dst_r].hi = {};
        } else {
            uint64_t v = regs_.ymm[insn.src.reg & 15].lo.q[0];
            if (msz == 4) v &= 0xFFFFFFFFull;
            if (insn.dst.type == OperandType::Reg) write_operand(insn.dst, v);
            else mem_write_(eff_addr(insn.dst), v, msz);
        }
        break;
    }

    case Mnemonic::PUNPCKLBW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            for (int i = 0; i < 8; ++i) { r.b[2*i] = d.b[i]; r.b[2*i+1] = s.b[i]; }
            d = r;
        });
        break;
    case Mnemonic::PUNPCKLWD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            for (int i = 0; i < 4; ++i) { r.w[2*i] = d.w[i]; r.w[2*i+1] = s.w[i]; }
            d = r;
        });
        break;
    case Mnemonic::PUNPCKLDQ:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            for (int i = 0; i < 2; ++i) { r.d[2*i] = d.d[i]; r.d[2*i+1] = s.d[i]; }
            d = r;
        });
        break;
    case Mnemonic::PUNPCKLQDQ:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.q[0] = d.q[0]; r.q[1] = s.q[0];
            d = r;
        });
        break;

    case Mnemonic::PSHUFB:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            for (int i = 0; i < 16; ++i)
                r.b[i] = (s.b[i] & 0x80) ? 0 : d.b[s.b[i] & 0x0F];
            d = r;
        });
        break;

    case Mnemonic::PSHUFLW:
    case Mnemonic::PSHUFHW: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        int base = (insn.mnemonic == Mnemonic::PSHUFLW) ? 0 : 4;
        exec_packed_un([imm, base](XMMRegister& d, const XMMRegister& s) {
            d = s;
            for (int i = 0; i < 4; ++i)
                d.w[base + i] = s.w[base + ((imm >> (i * 2)) & 3)];
        });
        break;
    }

    case Mnemonic::PSHUFD: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_un([imm](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 4; ++i)
                d.d[i] = s.d[(imm >> (i * 2)) & 3];
        });
        break;
    }

    case Mnemonic::PMOVMSKB: {
        const bool is_256 = insn.prefixes.vex && insn.prefixes.vex_len == 1;
        const int  src_r  = insn.src.reg & 15;
        uint32_t mask = 0;
        for (int i = 0; i < 16; ++i)
            if (regs_.ymm[src_r].lo.b[i] & 0x80) mask |= (1u << i);
        if (is_256) {
            for (int i = 0; i < 16; ++i)
                if (regs_.ymm[src_r].hi.b[i] & 0x80) mask |= (1u << (i + 16));
        }
        write_operand(insn.dst, mask);
        break;
    }

    // ── SSE / AVX conversions ────────────────────────────────────────────────
    case Mnemonic::CVTSI2SS: {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        uint64_t raw = read_operand(insn.src);
        int64_t iv = (insn.op_size == 8) ? static_cast<int64_t>(raw)
                                         : static_cast<int64_t>(static_cast<int32_t>(raw));
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        regs_.ymm[16].lo.f[0] = static_cast<float>(iv);
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }
    case Mnemonic::CVTSI2SD: {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        uint64_t raw = read_operand(insn.src);
        int64_t iv = (insn.op_size == 8) ? static_cast<int64_t>(raw)
                                         : static_cast<int64_t>(static_cast<int32_t>(raw));
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        regs_.ymm[16].lo.df[0] = static_cast<double>(iv);
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }
    case Mnemonic::CVTTSS2SI: {
        double v = static_cast<double>(read_f32(insn.src));
        uint64_t res = (insn.op_size == 8)
            ? static_cast<uint64_t>(cvtt_f64_to_i64(v))
            : static_cast<uint64_t>(static_cast<uint32_t>(cvtt_f64_to_i32(v)));
        write_operand(insn.dst, res);
        break;
    }
    case Mnemonic::CVTTSD2SI: {
        double v = read_f64(insn.src);
        uint64_t res = (insn.op_size == 8)
            ? static_cast<uint64_t>(cvtt_f64_to_i64(v))
            : static_cast<uint64_t>(static_cast<uint32_t>(cvtt_f64_to_i32(v)));
        write_operand(insn.dst, res);
        break;
    }
    case Mnemonic::CVTSS2SI: {
        double v = static_cast<double>(read_f32(insn.src));
        uint64_t res = (insn.op_size == 8)
            ? static_cast<uint64_t>(cvt_f64_to_i64(v))
            : static_cast<uint64_t>(static_cast<uint32_t>(cvt_f64_to_i32(v)));
        write_operand(insn.dst, res);
        break;
    }
    case Mnemonic::CVTSD2SI: {
        double v = read_f64(insn.src);
        uint64_t res = (insn.op_size == 8)
            ? static_cast<uint64_t>(cvt_f64_to_i64(v))
            : static_cast<uint64_t>(static_cast<uint32_t>(cvt_f64_to_i32(v)));
        write_operand(insn.dst, res);
        break;
    }
    case Mnemonic::CVTSS2SD: {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        float fv = read_f32(insn.src);
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        regs_.ymm[16].lo.df[0] = static_cast<double>(fv);
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }
    case Mnemonic::CVTSD2SS: {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        double dv = read_f64(insn.src);
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        regs_.ymm[16].lo.f[0] = static_cast<float>(dv);
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }
    case Mnemonic::CVTPS2PD: {
        const bool is_vex = insn.prefixes.vex;
        const bool is_256 = is_vex && insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        if (is_256) {
            const XMMRegister s = xsrc(insn.src);
            regs_.ymm[16].lo.df[0] = static_cast<double>(s.f[0]);
            regs_.ymm[16].lo.df[1] = static_cast<double>(s.f[1]);
            regs_.ymm[16].hi.df[0] = static_cast<double>(s.f[2]);
            regs_.ymm[16].hi.df[1] = static_cast<double>(s.f[3]);
            regs_.ymm[dst_r] = regs_.ymm[16];
        } else {
            float f0, f1;
            if (insn.src.type == OperandType::Reg) {
                f0 = regs_.ymm[insn.src.reg & 15].lo.f[0];
                f1 = regs_.ymm[insn.src.reg & 15].lo.f[1];
            } else {
                uint64_t raw = mem_read_(eff_addr(insn.src), 8);
                f0 = std::bit_cast<float>(static_cast<uint32_t>(raw & 0xFFFFFFFFu));
                f1 = std::bit_cast<float>(static_cast<uint32_t>(raw >> 32));
            }
            regs_.ymm[dst_r].lo.df[0] = static_cast<double>(f0);
            regs_.ymm[dst_r].lo.df[1] = static_cast<double>(f1);
            if (is_vex) regs_.ymm[dst_r].hi = {};
        }
        break;
    }
    case Mnemonic::CVTPD2PS: {
        const bool is_vex = insn.prefixes.vex;
        const bool is_256 = is_vex && insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        const XMMRegister lo = xsrc(insn.src);
        regs_.ymm[16].lo = {};
        regs_.ymm[16].lo.f[0] = static_cast<float>(lo.df[0]);
        regs_.ymm[16].lo.f[1] = static_cast<float>(lo.df[1]);
        if (is_256) {
            const XMMRegister hi = xsrc_hi(insn.src);
            regs_.ymm[16].lo.f[2] = static_cast<float>(hi.df[0]);
            regs_.ymm[16].lo.f[3] = static_cast<float>(hi.df[1]);
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            regs_.ymm[dst_r].hi = {};
        } else {
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        }
        break;
    }
    case Mnemonic::CVTDQ2PS:
        exec_packed_un([](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 4; ++i)
                d.f[i] = static_cast<float>(static_cast<int32_t>(s.d[i]));
        });
        break;
    case Mnemonic::CVTPS2DQ:
        exec_packed_un([](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 4; ++i)
                d.d[i] = static_cast<uint32_t>(cvt_f64_to_i32(static_cast<double>(s.f[i])));
        });
        break;
    case Mnemonic::CVTTPS2DQ:
        exec_packed_un([](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 4; ++i)
                d.d[i] = static_cast<uint32_t>(cvtt_f64_to_i32(static_cast<double>(s.f[i])));
        });
        break;
    case Mnemonic::CVTDQ2PD: {
        const bool is_vex = insn.prefixes.vex;
        const bool is_256 = is_vex && insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        if (is_256) {
            const XMMRegister s = xsrc(insn.src);
            regs_.ymm[16].lo.df[0] = static_cast<double>(static_cast<int32_t>(s.d[0]));
            regs_.ymm[16].lo.df[1] = static_cast<double>(static_cast<int32_t>(s.d[1]));
            regs_.ymm[16].hi.df[0] = static_cast<double>(static_cast<int32_t>(s.d[2]));
            regs_.ymm[16].hi.df[1] = static_cast<double>(static_cast<int32_t>(s.d[3]));
            regs_.ymm[dst_r] = regs_.ymm[16];
        } else {
            int32_t i0, i1;
            if (insn.src.type == OperandType::Reg) {
                i0 = static_cast<int32_t>(regs_.ymm[insn.src.reg & 15].lo.d[0]);
                i1 = static_cast<int32_t>(regs_.ymm[insn.src.reg & 15].lo.d[1]);
            } else {
                uint64_t raw = mem_read_(eff_addr(insn.src), 8);
                i0 = static_cast<int32_t>(raw & 0xFFFFFFFFu);
                i1 = static_cast<int32_t>(raw >> 32);
            }
            regs_.ymm[dst_r].lo.df[0] = static_cast<double>(i0);
            regs_.ymm[dst_r].lo.df[1] = static_cast<double>(i1);
            if (is_vex) regs_.ymm[dst_r].hi = {};
        }
        break;
    }
    case Mnemonic::CVTTPD2DQ:
    case Mnemonic::CVTPD2DQ: {
        const bool is_vex   = insn.prefixes.vex;
        const bool is_256   = is_vex && insn.prefixes.vex_len == 1;
        const bool is_trunc = (insn.mnemonic == Mnemonic::CVTTPD2DQ);
        const int  dst_r    = insn.dst.reg & 15;
        const XMMRegister lo = xsrc(insn.src);
        regs_.ymm[16].lo = {};
        regs_.ymm[16].lo.d[0] = static_cast<uint32_t>(is_trunc ? cvtt_f64_to_i32(lo.df[0]) : cvt_f64_to_i32(lo.df[0]));
        regs_.ymm[16].lo.d[1] = static_cast<uint32_t>(is_trunc ? cvtt_f64_to_i32(lo.df[1]) : cvt_f64_to_i32(lo.df[1]));
        if (is_256) {
            const XMMRegister hi = xsrc_hi(insn.src);
            regs_.ymm[16].lo.d[2] = static_cast<uint32_t>(is_trunc ? cvtt_f64_to_i32(hi.df[0]) : cvt_f64_to_i32(hi.df[0]));
            regs_.ymm[16].lo.d[3] = static_cast<uint32_t>(is_trunc ? cvtt_f64_to_i32(hi.df[1]) : cvt_f64_to_i32(hi.df[1]));
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            regs_.ymm[dst_r].hi = {};
        } else {
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        }
        break;
    }

    // ── SSE4.1 / AVX / AVX2 (0F 38 / 0F 3A) ──────────────────────────────────
    case Mnemonic::PEXTRB: {
        uint8_t idx = static_cast<uint8_t>(insn.src2.imm) & 15;
        uint64_t val = regs_.ymm[insn.src.reg & 15].lo.b[idx];
        write_operand(insn.dst, val);
        break;
    }
    case Mnemonic::PEXTRW: {
        uint8_t idx = static_cast<uint8_t>(insn.src2.imm) & 7;
        uint64_t val = regs_.ymm[insn.src.reg & 15].lo.w[idx];
        write_operand(insn.dst, val);
        break;
    }
    case Mnemonic::PEXTRD: {
        uint8_t idx = static_cast<uint8_t>(insn.src2.imm) & 3;
        uint64_t val = regs_.ymm[insn.src.reg & 15].lo.d[idx];
        write_operand(insn.dst, val);
        break;
    }
    case Mnemonic::PEXTRQ: {
        uint8_t idx = static_cast<uint8_t>(insn.src2.imm) & 1;
        uint64_t val = regs_.ymm[insn.src.reg & 15].lo.q[idx];
        write_operand(insn.dst, val);
        break;
    }

    case Mnemonic::PINSRB: {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        uint8_t v = static_cast<uint8_t>(read_operand(insn.src));
        uint8_t idx = static_cast<uint8_t>(insn.src2.imm) & 15;
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        regs_.ymm[16].lo.b[idx] = v;
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }
    case Mnemonic::PINSRW: {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        uint16_t v = static_cast<uint16_t>(read_operand(insn.src));
        uint8_t idx = static_cast<uint8_t>(insn.src2.imm) & 7;
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        regs_.ymm[16].lo.w[idx] = v;
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }
    case Mnemonic::PINSRD: {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        uint32_t v = static_cast<uint32_t>(read_operand(insn.src));
        uint8_t idx = static_cast<uint8_t>(insn.src2.imm) & 3;
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        regs_.ymm[16].lo.d[idx] = v;
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }
    case Mnemonic::PINSRQ: {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        uint64_t v = read_operand(insn.src);
        uint8_t idx = static_cast<uint8_t>(insn.src2.imm) & 1;
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        regs_.ymm[16].lo.q[idx] = v;
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }
    case Mnemonic::INSERTPS: {
        const bool is_vex = insn.prefixes.vex;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        uint32_t elem;
        if (insn.src.type == OperandType::Reg)
            elem = regs_.ymm[insn.src.reg & 15].lo.d[(imm >> 6) & 3];
        else
            elem = static_cast<uint32_t>(mem_read_(eff_addr(insn.src), 4));
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        regs_.ymm[16].lo.d[(imm >> 4) & 3] = elem;
        for (int i = 0; i < 4; ++i)
            if (imm & (1u << i)) regs_.ymm[16].lo.d[i] = 0;
        regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
        if (is_vex) regs_.ymm[dst_r].hi = {};
        break;
    }

    case Mnemonic::VBROADCASTSS: {
        const bool is_256 = insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        uint32_t v = (insn.src.type == OperandType::Reg)
            ? regs_.ymm[insn.src.reg & 15].lo.d[0]
            : static_cast<uint32_t>(mem_read_(eff_addr(insn.src), 4));
        for (int i = 0; i < 4; ++i) regs_.ymm[dst_r].lo.d[i] = v;
        if (is_256) { for (int i = 0; i < 4; ++i) regs_.ymm[dst_r].hi.d[i] = v; }
        else        { regs_.ymm[dst_r].hi = {}; }
        break;
    }
    case Mnemonic::VBROADCASTSD: {
        const bool is_256 = insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        uint64_t v = (insn.src.type == OperandType::Reg)
            ? regs_.ymm[insn.src.reg & 15].lo.q[0]
            : mem_read_(eff_addr(insn.src), 8);
        regs_.ymm[dst_r].lo.q[0] = regs_.ymm[dst_r].lo.q[1] = v;
        if (is_256) { regs_.ymm[dst_r].hi.q[0] = regs_.ymm[dst_r].hi.q[1] = v; }
        else        { regs_.ymm[dst_r].hi = {}; }
        break;
    }
    case Mnemonic::VBROADCASTF128: {
        const int dst_r = insn.dst.reg & 15;
        const XMMRegister v = xsrc(insn.src);
        regs_.ymm[dst_r].lo = v;
        regs_.ymm[dst_r].hi = v;
        break;
    }
    case Mnemonic::VPBROADCASTB: {
        const bool is_256 = insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        uint8_t v = (insn.src.type == OperandType::Reg)
            ? regs_.ymm[insn.src.reg & 15].lo.b[0]
            : static_cast<uint8_t>(mem_read_(eff_addr(insn.src), 1));
        for (int i = 0; i < 16; ++i) regs_.ymm[dst_r].lo.b[i] = v;
        if (is_256) { for (int i = 0; i < 16; ++i) regs_.ymm[dst_r].hi.b[i] = v; }
        else        { regs_.ymm[dst_r].hi = {}; }
        break;
    }
    case Mnemonic::VPBROADCASTW: {
        const bool is_256 = insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        uint16_t v = (insn.src.type == OperandType::Reg)
            ? regs_.ymm[insn.src.reg & 15].lo.w[0]
            : static_cast<uint16_t>(mem_read_(eff_addr(insn.src), 2));
        for (int i = 0; i < 8; ++i) regs_.ymm[dst_r].lo.w[i] = v;
        if (is_256) { for (int i = 0; i < 8; ++i) regs_.ymm[dst_r].hi.w[i] = v; }
        else        { regs_.ymm[dst_r].hi = {}; }
        break;
    }

    case Mnemonic::PTEST: {
        const bool is_256 = insn.prefixes.vex && insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        const XMMRegister a_lo = regs_.ymm[dst_r].lo;
        const XMMRegister b_lo = xsrc(insn.src);
        uint64_t and_nz  = (a_lo.q[0] & b_lo.q[0]) | (a_lo.q[1] & b_lo.q[1]);
        uint64_t andn_nz = (~a_lo.q[0] & b_lo.q[0]) | (~a_lo.q[1] & b_lo.q[1]);
        if (is_256) {
            const XMMRegister a_hi = regs_.ymm[dst_r].hi;
            const XMMRegister b_hi = xsrc_hi(insn.src);
            and_nz  |= (a_hi.q[0] & b_hi.q[0]) | (a_hi.q[1] & b_hi.q[1]);
            andn_nz |= (~a_hi.q[0] & b_hi.q[0]) | (~a_hi.q[1] & b_hi.q[1]);
        }
        set_flag(regs_, 6,  and_nz == 0);
        set_flag(regs_, 0,  andn_nz == 0);
        set_flag(regs_, 2,  false);
        set_flag(regs_, 4,  false);
        set_flag(regs_, 7,  false);
        set_flag(regs_, 11, false);
        break;
    }

    case Mnemonic::PALIGNR: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_bin([imm](XMMRegister& d, const XMMRegister& s, int) {
            uint8_t buf[32];
            std::memcpy(buf, s.b, 16);
            std::memcpy(buf + 16, d.b, 16);
            XMMRegister r{};
            for (int i = 0; i < 16; ++i)
                r.b[i] = (imm + i < 32) ? buf[imm + i] : 0;
            d = r;
        });
        break;
    }

    case Mnemonic::BLENDPS: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_bin([imm](XMMRegister& d, const XMMRegister& s, int lane) {
            uint8_t m = static_cast<uint8_t>(imm >> (lane * 4));
            for (int i = 0; i < 4; ++i) if (m & (1u << i)) d.d[i] = s.d[i];
        });
        break;
    }
    case Mnemonic::BLENDPD: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_bin([imm](XMMRegister& d, const XMMRegister& s, int lane) {
            uint8_t m = static_cast<uint8_t>(imm >> (lane * 2));
            for (int i = 0; i < 2; ++i) if (m & (1u << i)) d.q[i] = s.q[i];
        });
        break;
    }
    case Mnemonic::PBLENDW: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_bin([imm](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 8; ++i) if (imm & (1u << i)) d.w[i] = s.w[i];
        });
        break;
    }
    case Mnemonic::VBLENDVPS: {
        int mask_r = (static_cast<uint8_t>(insn.src2.imm) >> 4) & 15;
        exec_packed_bin([this, mask_r](XMMRegister& d, const XMMRegister& s, int lane) {
            const XMMRegister& m = lane ? regs_.ymm[mask_r].hi : regs_.ymm[mask_r].lo;
            for (int i = 0; i < 4; ++i) if (m.d[i] & 0x80000000u) d.d[i] = s.d[i];
        });
        break;
    }
    case Mnemonic::VBLENDVPD: {
        int mask_r = (static_cast<uint8_t>(insn.src2.imm) >> 4) & 15;
        exec_packed_bin([this, mask_r](XMMRegister& d, const XMMRegister& s, int lane) {
            const XMMRegister& m = lane ? regs_.ymm[mask_r].hi : regs_.ymm[mask_r].lo;
            for (int i = 0; i < 2; ++i) if (m.q[i] >> 63) d.q[i] = s.q[i];
        });
        break;
    }
    case Mnemonic::VPBLENDVB: {
        int mask_r = (static_cast<uint8_t>(insn.src2.imm) >> 4) & 15;
        exec_packed_bin([this, mask_r](XMMRegister& d, const XMMRegister& s, int lane) {
            const XMMRegister& m = lane ? regs_.ymm[mask_r].hi : regs_.ymm[mask_r].lo;
            for (int i = 0; i < 16; ++i) if (m.b[i] & 0x80) d.b[i] = s.b[i];
        });
        break;
    }

    case Mnemonic::ROUNDPS: {
        uint8_t mode = static_cast<uint8_t>(insn.src2.imm) & 3;
        exec_packed_un([mode](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 4; ++i) {
                float v = s.f[i];
                if      (mode == 1) d.f[i] = std::floor(v);
                else if (mode == 2) d.f[i] = std::ceil(v);
                else if (mode == 3) d.f[i] = std::trunc(v);
                else                d.f[i] = std::nearbyint(v);
            }
        });
        break;
    }
    case Mnemonic::ROUNDPD: {
        uint8_t mode = static_cast<uint8_t>(insn.src2.imm) & 3;
        exec_packed_un([mode](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 2; ++i) {
                double v = s.df[i];
                if      (mode == 1) d.df[i] = std::floor(v);
                else if (mode == 2) d.df[i] = std::ceil(v);
                else if (mode == 3) d.df[i] = std::trunc(v);
                else                d.df[i] = std::nearbyint(v);
            }
        });
        break;
    }
    case Mnemonic::ROUNDSS: {
        uint8_t mode = static_cast<uint8_t>(insn.src2.imm) & 3;
        exec_scalar_ss([mode](float, float b) -> float {
            if (mode == 1) return std::floor(b);
            if (mode == 2) return std::ceil(b);
            if (mode == 3) return std::trunc(b);
            return std::nearbyint(b);
        });
        break;
    }
    case Mnemonic::ROUNDSD: {
        uint8_t mode = static_cast<uint8_t>(insn.src2.imm) & 3;
        exec_scalar_sd([mode](double, double b) -> double {
            if (mode == 1) return std::floor(b);
            if (mode == 2) return std::ceil(b);
            if (mode == 3) return std::trunc(b);
            return std::nearbyint(b);
        });
        break;
    }

    case Mnemonic::VPERMQ: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        const int dst_r = insn.dst.reg & 15;
        XMMRegister lo = xsrc(insn.src);
        XMMRegister hi = xsrc_hi(insn.src);
        uint64_t q[4] = { lo.q[0], lo.q[1], hi.q[0], hi.q[1] };
        regs_.ymm[16].lo.q[0] = q[(imm >> 0) & 3];
        regs_.ymm[16].lo.q[1] = q[(imm >> 2) & 3];
        regs_.ymm[16].hi.q[0] = q[(imm >> 4) & 3];
        regs_.ymm[16].hi.q[1] = q[(imm >> 6) & 3];
        regs_.ymm[dst_r] = regs_.ymm[16];
        break;
    }
    case Mnemonic::VPERMILPS: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_un([imm](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 4; ++i) d.d[i] = s.d[(imm >> (i * 2)) & 3];
        });
        break;
    }
    case Mnemonic::VPERMILPD: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        const bool is_256 = insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        const XMMRegister s_lo = xsrc(insn.src);
        regs_.ymm[16].lo.q[0] = s_lo.q[(imm >> 0) & 1];
        regs_.ymm[16].lo.q[1] = s_lo.q[(imm >> 1) & 1];
        if (is_256) {
            const XMMRegister s_hi = xsrc_hi(insn.src);
            regs_.ymm[16].hi.q[0] = s_hi.q[(imm >> 2) & 1];
            regs_.ymm[16].hi.q[1] = s_hi.q[(imm >> 3) & 1];
            regs_.ymm[dst_r] = regs_.ymm[16];
        } else {
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            regs_.ymm[dst_r].hi = {};
        }
        break;
    }
    case Mnemonic::VPERM2F128: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        const int dst_r  = insn.dst.reg & 15;
        const int src1_r = insn.prefixes.vex_vvvv & 15;
        XMMRegister lanes[4] = { regs_.ymm[src1_r].lo, regs_.ymm[src1_r].hi, xsrc(insn.src), xsrc_hi(insn.src) };
        regs_.ymm[16].lo = (imm & 0x08) ? XMMRegister{} : lanes[imm & 3];
        regs_.ymm[16].hi = (imm & 0x80) ? XMMRegister{} : lanes[(imm >> 4) & 3];
        regs_.ymm[dst_r] = regs_.ymm[16];
        break;
    }
    case Mnemonic::VINSERTF128: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm) & 1;
        const int dst_r  = insn.dst.reg & 15;
        const int src1_r = insn.prefixes.vex_vvvv & 15;
        XMMRegister s = xsrc(insn.src);
        regs_.ymm[16] = regs_.ymm[src1_r];
        if (imm == 0) regs_.ymm[16].lo = s;
        else          regs_.ymm[16].hi = s;
        regs_.ymm[dst_r] = regs_.ymm[16];
        break;
    }
    case Mnemonic::VEXTRACTF128: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm) & 1;
        const int src_r = insn.src.reg & 15;
        const XMMRegister& lane = (imm == 0) ? regs_.ymm[src_r].lo : regs_.ymm[src_r].hi;
        if (insn.dst.type == OperandType::Reg) {
            const int dst_r = insn.dst.reg & 15;
            regs_.ymm[dst_r].lo = lane;
            regs_.ymm[dst_r].hi = {};
        } else {
            write_xmm_mem(eff_addr(insn.dst), lane);
        }
        break;
    }

    // ── SSE3 horizontal / addsub, SSE4.1 dot product, unpack high, cmpgt, shifts ─
    case Mnemonic::HADDPS:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.f[0] = d.f[0] + d.f[1];
            r.f[1] = d.f[2] + d.f[3];
            r.f[2] = s.f[0] + s.f[1];
            r.f[3] = s.f[2] + s.f[3];
            d = r;
        });
        break;
    case Mnemonic::HADDPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.df[0] = d.df[0] + d.df[1];
            r.df[1] = s.df[0] + s.df[1];
            d = r;
        });
        break;
    case Mnemonic::HSUBPS:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.f[0] = d.f[0] - d.f[1];
            r.f[1] = d.f[2] - d.f[3];
            r.f[2] = s.f[0] - s.f[1];
            r.f[3] = s.f[2] - s.f[3];
            d = r;
        });
        break;
    case Mnemonic::HSUBPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.df[0] = d.df[0] - d.df[1];
            r.df[1] = s.df[0] - s.df[1];
            d = r;
        });
        break;
    case Mnemonic::ADDSUBPS:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            d.f[0] -= s.f[0]; d.f[1] += s.f[1]; d.f[2] -= s.f[2]; d.f[3] += s.f[3];
        });
        break;
    case Mnemonic::ADDSUBPD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            d.df[0] -= s.df[0]; d.df[1] += s.df[1];
        });
        break;
    case Mnemonic::DPPS: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_bin([imm](XMMRegister& d, const XMMRegister& s, int) {
            float sum = 0.0f;
            for (int i = 0; i < 4; ++i)
                if (imm & (1u << (i + 4))) sum += d.f[i] * s.f[i];
            for (int i = 0; i < 4; ++i)
                d.f[i] = (imm & (1u << i)) ? sum : 0.0f;
        });
        break;
    }
    case Mnemonic::DPPD: {
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_bin([imm](XMMRegister& d, const XMMRegister& s, int) {
            double sum = 0.0;
            for (int i = 0; i < 2; ++i)
                if (imm & (1u << (i + 4))) sum += d.df[i] * s.df[i];
            for (int i = 0; i < 2; ++i)
                d.df[i] = (imm & (1u << i)) ? sum : 0.0;
        });
        break;
    }
    case Mnemonic::PUNPCKHBW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            for (int i = 0; i < 8; ++i) { r.b[2*i] = d.b[i+8]; r.b[2*i+1] = s.b[i+8]; }
            d = r;
        });
        break;
    case Mnemonic::PUNPCKHWD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            for (int i = 0; i < 4; ++i) { r.w[2*i] = d.w[i+4]; r.w[2*i+1] = s.w[i+4]; }
            d = r;
        });
        break;
    case Mnemonic::PUNPCKHDQ:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            for (int i = 0; i < 2; ++i) { r.d[2*i] = d.d[i+2]; r.d[2*i+1] = s.d[i+2]; }
            d = r;
        });
        break;
    case Mnemonic::PUNPCKHQDQ:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.q[0] = d.q[1]; r.q[1] = s.q[1];
            d = r;
        });
        break;
    case Mnemonic::PCMPGTB:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 16; ++i)
                d.b[i] = (static_cast<int8_t>(d.b[i]) > static_cast<int8_t>(s.b[i])) ? 0xFF : 0;
        });
        break;
    case Mnemonic::PCMPGTW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 8; ++i)
                d.w[i] = (static_cast<int16_t>(d.w[i]) > static_cast<int16_t>(s.w[i])) ? 0xFFFF : 0;
        });
        break;
    case Mnemonic::PCMPGTD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i)
                d.d[i] = (static_cast<int32_t>(d.d[i]) > static_cast<int32_t>(s.d[i])) ? 0xFFFFFFFFu : 0;
        });
        break;
    case Mnemonic::PSRLW: {
        uint8_t c = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_un([c](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 8; ++i) d.w[i] = (c >= 16) ? 0 : static_cast<uint16_t>(s.w[i] >> c);
        });
        break;
    }
    case Mnemonic::PSRAW: {
        uint8_t c = static_cast<uint8_t>(insn.src2.imm);
        int sh = (c >= 16) ? 15 : c;
        exec_packed_un([sh](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 8; ++i) d.w[i] = static_cast<uint16_t>(static_cast<int16_t>(s.w[i]) >> sh);
        });
        break;
    }
    case Mnemonic::PSLLW: {
        uint8_t c = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_un([c](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 8; ++i) d.w[i] = (c >= 16) ? 0 : static_cast<uint16_t>(s.w[i] << c);
        });
        break;
    }
    case Mnemonic::PSRLD: {
        uint8_t c = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_un([c](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 4; ++i) d.d[i] = (c >= 32) ? 0 : (s.d[i] >> c);
        });
        break;
    }
    case Mnemonic::PSRAD: {
        uint8_t c = static_cast<uint8_t>(insn.src2.imm);
        int sh = (c >= 32) ? 31 : c;
        exec_packed_un([sh](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 4; ++i) d.d[i] = static_cast<uint32_t>(static_cast<int32_t>(s.d[i]) >> sh);
        });
        break;
    }
    case Mnemonic::PSLLD: {
        uint8_t c = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_un([c](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 4; ++i) d.d[i] = (c >= 32) ? 0 : (s.d[i] << c);
        });
        break;
    }
    case Mnemonic::PSRLQ: {
        uint8_t c = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_un([c](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 2; ++i) d.q[i] = (c >= 64) ? 0 : (s.q[i] >> c);
        });
        break;
    }
    case Mnemonic::PSLLQ: {
        uint8_t c = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_un([c](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 2; ++i) d.q[i] = (c >= 64) ? 0 : (s.q[i] << c);
        });
        break;
    }
    case Mnemonic::PSRLDQ: {
        uint8_t c = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_un([c](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 16; ++i) d.b[i] = (i + c < 16) ? s.b[i + c] : 0;
        });
        break;
    }
    case Mnemonic::PSLLDQ: {
        uint8_t c = static_cast<uint8_t>(insn.src2.imm);
        exec_packed_un([c](XMMRegister& d, const XMMRegister& s) {
            for (int i = 0; i < 16; ++i) d.b[i] = (i >= c) ? s.b[i - c] : 0;
        });
        break;
    }

    case Mnemonic::FMA3: {
        uint8_t op = static_cast<uint8_t>(insn.src2.imm);
        uint8_t lo = op & 0x0F;
        uint8_t order = (op >> 4) & 3; // 1=132 (0x9x), 2=213 (0xAx), 3=231 (0xBx)
        bool is_dbl = insn.prefixes.vex_w;
        bool scalar = (lo >= 8) && ((lo & 1) != 0);
        bool is_256 = !scalar && (insn.prefixes.vex_len == 1);
        const int dst_r = insn.dst.reg & 15;
        const int v_r   = insn.prefixes.vex_vvvv & 15;

        auto fma_eval = [lo, order](auto a, auto b, auto c, int idx) {
            using T = decltype(a);
            T m1, m2, add;
            if      (order == 1) { m1 = a; m2 = c; add = b; } // 132
            else if (order == 2) { m1 = b; m2 = a; add = c; } // 213
            else                 { m1 = b; m2 = c; add = a; } // 231
            switch (lo) {
                case 6: return std::fma(m1, m2, (idx & 1) ? add : -add); // FMADDSUB
                case 7: return std::fma(m1, m2, (idx & 1) ? -add : add); // FMSUBADD
                case 8: case 9:  return std::fma( m1, m2,  add); // FMADD
                case 10: case 11: return std::fma( m1, m2, -add); // FMSUB
                case 12: case 13: return std::fma(-m1, m2,  add); // FNMADD
                case 14: case 15: return std::fma(-m1, m2, -add); // FNMSUB
                default: return T(0);
            }
        };

        if (scalar) {
            regs_.ymm[16].lo = regs_.ymm[dst_r].lo;
            if (is_dbl) {
                double c = read_f64(insn.src);
                regs_.ymm[16].lo.df[0] = fma_eval(regs_.ymm[dst_r].lo.df[0], regs_.ymm[v_r].lo.df[0], c, 0);
            } else {
                float c = read_f32(insn.src);
                regs_.ymm[16].lo.f[0] = fma_eval(regs_.ymm[dst_r].lo.f[0], regs_.ymm[v_r].lo.f[0], c, 0);
            }
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            regs_.ymm[dst_r].hi = {};
        } else {
            auto do_lane = [&](XMMRegister& out, const XMMRegister& a, const XMMRegister& b, const XMMRegister& c) {
                if (is_dbl) {
                    for (int i = 0; i < 2; ++i) out.df[i] = fma_eval(a.df[i], b.df[i], c.df[i], i);
                } else {
                    for (int i = 0; i < 4; ++i) out.f[i]  = fma_eval(a.f[i],  b.f[i],  c.f[i],  i);
                }
            };
            const XMMRegister c_lo = xsrc(insn.src);
            do_lane(regs_.ymm[16].lo, regs_.ymm[dst_r].lo, regs_.ymm[v_r].lo, c_lo);
            if (is_256) {
                const XMMRegister c_hi = xsrc_hi(insn.src);
                do_lane(regs_.ymm[16].hi, regs_.ymm[dst_r].hi, regs_.ymm[v_r].hi, c_hi);
                regs_.ymm[dst_r] = regs_.ymm[16];
            } else {
                regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
                regs_.ymm[dst_r].hi = {};
            }
        }
        break;
    }

    // ── SSE2 / SSE4.1 / AVX2 packed integer extensions ───────────────────────
    case Mnemonic::PACKSSWB:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            auto sat = [](int16_t v) -> uint8_t { return static_cast<uint8_t>(v < -128 ? -128 : v > 127 ? 127 : v); };
            XMMRegister r{};
            for (int i = 0; i < 8; ++i) r.b[i]     = sat(static_cast<int16_t>(d.w[i]));
            for (int i = 0; i < 8; ++i) r.b[i + 8] = sat(static_cast<int16_t>(s.w[i]));
            d = r;
        });
        break;
    case Mnemonic::PACKUSWB:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            auto sat = [](int16_t v) -> uint8_t { return static_cast<uint8_t>(v < 0 ? 0 : v > 255 ? 255 : v); };
            XMMRegister r{};
            for (int i = 0; i < 8; ++i) r.b[i]     = sat(static_cast<int16_t>(d.w[i]));
            for (int i = 0; i < 8; ++i) r.b[i + 8] = sat(static_cast<int16_t>(s.w[i]));
            d = r;
        });
        break;
    case Mnemonic::PACKSSDW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            auto sat = [](int32_t v) -> uint16_t { return static_cast<uint16_t>(v < -32768 ? -32768 : v > 32767 ? 32767 : v); };
            XMMRegister r{};
            for (int i = 0; i < 4; ++i) r.w[i]     = sat(static_cast<int32_t>(d.d[i]));
            for (int i = 0; i < 4; ++i) r.w[i + 4] = sat(static_cast<int32_t>(s.d[i]));
            d = r;
        });
        break;
    case Mnemonic::PACKUSDW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            auto sat = [](int32_t v) -> uint16_t { return static_cast<uint16_t>(v < 0 ? 0 : v > 65535 ? 65535 : v); };
            XMMRegister r{};
            for (int i = 0; i < 4; ++i) r.w[i]     = sat(static_cast<int32_t>(d.d[i]));
            for (int i = 0; i < 4; ++i) r.w[i + 4] = sat(static_cast<int32_t>(s.d[i]));
            d = r;
        });
        break;

    case Mnemonic::PMULLW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 8; ++i) d.w[i] = static_cast<uint16_t>(static_cast<int16_t>(d.w[i]) * static_cast<int16_t>(s.w[i]));
        });
        break;
    case Mnemonic::PMULHUW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 8; ++i) d.w[i] = static_cast<uint16_t>((static_cast<uint32_t>(d.w[i]) * s.w[i]) >> 16);
        });
        break;
    case Mnemonic::PMULHW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 8; ++i) d.w[i] = static_cast<uint16_t>((static_cast<int32_t>(static_cast<int16_t>(d.w[i])) * static_cast<int16_t>(s.w[i])) >> 16);
        });
        break;
    case Mnemonic::PMULUDQ:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            d.q[0] = static_cast<uint64_t>(d.d[0]) * s.d[0];
            d.q[1] = static_cast<uint64_t>(d.d[2]) * s.d[2];
        });
        break;
    case Mnemonic::PMULLD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i) d.d[i] *= s.d[i];
        });
        break;
    case Mnemonic::PMADDWD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            for (int i = 0; i < 4; ++i) {
                int32_t p0 = static_cast<int32_t>(static_cast<int16_t>(d.w[2*i]))   * static_cast<int16_t>(s.w[2*i]);
                int32_t p1 = static_cast<int32_t>(static_cast<int16_t>(d.w[2*i+1])) * static_cast<int16_t>(s.w[2*i+1]);
                r.d[i] = static_cast<uint32_t>(p0 + p1);
            }
            d = r;
        });
        break;

    case Mnemonic::PMINUB: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<16;++i) if (s.b[i]<d.b[i]) d.b[i]=s.b[i]; }); break;
    case Mnemonic::PMAXUB: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<16;++i) if (s.b[i]>d.b[i]) d.b[i]=s.b[i]; }); break;
    case Mnemonic::PMINSW: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<8;++i)  if ((int16_t)s.w[i]<(int16_t)d.w[i]) d.w[i]=s.w[i]; }); break;
    case Mnemonic::PMAXSW: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<8;++i)  if ((int16_t)s.w[i]>(int16_t)d.w[i]) d.w[i]=s.w[i]; }); break;
    case Mnemonic::PMINSB: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<16;++i) if ((int8_t)s.b[i]<(int8_t)d.b[i]) d.b[i]=s.b[i]; }); break;
    case Mnemonic::PMAXSB: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<16;++i) if ((int8_t)s.b[i]>(int8_t)d.b[i]) d.b[i]=s.b[i]; }); break;
    case Mnemonic::PMINUW: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<8;++i)  if (s.w[i]<d.w[i]) d.w[i]=s.w[i]; }); break;
    case Mnemonic::PMAXUW: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<8;++i)  if (s.w[i]>d.w[i]) d.w[i]=s.w[i]; }); break;
    case Mnemonic::PMINSD: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<4;++i)  if ((int32_t)s.d[i]<(int32_t)d.d[i]) d.d[i]=s.d[i]; }); break;
    case Mnemonic::PMAXSD: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<4;++i)  if ((int32_t)s.d[i]>(int32_t)d.d[i]) d.d[i]=s.d[i]; }); break;
    case Mnemonic::PMINUD: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<4;++i)  if (s.d[i]<d.d[i]) d.d[i]=s.d[i]; }); break;
    case Mnemonic::PMAXUD: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<4;++i)  if (s.d[i]>d.d[i]) d.d[i]=s.d[i]; }); break;

    case Mnemonic::PAVGB: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<16;++i) d.b[i]=static_cast<uint8_t>((d.b[i]+s.b[i]+1)>>1); }); break;
    case Mnemonic::PAVGW: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<8;++i)  d.w[i]=static_cast<uint16_t>((static_cast<uint32_t>(d.w[i])+s.w[i]+1)>>1); }); break;
    case Mnemonic::PSADBW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            uint64_t s0 = 0, s1 = 0;
            for (int i = 0; i < 8; ++i) s0 += static_cast<uint64_t>(d.b[i] > s.b[i] ? d.b[i] - s.b[i] : s.b[i] - d.b[i]);
            for (int i = 8; i < 16; ++i) s1 += static_cast<uint64_t>(d.b[i] > s.b[i] ? d.b[i] - s.b[i] : s.b[i] - d.b[i]);
            d.q[0] = s0; d.q[1] = s1;
        });
        break;

    case Mnemonic::PADDUSB: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<16;++i) { int v=d.b[i]+s.b[i]; d.b[i]=v>255?255:v; } }); break;
    case Mnemonic::PADDUSW: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<8;++i)  { int v=d.w[i]+s.w[i]; d.w[i]=v>65535?65535:v; } }); break;
    case Mnemonic::PSUBUSB: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<16;++i) d.b[i]=d.b[i]>s.b[i]?d.b[i]-s.b[i]:0; }); break;
    case Mnemonic::PSUBUSW: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<8;++i)  d.w[i]=d.w[i]>s.w[i]?d.w[i]-s.w[i]:0; }); break;
    case Mnemonic::PADDSB:  exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<16;++i) { int v=(int8_t)d.b[i]+(int8_t)s.b[i]; d.b[i]=static_cast<uint8_t>(v<-128?-128:v>127?127:v); } }); break;
    case Mnemonic::PADDSW:  exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<8;++i)  { int v=(int16_t)d.w[i]+(int16_t)s.w[i]; d.w[i]=static_cast<uint16_t>(v<-32768?-32768:v>32767?32767:v); } }); break;
    case Mnemonic::PSUBSB:  exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<16;++i) { int v=(int8_t)d.b[i]-(int8_t)s.b[i]; d.b[i]=static_cast<uint8_t>(v<-128?-128:v>127?127:v); } }); break;
    case Mnemonic::PSUBSW:  exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<8;++i)  { int v=(int16_t)d.w[i]-(int16_t)s.w[i]; d.w[i]=static_cast<uint16_t>(v<-32768?-32768:v>32767?32767:v); } }); break;

    case Mnemonic::PCMPEQQ: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<2;++i) d.q[i]=(d.q[i]==s.q[i])?~0ULL:0ULL; }); break;
    case Mnemonic::PCMPGTQ: exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) { for (int i=0;i<2;++i) d.q[i]=((int64_t)d.q[i]>(int64_t)s.q[i])?~0ULL:0ULL; }); break;

    case Mnemonic::PABSB: exec_packed_un([](XMMRegister& d, const XMMRegister& s) { for (int i=0;i<16;++i) { int8_t v=s.b[i]; d.b[i]=static_cast<uint8_t>(v<0?-v:v); } }); break;
    case Mnemonic::PABSW: exec_packed_un([](XMMRegister& d, const XMMRegister& s) { for (int i=0;i<8;++i)  { int16_t v=s.w[i]; d.w[i]=static_cast<uint16_t>(v<0?-v:v); } }); break;
    case Mnemonic::PABSD: exec_packed_un([](XMMRegister& d, const XMMRegister& s) { for (int i=0;i<4;++i)  { int32_t v=s.d[i]; d.d[i]=static_cast<uint32_t>(v<0?-static_cast<uint32_t>(v):v); } }); break;

    case Mnemonic::PMOVSXBW: case Mnemonic::PMOVSXBD: case Mnemonic::PMOVSXBQ:
    case Mnemonic::PMOVSXWD: case Mnemonic::PMOVSXWQ: case Mnemonic::PMOVSXDQ:
    case Mnemonic::PMOVZXBW: case Mnemonic::PMOVZXBD: case Mnemonic::PMOVZXBQ:
    case Mnemonic::PMOVZXWD: case Mnemonic::PMOVZXWQ: case Mnemonic::PMOVZXDQ: {
        const bool is_vex = insn.prefixes.vex;
        const bool is_256 = is_vex && insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        XMMRegister s{};
        if (insn.src.type == OperandType::Reg) {
            s = regs_.ymm[insn.src.reg & 15].lo;
        } else {
            uint64_t a = eff_addr(insn.src);
            int n = insn.src.size;
            if (n >= 8) { s.q[0] = mem_read_(a, 8); if (n >= 16) s.q[1] = mem_read_(a + 8, 8); }
            else        { s.q[0] = mem_read_(a, n); }
        }
        YMMRegister out{};
        int lanes = is_256 ? 2 : 1;
        for (int l = 0; l < lanes; ++l) {
            XMMRegister& d = l ? out.hi : out.lo;
            switch (insn.mnemonic) {
                case Mnemonic::PMOVSXBW: for (int i=0;i<8;++i) d.w[i]=static_cast<uint16_t>(static_cast<int16_t>(static_cast<int8_t>(s.b[l*8+i]))); break;
                case Mnemonic::PMOVSXBD: for (int i=0;i<4;++i) d.d[i]=static_cast<uint32_t>(static_cast<int32_t>(static_cast<int8_t>(s.b[l*4+i]))); break;
                case Mnemonic::PMOVSXBQ: for (int i=0;i<2;++i) d.q[i]=static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(s.b[l*2+i]))); break;
                case Mnemonic::PMOVSXWD: for (int i=0;i<4;++i) d.d[i]=static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(s.w[l*4+i]))); break;
                case Mnemonic::PMOVSXWQ: for (int i=0;i<2;++i) d.q[i]=static_cast<uint64_t>(static_cast<int64_t>(static_cast<int16_t>(s.w[l*2+i]))); break;
                case Mnemonic::PMOVSXDQ: for (int i=0;i<2;++i) d.q[i]=static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(s.d[l*2+i]))); break;
                case Mnemonic::PMOVZXBW: for (int i=0;i<8;++i) d.w[i]=s.b[l*8+i]; break;
                case Mnemonic::PMOVZXBD: for (int i=0;i<4;++i) d.d[i]=s.b[l*4+i]; break;
                case Mnemonic::PMOVZXBQ: for (int i=0;i<2;++i) d.q[i]=s.b[l*2+i]; break;
                case Mnemonic::PMOVZXWD: for (int i=0;i<4;++i) d.d[i]=s.w[l*4+i]; break;
                case Mnemonic::PMOVZXWQ: for (int i=0;i<2;++i) d.q[i]=s.w[l*2+i]; break;
                case Mnemonic::PMOVZXDQ: for (int i=0;i<2;++i) d.q[i]=s.d[l*2+i]; break;
                default: break;
            }
        }
        if (is_256) regs_.ymm[dst_r] = out;
        else { regs_.ymm[dst_r].lo = out.lo; if (is_vex) regs_.ymm[dst_r].hi = {}; }
        break;
    }

    case Mnemonic::PSRLW_R: case Mnemonic::PSRLD_R: case Mnemonic::PSRLQ_R:
    case Mnemonic::PSRAW_R: case Mnemonic::PSRAD_R:
    case Mnemonic::PSLLW_R: case Mnemonic::PSLLD_R: case Mnemonic::PSLLQ_R: {
        const bool is_vex = insn.prefixes.vex;
        const bool is_256 = is_vex && insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        const int  src1_r = is_vex ? (insn.prefixes.vex_vvvv & 15) : dst_r;
        uint64_t cnt = xsrc(insn.src).q[0];
        auto do_shift = [&](XMMRegister& d) {
            switch (insn.mnemonic) {
                case Mnemonic::PSRLW_R: for (int i=0;i<8;++i) d.w[i]=(cnt>=16)?0:static_cast<uint16_t>(d.w[i]>>cnt); break;
                case Mnemonic::PSRLD_R: for (int i=0;i<4;++i) d.d[i]=(cnt>=32)?0:(d.d[i]>>cnt); break;
                case Mnemonic::PSRLQ_R: for (int i=0;i<2;++i) d.q[i]=(cnt>=64)?0:(d.q[i]>>cnt); break;
                case Mnemonic::PSRAW_R: { int sh=(cnt>=16)?15:(int)cnt; for (int i=0;i<8;++i) d.w[i]=static_cast<uint16_t>(static_cast<int16_t>(d.w[i])>>sh); break; }
                case Mnemonic::PSRAD_R: { int sh=(cnt>=32)?31:(int)cnt; for (int i=0;i<4;++i) d.d[i]=static_cast<uint32_t>(static_cast<int32_t>(d.d[i])>>sh); break; }
                case Mnemonic::PSLLW_R: for (int i=0;i<8;++i) d.w[i]=(cnt>=16)?0:static_cast<uint16_t>(d.w[i]<<cnt); break;
                case Mnemonic::PSLLD_R: for (int i=0;i<4;++i) d.d[i]=(cnt>=32)?0:(d.d[i]<<cnt); break;
                case Mnemonic::PSLLQ_R: for (int i=0;i<2;++i) d.q[i]=(cnt>=64)?0:(d.q[i]<<cnt); break;
                default: break;
            }
        };
        regs_.ymm[16].lo = regs_.ymm[src1_r].lo;
        do_shift(regs_.ymm[16].lo);
        if (is_256) {
            regs_.ymm[16].hi = regs_.ymm[src1_r].hi;
            do_shift(regs_.ymm[16].hi);
            regs_.ymm[dst_r] = regs_.ymm[16];
        } else {
            regs_.ymm[dst_r].lo = regs_.ymm[16].lo;
            if (is_vex) regs_.ymm[dst_r].hi = {};
        }
        break;
    }

    // ── SSSE3 / AVX2 0F 38 additions ─────────────────────────────────────────
    case Mnemonic::PSIGNB:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 16; ++i) {
                int8_t sv = static_cast<int8_t>(s.b[i]);
                int8_t dv = static_cast<int8_t>(d.b[i]);
                d.b[i] = (sv < 0) ? static_cast<uint8_t>(-dv) : (sv == 0) ? 0 : d.b[i];
            }
        });
        break;
    case Mnemonic::PSIGNW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 8; ++i) {
                int16_t sv = static_cast<int16_t>(s.w[i]);
                int16_t dv = static_cast<int16_t>(d.w[i]);
                d.w[i] = (sv < 0) ? static_cast<uint16_t>(-dv) : (sv == 0) ? 0 : d.w[i];
            }
        });
        break;
    case Mnemonic::PSIGND:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i) {
                int32_t sv = static_cast<int32_t>(s.d[i]);
                d.d[i] = (sv < 0) ? static_cast<uint32_t>(-d.d[i]) : (sv == 0) ? 0 : d.d[i];
            }
        });
        break;
    case Mnemonic::PHADDW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            for (int i = 0; i < 4; ++i) r.w[i]     = static_cast<uint16_t>(d.w[2*i] + d.w[2*i+1]);
            for (int i = 0; i < 4; ++i) r.w[i + 4] = static_cast<uint16_t>(s.w[2*i] + s.w[2*i+1]);
            d = r;
        });
        break;
    case Mnemonic::PHADDD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.d[0] = d.d[0] + d.d[1]; r.d[1] = d.d[2] + d.d[3];
            r.d[2] = s.d[0] + s.d[1]; r.d[3] = s.d[2] + s.d[3];
            d = r;
        });
        break;
    case Mnemonic::PHSUBW:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            for (int i = 0; i < 4; ++i) r.w[i]     = static_cast<uint16_t>(d.w[2*i] - d.w[2*i+1]);
            for (int i = 0; i < 4; ++i) r.w[i + 4] = static_cast<uint16_t>(s.w[2*i] - s.w[2*i+1]);
            d = r;
        });
        break;
    case Mnemonic::PHSUBD:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            XMMRegister r{};
            r.d[0] = d.d[0] - d.d[1]; r.d[1] = d.d[2] - d.d[3];
            r.d[2] = s.d[0] - s.d[1]; r.d[3] = s.d[2] - s.d[3];
            d = r;
        });
        break;
    case Mnemonic::VTESTPS:
    case Mnemonic::VTESTPD: {
        const bool is_256 = insn.prefixes.vex_len == 1;
        const bool is_pd  = (insn.mnemonic == Mnemonic::VTESTPD);
        const int  dst_r  = insn.dst.reg & 15;
        auto check_lane = [is_pd](const XMMRegister& a, const XMMRegister& b, uint64_t& and_nz, uint64_t& andn_nz) {
            if (is_pd) {
                for (int i = 0; i < 2; ++i) {
                    uint64_t ma = a.q[i] >> 63, mb = b.q[i] >> 63;
                    and_nz |= (ma & mb); andn_nz |= ((~ma & 1) & mb);
                }
            } else {
                for (int i = 0; i < 4; ++i) {
                    uint32_t ma = a.d[i] >> 31, mb = b.d[i] >> 31;
                    and_nz |= (ma & mb); andn_nz |= ((~ma & 1) & mb);
                }
            }
        };
        uint64_t and_nz = 0, andn_nz = 0;
        check_lane(regs_.ymm[dst_r].lo, xsrc(insn.src), and_nz, andn_nz);
        if (is_256) check_lane(regs_.ymm[dst_r].hi, xsrc_hi(insn.src), and_nz, andn_nz);
        set_flag(regs_, 6, and_nz == 0);
        set_flag(regs_, 0, andn_nz == 0);
        set_flag(regs_, 2, false); set_flag(regs_, 4, false);
        set_flag(regs_, 7, false); set_flag(regs_, 11, false);
        break;
    }
    case Mnemonic::VPERMD: {
        const int dst_r = insn.dst.reg & 15;
        const int idx_r = insn.prefixes.vex_vvvv & 15;
        const XMMRegister s_lo = xsrc(insn.src), s_hi = xsrc_hi(insn.src);
        uint32_t elems[8] = { s_lo.d[0], s_lo.d[1], s_lo.d[2], s_lo.d[3],
                              s_hi.d[0], s_hi.d[1], s_hi.d[2], s_hi.d[3] };
        for (int i = 0; i < 4; ++i) {
            regs_.ymm[16].lo.d[i] = elems[regs_.ymm[idx_r].lo.d[i] & 7];
            regs_.ymm[16].hi.d[i] = elems[regs_.ymm[idx_r].hi.d[i] & 7];
        }
        regs_.ymm[dst_r] = regs_.ymm[16];
        break;
    }
    case Mnemonic::VPSRLV: {
        bool is_q = insn.prefixes.vex_w;
        exec_packed_bin([is_q](XMMRegister& d, const XMMRegister& s, int) {
            if (is_q) { for (int i=0;i<2;++i) d.q[i] = (s.q[i] >= 64) ? 0 : (d.q[i] >> s.q[i]); }
            else      { for (int i=0;i<4;++i) d.d[i] = (s.d[i] >= 32) ? 0 : (d.d[i] >> s.d[i]); }
        });
        break;
    }
    case Mnemonic::VPSRAV:
        exec_packed_bin([](XMMRegister& d, const XMMRegister& s, int) {
            for (int i = 0; i < 4; ++i) {
                int sh = (s.d[i] >= 32) ? 31 : static_cast<int>(s.d[i]);
                d.d[i] = static_cast<uint32_t>(static_cast<int32_t>(d.d[i]) >> sh);
            }
        });
        break;
    case Mnemonic::VPSLLV: {
        bool is_q = insn.prefixes.vex_w;
        exec_packed_bin([is_q](XMMRegister& d, const XMMRegister& s, int) {
            if (is_q) { for (int i=0;i<2;++i) d.q[i] = (s.q[i] >= 64) ? 0 : (d.q[i] << s.q[i]); }
            else      { for (int i=0;i<4;++i) d.d[i] = (s.d[i] >= 32) ? 0 : (d.d[i] << s.d[i]); }
        });
        break;
    }

    case Mnemonic::VMASKMOVD: {
        const bool is_256 = insn.prefixes.vex_len == 1;
        const int  mask_r = insn.prefixes.vex_vvvv & 15;
        if (insn.dst.type == OperandType::Reg) {
            const int dst_r = insn.dst.reg & 15;
            uint64_t a = eff_addr(insn.src);
            YMMRegister res{};
            for (int i = 0; i < 4; ++i)
                if (regs_.ymm[mask_r].lo.d[i] & 0x80000000u)
                    res.lo.d[i] = static_cast<uint32_t>(mem_read_(a + i * 4, 4));
            if (is_256) {
                for (int i = 0; i < 4; ++i)
                    if (regs_.ymm[mask_r].hi.d[i] & 0x80000000u)
                        res.hi.d[i] = static_cast<uint32_t>(mem_read_(a + 16 + i * 4, 4));
            }
            regs_.ymm[dst_r] = res;
        } else {
            const int src_r = insn.src.reg & 15;
            uint64_t a = eff_addr(insn.dst);
            for (int i = 0; i < 4; ++i)
                if (regs_.ymm[mask_r].lo.d[i] & 0x80000000u)
                    mem_write_(a + i * 4, regs_.ymm[src_r].lo.d[i], 4);
            if (is_256) {
                for (int i = 0; i < 4; ++i)
                    if (regs_.ymm[mask_r].hi.d[i] & 0x80000000u)
                        mem_write_(a + 16 + i * 4, regs_.ymm[src_r].hi.d[i], 4);
            }
        }
        break;
    }

    case Mnemonic::VMASKMOVQ: {
        const bool is_256 = insn.prefixes.vex_len == 1;
        const int  mask_r = insn.prefixes.vex_vvvv & 15;
        if (insn.dst.type == OperandType::Reg) {
            const int dst_r = insn.dst.reg & 15;
            uint64_t a = eff_addr(insn.src);
            YMMRegister res{};
            for (int i = 0; i < 2; ++i)
                if (regs_.ymm[mask_r].lo.q[i] >> 63)
                    res.lo.q[i] = mem_read_(a + i * 8, 8);
            if (is_256) {
                for (int i = 0; i < 2; ++i)
                    if (regs_.ymm[mask_r].hi.q[i] >> 63)
                        res.hi.q[i] = mem_read_(a + 16 + i * 8, 8);
            }
            regs_.ymm[dst_r] = res;
        } else {
            const int src_r = insn.src.reg & 15;
            uint64_t a = eff_addr(insn.dst);
            for (int i = 0; i < 2; ++i)
                if (regs_.ymm[mask_r].lo.q[i] >> 63)
                    mem_write_(a + i * 8, regs_.ymm[src_r].lo.q[i], 8);
            if (is_256) {
                for (int i = 0; i < 2; ++i)
                    if (regs_.ymm[mask_r].hi.q[i] >> 63)
                        mem_write_(a + 16 + i * 8, regs_.ymm[src_r].hi.q[i], 8);
            }
        }
        break;
    }

    case Mnemonic::VCVTPS2PH: {
        const bool is_256 = insn.prefixes.vex_len == 1;
        const int  src_r  = insn.src.reg & 15;
        uint8_t imm = static_cast<uint8_t>(insn.src2.imm);
        XMMRegister res{};
        for (int i = 0; i < 4; ++i) res.w[i] = f32_to_f16(regs_.ymm[src_r].lo.f[i], imm);
        if (is_256) {
            for (int i = 0; i < 4; ++i) res.w[i + 4] = f32_to_f16(regs_.ymm[src_r].hi.f[i], imm);
        }
        if (insn.dst.type == OperandType::Reg) {
            const int dst_r = insn.dst.reg & 15;
            regs_.ymm[dst_r].lo = res;
            regs_.ymm[dst_r].hi = {};
        } else {
            uint64_t a = eff_addr(insn.dst);
            mem_write_(a, res.q[0], 8);
            if (is_256) mem_write_(a + 8, res.q[1], 8);
        }
        break;
    }

    case Mnemonic::VCVTPH2PS: {
        const bool is_256 = insn.prefixes.vex_len == 1;
        const int  dst_r  = insn.dst.reg & 15;
        XMMRegister s{};
        if (insn.src.type == OperandType::Reg) {
            s = regs_.ymm[insn.src.reg & 15].lo;
        } else {
            uint64_t a = eff_addr(insn.src);
            s.q[0] = mem_read_(a, 8);
            if (is_256) s.q[1] = mem_read_(a + 8, 8);
        }
        YMMRegister res{};
        for (int i = 0; i < 4; ++i) res.lo.f[i] = f16_to_f32(s.w[i]);
        if (is_256) {
            for (int i = 0; i < 4; ++i) res.hi.f[i] = f16_to_f32(s.w[i + 4]);
        }
        regs_.ymm[dst_r] = res;
        break;
    }

    case Mnemonic::PCMPESTRM: case Mnemonic::PCMPESTRI:
    case Mnemonic::PCMPISTRM: case Mnemonic::PCMPISTRI: {
        const bool is_explicit = (insn.mnemonic == Mnemonic::PCMPESTRM || insn.mnemonic == Mnemonic::PCMPESTRI);
        const bool is_mask     = (insn.mnemonic == Mnemonic::PCMPESTRM || insn.mnemonic == Mnemonic::PCMPISTRM);
        const XMMRegister a = regs_.ymm[insn.dst.reg & 15].lo;
        const XMMRegister b = xsrc(insn.src);
        const uint8_t imm   = static_cast<uint8_t>(insn.src2.imm);
        const bool is_word  = (imm & 1) != 0;
        const bool is_sign  = (imm & 2) != 0;
        const int  agg      = (imm >> 2) & 3;
        const int  pol      = (imm >> 4) & 3;
        const bool out_sel  = (imm & 0x40) != 0;
        const int  N        = is_word ? 8 : 16;

        auto get_elem = [&](const XMMRegister& r, int idx) -> int32_t {
            if (is_word) return is_sign ? static_cast<int32_t>(static_cast<int16_t>(r.w[idx]))
                                        : static_cast<int32_t>(r.w[idx]);
            return is_sign ? static_cast<int32_t>(static_cast<int8_t>(r.b[idx]))
                           : static_cast<int32_t>(r.b[idx]);
        };

        int len_a = N, len_b = N;
        if (is_explicit) {
            auto clamp_len = [&](uint64_t regv) -> int {
                int64_t sv = insn.prefixes.rex_w ? static_cast<int64_t>(regv)
                                                 : static_cast<int64_t>(static_cast<int32_t>(regv));
                if (sv < 0) sv = -sv;
                return (sv > N) ? N : static_cast<int>(sv);
            };
            len_a = clamp_len(regs_.rax);
            len_b = clamp_len(regs_.rdx);
        } else {
            for (int i = 0; i < N; ++i) { if (get_elem(a, i) == 0) { len_a = i; break; } }
            for (int i = 0; i < N; ++i) { if (get_elem(b, i) == 0) { len_b = i; break; } }
        }

        uint32_t intRes1 = 0;
        if (agg == 0) { // Equal Any
            for (int j = 0; j < len_b; ++j) {
                int32_t bv = get_elem(b, j);
                for (int i = 0; i < len_a; ++i) {
                    if (get_elem(a, i) == bv) { intRes1 |= (1u << j); break; }
                }
            }
        } else if (agg == 1) { // Ranges
            for (int j = 0; j < len_b; ++j) {
                int32_t bv = get_elem(b, j);
                for (int i = 0; i + 1 < len_a; i += 2) {
                    if (bv >= get_elem(a, i) && bv <= get_elem(a, i + 1)) {
                        intRes1 |= (1u << j); break;
                    }
                }
            }
        } else if (agg == 2) { // Equal Each
            for (int j = 0; j < N; ++j) {
                bool va = (j < len_a), vb = (j < len_b);
                bool eq = (!va && !vb) || (va && vb && get_elem(a, j) == get_elem(b, j));
                if (eq) intRes1 |= (1u << j);
            }
        } else { // Equal Ordered (substring)
            for (int j = 0; j < N; ++j) {
                bool match = true;
                for (int i = 0; i < N && (i + j) < N; ++i) {
                    bool va = (i < len_a), vb = ((i + j) < len_b);
                    if (!va) break;
                    if (!vb || get_elem(a, i) != get_elem(b, i + j)) { match = false; break; }
                }
                if (match) intRes1 |= (1u << j);
            }
        }

        uint32_t all_mask = (1u << N) - 1u;
        uint32_t intRes2 = intRes1;
        if (pol == 1) {
            intRes2 = (~intRes1) & all_mask;
        } else if (pol == 3) {
            uint32_t b_valid_mask = (len_b >= N) ? all_mask : ((1u << len_b) - 1u);
            intRes2 = (intRes1 ^ b_valid_mask) & all_mask;
        }

        if (is_mask) {
            XMMRegister out{};
            if (!out_sel) {
                out.d[0] = intRes2;
            } else if (is_word) {
                for (int i = 0; i < 8; ++i) out.w[i] = (intRes2 & (1u << i)) ? 0xFFFFu : 0u;
            } else {
                for (int i = 0; i < 16; ++i) out.b[i] = (intRes2 & (1u << i)) ? 0xFFu : 0u;
            }
            regs_.ymm[0].lo = out;
            if (insn.prefixes.vex) regs_.ymm[0].hi = {};
        } else {
            uint32_t idx = static_cast<uint32_t>(N);
            if (intRes2 != 0) {
                idx = out_sel ? static_cast<uint32_t>(31 - __builtin_clz(intRes2))
                              : static_cast<uint32_t>(__builtin_ctz(intRes2));
            }
            write_gpr(regs_, 1, 4, idx); // ECX (zero-extended to RCX)
        }

        set_flag(regs_, 0,  intRes2 != 0);       // CF
        set_flag(regs_, 6,  len_b < N);          // ZF
        set_flag(regs_, 7,  len_a < N);          // SF
        set_flag(regs_, 11, (intRes2 & 1u) != 0);// OF
        set_flag(regs_, 4,  false);              // AF
        set_flag(regs_, 2,  false);              // PF
        break;
    }

    default:
        fault_ = 2; fault_rip_ = insn_rip_; fault_mn_ = static_cast<int>(insn.mnemonic);
        halted_ = true;
        break;
    }
}

} // namespace emu::cpu
