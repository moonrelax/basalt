#pragma once
#include <cstdint>
#include <optional>

namespace emu::cpu {

// ── Prefix flags ─────────────────────────────────────────────────────────────
struct PrefixSet {
    bool lock   = false;
    bool repne  = false; // F2
    bool rep    = false; // F3
    bool seg_cs = false;
    bool seg_ss = false;
    bool seg_ds = false;
    bool seg_es = false;
    bool seg_fs = false;
    bool seg_gs = false;
    bool op66   = false; // operand-size override (66h)
    bool ad67   = false; // address-size override (67h)

    // REX byte (40–4F)
    bool rex    = false;
    bool rex_w  = false; // 64-bit operand
    bool rex_r  = false; // extends ModRM.reg
    bool rex_x  = false; // extends SIB.index
    bool rex_b  = false; // extends ModRM.rm / SIB.base / opcode reg

    // VEX/EVEX (decoded separately)
    bool vex    = false;
    bool evex   = false;
    uint8_t vex_vvvv = 0;
    uint8_t vex_pp   = 0; // implied legacy prefix
    uint8_t vex_map  = 0; // implied escape
    uint8_t vex_len  = 0; // 0=128, 1=256, 2=512
    bool    vex_w    = false;
};

// ── ModRM / SIB ───────────────────────────────────────────────────────────────
struct ModRM {
    uint8_t mod;  // 2 bits
    uint8_t reg;  // 3 bits (+ REX.R)
    uint8_t rm;   // 3 bits (+ REX.B)
};

struct SIB {
    uint8_t scale; // 2 bits
    uint8_t index; // 3 bits (+ REX.X)
    uint8_t base;  // 3 bits (+ REX.B)
};

// ── Decoded operand ───────────────────────────────────────────────────────────
enum class OperandType : uint8_t {
    None,
    Reg,       // register index
    Mem,       // effective address
    Imm,       // immediate value
    Rel,       // RIP-relative (branches)
    Moffs,     // absolute memory offset (MOV AL,[addr])
};

struct Operand {
    OperandType type = OperandType::None;
    int         size = 0; // bytes: 1/2/4/8/16/32

    // Reg
    uint8_t  reg = 0;

    // Mem: seg:[base + index*scale + disp]
    int      base  = -1; // -1 = none
    int      index = -1;
    uint8_t  scale = 1;
    int64_t  disp  = 0;
    bool     rip_rel = false;

    // Imm / Rel / Moffs
    int64_t  imm = 0;
};

// ── Instruction ───────────────────────────────────────────────────────────────
enum class Mnemonic : uint16_t {
    INVALID = 0,
    // Data movement
    MOV, MOVSX, MOVSXD, MOVZX, MOVBE,
    PUSH, POP, PUSHA, POPA, PUSHF, POPF,
    LEA, XCHG, XADD, CMPXCHG, CMPXCHG8B, CMPXCHG16B,
    BSWAP,
    // ALU
    ADD, ADC, ADCX, ADOX, SUB, SBB, AND, OR, XOR, NOT, NEG,
    INC, DEC, MUL, IMUL, DIV, IDIV,
    CMP, TEST,
    // Shifts/rotates
    SHL, SHR, SAL, SAR, ROL, ROR, RCL, RCR,
    SHLD, SHRD,
    // Bit manipulation
    BT, BTS, BTR, BTC, BSF, BSR, LZCNT, TZCNT, POPCNT,
    // Control flow
    JMP, JMP_FAR,
    JO, JNO, JB, JNB, JZ, JNZ, JBE, JA,
    JS, JNS, JP, JNP, JL, JGE, JLE, JG,
    JCXZ, JECXZ, JRCXZ,
    CALL, CALL_FAR, RET, RETF, IRET, IRETQ,
    LOOP, LOOPE, LOOPNE,
    // String ops
    MOVS, CMPS, SCAS, LODS, STOS,
    // Stack/flags
    NOP, HLT, PAUSE,
    CLI, STI, CLC, STC, CMC, CLD, STD,
    CLTS, CLAC, STAC,
    // System
    SYSCALL, SYSRET, SYSENTER, SYSEXIT,
    INT, INT3, INTO,
    CPUID, RDTSC, RDTSCP, RDMSR, WRMSR,
    LGDT, SGDT, LIDT, SIDT, LLDT, SLDT, LTR, STR,
    LMSW, SMSW, INVLPG, INVPCID,
    WBINVD, CLFLUSH, CLFLUSHOPT,
    MOV_CR, MOV_DR, MOV_SR,
    SWAPGS, XGETBV, XSETBV,
    // Conditional moves
    CMOVO, CMOVNO, CMOVB, CMOVNB, CMOVZ, CMOVNZ,
    CMOVBE, CMOVA, CMOVS, CMOVNS, CMOVP, CMOVNP,
    CMOVL, CMOVGE, CMOVLE, CMOVG,
    // Set byte
    SETO, SETNO, SETB, SETNB, SETZ, SETNZ,
    SETBE, SETA, SETS, SETNS, SETP, SETNP,
    SETL, SETGE, SETLE, SETG,
    // SSE/AVX (subset used by game engines)
    MOVAPS, MOVUPS, MOVAPD, MOVUPD,
    MOVSS, MOVSD,
    ADDPS, SUBPS, MULPS, DIVPS,
    ADDSS, SUBSS, MULSS, DIVSS,
    ADDPD, SUBPD, MULPD, DIVPD,
    ADDSD, SUBSD, MULSD, DIVSD,
    MAXPS, MINPS, MAXSS, MINSS,
    CMPPS, CMPSS, COMISS, UCOMISS,
    SQRTPS, SQRTSS, RSQRTPS, RSQRTSS,
    ANDPS, ORPS, XORPS, ANDNPS,
    SHUFPS, UNPCKLPS, UNPCKHPS,
    MOVHLPS, MOVLHPS,
    CVTSI2SS, CVTSI2SD, CVTSS2SI, CVTSD2SI,
    CVTSS2SD, CVTSD2SS,
    MOVDQA, MOVDQU, MOVQ,
    PXOR, PAND, POR, PANDN,
    PADDB, PADDW, PADDD, PADDQ,
    PSUBB, PSUBW, PSUBD, PSUBQ,
    PCMPEQB, PCMPEQW, PCMPEQD,
    PSHUFD, PSHUFB, PSHUFLW, PSHUFHW,
    PMOVMSKB,
    // AVX
    VMOVAPS, VMOVUPS, VMOVDQA, VMOVDQU,
    VADDPS, VSUBPS, VMULPS, VDIVPS,
    VPXOR, VPAND, VPOR,
    // Misc
    FENCE, MFENCE, SFENCE, LFENCE,
    PREFETCHT0, PREFETCHT1, PREFETCHT2, PREFETCHNTA,
    UD2,
    MOVD, PUNPCKLBW, PUNPCKLWD, PUNPCKLDQ, PUNPCKLQDQ,
    // SSE/AVX additions
    MOVLPS, MOVHPS, MOVLPD, MOVHPD, MOVSLDUP, MOVSHDUP, MOVDDUP,
    UNPCKLPD, UNPCKHPD,
    CVTTSS2SI, CVTTSD2SI,
    COMISD, UCOMISD,
    MOVMSKPS, MOVMSKPD,
    SQRTPD, SQRTSD,
    RCPPS, RCPSS,
    ANDPD, ANDNPD, ORPD, XORPD,
    CVTPS2PD, CVTPD2PS, CVTDQ2PS, CVTPS2DQ, CVTTPS2DQ,
    MINPD, MINSD, MAXPD, MAXSD,
    CMPPD, CMPSD,
    SHUFPD,
    VZEROUPPER, VZEROALL,
    CVTDQ2PD, CVTTPD2DQ, CVTPD2DQ,
    CDQE, CQO,
    // BMI1 / BMI2
    ANDN, BLSR, BLSMSK, BLSI, BZHI, BEXTR,
    SHLX, SARX, SHRX, RORX, MULX, PEXT, PDEP,
    // SSE4.1 / AVX / AVX2 (0F 38 / 0F 3A)
    PEXTRB, PEXTRW, PEXTRD, PEXTRQ,
    PINSRB, PINSRW, PINSRD, PINSRQ, INSERTPS,
    VBROADCASTSS, VBROADCASTSD, VBROADCASTF128, VPBROADCASTB, VPBROADCASTW,
    PTEST, PALIGNR,
    BLENDPS, BLENDPD, PBLENDW, VBLENDVPS, VBLENDVPD, VPBLENDVB,
    ROUNDPS, ROUNDPD, ROUNDSS, ROUNDSD,
    VPERMQ, VPERMILPS, VPERMILPD, VPERM2F128,
    VINSERTF128, VEXTRACTF128,
    // SSE3 / SSE2 / SSE4.1 horizontal, dot-product, unpack-high, cmpgt, shifts
    HADDPS, HADDPD, HSUBPS, HSUBPD, ADDSUBPS, ADDSUBPD,
    DPPS, DPPD,
    PUNPCKHBW, PUNPCKHWD, PUNPCKHDQ, PUNPCKHQDQ,
    PCMPGTB, PCMPGTW, PCMPGTD,
    PSRLW, PSRAW, PSLLW, PSRLD, PSRAD, PSLLD, PSRLQ, PSRLDQ, PSLLQ, PSLLDQ,
    FMA3,
    // SSE2 / SSE4.1 / AVX2 packed integer extensions
    PACKSSWB, PACKUSWB, PACKSSDW, PACKUSDW,
    PMULLW, PMULHUW, PMULHW, PMULUDQ, PMULLD, PMADDWD,
    PMINUB, PMAXUB, PMINSW, PMAXSW,
    PMINSB, PMINSD, PMINUW, PMINUD, PMAXSB, PMAXSD, PMAXUW, PMAXUD,
    PAVGB, PAVGW, PSADBW,
    PADDUSB, PADDUSW, PSUBUSB, PSUBUSW, PADDSB, PADDSW, PSUBSB, PSUBSW,
    PCMPEQQ, PCMPGTQ,
    PABSB, PABSW, PABSD,
    PMOVSXBW, PMOVSXBD, PMOVSXBQ, PMOVSXWD, PMOVSXWQ, PMOVSXDQ,
    PMOVZXBW, PMOVZXBD, PMOVZXBQ, PMOVZXWD, PMOVZXWQ, PMOVZXDQ,
    PSRLW_R, PSRLD_R, PSRLQ_R, PSRAW_R, PSRAD_R, PSLLW_R, PSLLD_R, PSLLQ_R,
    // SSSE3 / AVX2 0F 38 additions
    PSIGNB, PSIGNW, PSIGND,
    PHADDW, PHADDD, PHSUBW, PHSUBD,
    VTESTPS, VTESTPD, VPERMD,
    VPSRLV, VPSRAV, VPSLLV,
    VMASKMOVD, VMASKMOVQ,
    VCVTPS2PH, VCVTPH2PS,
    PCMPESTRM, PCMPESTRI, PCMPISTRM, PCMPISTRI,
    STMXCSR, LDMXCSR,
};

struct DecodedInsn {
    Mnemonic mnemonic  = Mnemonic::INVALID;
    PrefixSet prefixes;
    Operand   dst;
    Operand   src;
    Operand   src2;    // for 3-operand forms (IMUL, SHLD, etc.)
    uint8_t   length   = 0; // total bytes consumed
    int       op_size  = 8; // default operand size in bytes (long mode: 4 or 8)
    int       addr_size = 8;

    bool valid() const { return mnemonic != Mnemonic::INVALID; }
};

// ── Decoder ───────────────────────────────────────────────────────────────────
class Decoder {
public:
    // Decode one instruction from raw bytes at `ip`.
    // `max_len` is the number of readable bytes (up to 15).
    static DecodedInsn decode(const uint8_t* ip, int max_len = 15);

private:
    struct Ctx {
        const uint8_t* base;
        int            pos;
        int            max;
        PrefixSet      pfx;
        int            op_size;
        int            addr_size;

        uint8_t  read8()  { return (pos < max) ? base[pos++] : 0; }
        uint16_t read16() { uint16_t v; v = base[pos]|(base[pos+1]<<8); pos+=2; return v; }
        uint32_t read32() { uint32_t v=0; for(int i=0;i<4;i++) v|=(uint32_t)base[pos+i]<<(i*8); pos+=4; return v; }
        uint64_t read64() { uint64_t v=0; for(int i=0;i<8;i++) v|=(uint64_t)base[pos+i]<<(i*8); pos+=8; return v; }
        int8_t   reads8()  { return (int8_t)read8(); }
        int32_t  reads32() { return (int32_t)read32(); }
    };

    static void     decode_prefixes(Ctx& c);
    static void     decode_vex2(Ctx& c);
    static void     decode_vex3(Ctx& c);
    static void     decode_evex(Ctx& c);
    static ModRM    read_modrm(Ctx& c);
    static SIB      read_sib(Ctx& c);
    static Operand  decode_modrm_mem(Ctx& c, ModRM m, int op_size);
    static Operand  make_reg(uint8_t idx, int size);
    static Operand  make_imm(int64_t val, int size);
    static Operand  make_rel(int64_t rel, int size);

    static DecodedInsn decode_one_byte  (Ctx& c);
    static DecodedInsn decode_two_byte  (Ctx& c); // 0F xx
    static DecodedInsn decode_three_byte(Ctx& c, uint8_t map); // 0F 38/3A
    static DecodedInsn decode_vex_insn  (Ctx& c);
};

} // namespace emu::cpu
