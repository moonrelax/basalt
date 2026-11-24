#pragma once
#include <cstdint>
#include <array>
#include <functional>
#include "cpu/decoder.h"

namespace emu::cpu {

// Xbox Series S: AMD Zen 2, 8 cores @ 3.6 GHz (3.8 GHz boost), SMT disabled
// Same ISA as host (x86-64) — no recompilation needed, TCG-style dispatch used
// for cycle accuracy and memory intercept.

struct Flags {
    uint8_t cf : 1; // carry
    uint8_t pf : 1; // parity
    uint8_t af : 1; // auxiliary carry
    uint8_t zf : 1; // zero
    uint8_t sf : 1; // sign
    uint8_t tf : 1; // trap
    uint8_t if_ : 1; // interrupt enable
    uint8_t df : 1; // direction
    uint8_t of : 1; // overflow
    uint8_t iopl : 2;
    uint8_t nt : 1;
    uint8_t rf : 1;
    uint8_t vm : 1;
    uint8_t ac : 1; // alignment check
    uint8_t vif : 1;
    uint8_t vip : 1;
    uint8_t id : 1;
};

struct XMMRegister {
    union {
        uint8_t  b[16];
        uint16_t w[8];
        uint32_t d[4];
        uint64_t q[2];
        float    f[4];
        double   df[2];
    };
};

struct YMMRegister {
    XMMRegister lo;
    XMMRegister hi;
};

struct Registers {
    // GPRs
    uint64_t rax, rcx, rdx, rbx;
    uint64_t rsp, rbp, rsi, rdi;
    uint64_t r8,  r9,  r10, r11;
    uint64_t r12, r13, r14, r15;

    uint64_t rip;
    uint64_t rflags;

    // Segment registers (selectors)
    uint16_t cs, ds, es, fs, gs, ss;

    // Control registers
    uint64_t cr0, cr2, cr3, cr4, cr8;

    // MSRs (subset relevant to OS execution)
    uint64_t msr_efer;         // Extended Feature Enable Register
    uint64_t msr_star;         // SYSCALL target CS/SS
    uint64_t msr_lstar;        // SYSCALL target RIP (64-bit)
    uint64_t msr_cstar;        // SYSCALL target RIP (compat)
    uint64_t msr_sfmask;       // SYSCALL RFLAGS mask
    uint64_t msr_fs_base;
    uint64_t msr_gs_base;
    uint64_t msr_kernel_gs_base;

    // AVX-512 registers (Zen 2 supports AVX-512 on EPYC, but Xbox disables it)
    // Using YMM (AVX2 is present on Zen 2 consumer)
    std::array<YMMRegister, 32> ymm; // 0-15 architectural, 16+ emulator scratch

    // x87 FPU
    uint64_t fpu_st[8][2]; // 80-bit extended as two 64-bit halves
    uint16_t fpu_cw, fpu_sw, fpu_tw;
    uint32_t mxcsr;
};

using MemReadFn  = std::function<uint64_t(uint64_t addr, int size)>;
using MemWriteFn = std::function<void(uint64_t addr, uint64_t val, int size)>;

class CPU {
public:
    CPU();

    void reset();
    void step();              // execute one instruction
    void run(uint64_t cycles); // run N cycles

    void set_mem_read (MemReadFn  fn) { mem_read_  = std::move(fn); }
    void set_mem_write(MemWriteFn fn) { mem_write_ = std::move(fn); }

    void raise_interrupt(uint8_t vector);
    void assert_nmi();

    Registers&       regs()       { return regs_; }
    const Registers& regs() const { return regs_; }

    bool halted() const { return halted_; }

    // 0 = none, 1 = undecodable opcode, 2 = decoded but unimplemented mnemonic
    int      fault()     const { return fault_; }
    uint64_t fault_rip() const { return fault_rip_; }
    int      fault_mnemonic() const { return fault_mn_; }
    void     clear_fault() { fault_ = 0; halted_ = false; }

private:
    Registers regs_{};
    bool      halted_   = false;
    bool      nmi_pending_ = false;
    uint8_t   pending_irq_ = 0xFF; // 0xFF = none
    uint64_t  seg_base_  = 0;     // fs/gs override base for the current insn
    int       fault_     = 0;
    uint64_t  fault_rip_ = 0;
    int       fault_mn_  = 0;
    uint64_t  insn_rip_  = 0;

    MemReadFn  mem_read_;
    MemWriteFn mem_write_;

    uint8_t  fetch8();
    uint16_t fetch16();
    uint32_t fetch32();
    uint64_t fetch64();

    void dispatch(uint8_t opcode);
    void handle_interrupt(uint8_t vector);

    void     execute(const DecodedInsn& insn);
    uint64_t read_operand(const Operand& op);
    void     write_operand(const Operand& op, uint64_t val);
    uint64_t eff_addr(const Operand& op);
    XMMRegister xsrc(const Operand& op);   // xmm reg or 16-byte memory load
    XMMRegister xsrc_hi(const Operand& op); // ymm hi reg or 16-byte memory load at +16
    float       read_f32(const Operand& op);
    double      read_f64(const Operand& op);
    void        write_xmm_mem(uint64_t addr, const XMMRegister& v);
    void     push_val(uint64_t val, int sz);
    uint64_t pop_val(int sz);
};

} // namespace emu::cpu
