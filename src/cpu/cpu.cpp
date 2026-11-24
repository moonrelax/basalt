#include "cpu/cpu.h"
#include <stdexcept>
#include <cstring>

namespace emu::cpu {

CPU::CPU() {
    reset();
}

void CPU::reset() {
    std::memset(&regs_, 0, sizeof(regs_));
    // Real mode defaults don't apply — Xbox boots directly into 64-bit long mode
    // via its hypervisor, so we start with sane long-mode CS descriptor.
    regs_.rflags = 0x0000000000000002; // Reserved bit 1 always set
    regs_.cr0    = 0x80050033;         // PE | MP | ET | NE | WP | PG (paging on)
    regs_.cr4    = 0x00000668;         // PAE | MCE | PGE | OSFXSR | OSXMMEXCPT
    regs_.msr_efer = 0x0D01;           // SCE | LME | LMA | NXE
    regs_.mxcsr = 0x1F80;              // default: all exceptions masked
    halted_ = false;
    pending_irq_ = 0xFF;
}

uint8_t CPU::fetch8() {
    uint8_t v = static_cast<uint8_t>(mem_read_(regs_.rip, 1));
    regs_.rip += 1;
    return v;
}

uint16_t CPU::fetch16() {
    uint16_t v = static_cast<uint16_t>(mem_read_(regs_.rip, 2));
    regs_.rip += 2;
    return v;
}

uint32_t CPU::fetch32() {
    uint32_t v = static_cast<uint32_t>(mem_read_(regs_.rip, 4));
    regs_.rip += 4;
    return v;
}

uint64_t CPU::fetch64() {
    uint64_t v = mem_read_(regs_.rip, 8);
    regs_.rip += 8;
    return v;
}

void CPU::raise_interrupt(uint8_t vector) {
    pending_irq_ = vector;
}

void CPU::assert_nmi() {
    nmi_pending_ = true;
}

void CPU::handle_interrupt(uint8_t vector) {
    // Minimal interrupt delivery: push RIP/CS/RFLAGS, jump to IDT handler.
    // Full IDT parsing and privilege transitions will be expanded here.
    (void)vector; // stub
}

void CPU::step() {
    if (halted_) {
        if (pending_irq_ != 0xFF && (regs_.rflags & (1 << 9))) {
            halted_ = false; // HLT woken by interrupt
        } else {
            return;
        }
    }

    if (nmi_pending_) {
        nmi_pending_ = false;
        handle_interrupt(2);
        return;
    }
    if (pending_irq_ != 0xFF && (regs_.rflags & (1 << 9))) {
        uint8_t vec = pending_irq_;
        pending_irq_ = 0xFF;
        handle_interrupt(vec);
        return;
    }

    uint8_t buf[15] = {};
    for (int i = 0; i < 15; ++i)
        buf[i] = static_cast<uint8_t>(mem_read_(regs_.rip + i, 1));
    DecodedInsn insn = Decoder::decode(buf, 15);
    if (!insn.valid()) {
        fault_ = 1; fault_rip_ = regs_.rip; halted_ = true;
        return;
    }
    seg_base_ = insn.prefixes.seg_gs ? regs_.msr_gs_base
              : insn.prefixes.seg_fs ? regs_.msr_fs_base : 0;
    insn_rip_ = regs_.rip;
    regs_.rip += insn.length;
    execute(insn);
}

void CPU::run(uint64_t cycles) {
    for (uint64_t i = 0; i < cycles && !halted_; ++i) {
        step();
    }
}

void CPU::dispatch(uint8_t /*opcode*/) {
    // superseded by execute(insn) path in step()
}

} // namespace emu::cpu
