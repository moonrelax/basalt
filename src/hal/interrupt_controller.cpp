#include "hal/interrupt_controller.h"
#include <cstring>

namespace emu::hal {

LAPIC::LAPIC(uint8_t cpu_id) : cpu_id_(cpu_id) {
    regs_.fill(0);
    // Default LAPIC state after RESET
    regs_[LAPIC_VER   / 4] = 0x01050014; // version 0x14, max LVT 5
    regs_[LAPIC_SVR   / 4] = 0x000000FF; // spurious vector 0xFF, APIC disabled
    regs_[LAPIC_DFR   / 4] = 0xFFFFFFFF; // flat model
    regs_[LAPIC_ID    / 4] = cpu_id << 24;
}

uint32_t LAPIC::read(uint32_t offset) const {
    uint32_t idx = (offset & 0x3FF) / 4;
    if (idx >= regs_.size()) return 0;

    // IRR and ISR are 256-bit bitfields spread over 8 dword registers
    if (offset >= LAPIC_IRR0 && offset < LAPIC_IRR0 + 32) {
        uint32_t bit_start = ((offset - LAPIC_IRR0) / 4) * 32;
        uint32_t val = 0;
        for (int b = 0; b < 32; ++b)
            if (irr_.test(bit_start + b)) val |= (1u << b);
        return val;
    }
    if (offset >= LAPIC_ISR0 && offset < LAPIC_ISR0 + 32) {
        uint32_t bit_start = ((offset - LAPIC_ISR0) / 4) * 32;
        uint32_t val = 0;
        for (int b = 0; b < 32; ++b)
            if (isr_.test(bit_start + b)) val |= (1u << b);
        return val;
    }

    if (offset == LAPIC_TIMER_CCR)
        return static_cast<uint32_t>(timer_counter_);

    return regs_[idx];
}

void LAPIC::write(uint32_t offset, uint32_t val) {
    uint32_t idx = (offset & 0x3FF) / 4;
    if (idx >= regs_.size()) return;

    switch (offset) {
        case LAPIC_EOI:
            // Find highest ISR bit and clear it
            for (int i = 255; i >= 0; --i) {
                if (isr_.test(i)) { isr_.reset(i); break; }
            }
            return;
        case LAPIC_TIMER_ICR:
            timer_counter_ = val;
            regs_[idx] = val;
            return;
        default:
            regs_[idx] = val;
            break;
    }
}

bool LAPIC::pending_irq(uint8_t& out_vector) const {
    uint32_t svr = regs_[LAPIC_SVR / 4];
    if (!(svr & (1 << 8))) return false; // APIC disabled

    uint32_t ppr = regs_[LAPIC_PPR / 4] & 0xF0;

    for (int i = 255; i >= 16; --i) {
        if (irr_.test(i)) {
            uint32_t priority = i & 0xF0;
            if (priority > ppr) {
                out_vector = static_cast<uint8_t>(i);
                return true;
            }
        }
    }
    return false;
}

void LAPIC::signal_eoi() {
    for (int i = 255; i >= 0; --i) {
        if (isr_.test(i)) { isr_.reset(i); return; }
    }
}

void LAPIC::tick(uint64_t cycles) {
    if (timer_counter_ == 0) return;

    uint32_t lvt  = regs_[LAPIC_TIMER_LVT / 4];
    uint32_t dcr  = regs_[LAPIC_TIMER_DCR / 4];
    uint32_t divs = 1u << ((dcr & 0xB) == 0xB ? 0 : (dcr & 0xB) + 1); // divide config

    uint64_t dec = cycles / divs;
    if (dec >= timer_counter_) {
        uint8_t vector = lvt & 0xFF;
        bool    masked = !!(lvt & (1 << 16));
        bool    periodic = ((lvt >> 17) & 0x3) == 1;

        if (!masked) {
            irr_.set(vector);
            if (irq_handler_) irq_handler_(vector);
        }

        if (periodic)
            timer_counter_ = regs_[LAPIC_TIMER_ICR / 4]; // reload
        else
            timer_counter_ = 0;
    } else {
        timer_counter_ -= dec;
    }
}

} // namespace emu::hal
