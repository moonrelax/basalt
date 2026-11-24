#pragma once
#include <cstdint>
#include <functional>
#include <bitset>

namespace emu::hal {

// Xbox Series S uses a GIC-like interrupt fabric exposed through ACPI
// plus the standard x86 LAPIC per core and I/O APIC for platform IRQs.

constexpr uint32_t LAPIC_BASE_DEFAULT = 0xFEE00000;
constexpr uint32_t IOAPIC_BASE        = 0xFEC00000;

// Local APIC register offsets (from LAPIC_BASE)
constexpr uint32_t LAPIC_ID       = 0x020;
constexpr uint32_t LAPIC_VER      = 0x030;
constexpr uint32_t LAPIC_TPR      = 0x080; // Task Priority
constexpr uint32_t LAPIC_APR      = 0x090; // Arbitration Priority
constexpr uint32_t LAPIC_PPR      = 0x0A0; // Processor Priority
constexpr uint32_t LAPIC_EOI      = 0x0B0; // End of Interrupt
constexpr uint32_t LAPIC_LDR      = 0x0D0; // Logical Destination
constexpr uint32_t LAPIC_DFR      = 0x0E0; // Destination Format
constexpr uint32_t LAPIC_SVR      = 0x0F0; // Spurious Interrupt Vector
constexpr uint32_t LAPIC_ISR0     = 0x100; // In-Service Register (8×32)
constexpr uint32_t LAPIC_IRR0     = 0x200; // Interrupt Request Register (8×32)
constexpr uint32_t LAPIC_TMR0     = 0x180; // Trigger Mode Register
constexpr uint32_t LAPIC_ICR_LO   = 0x300; // IPI Command Register low
constexpr uint32_t LAPIC_ICR_HI   = 0x310;
constexpr uint32_t LAPIC_TIMER_LVT = 0x320;
constexpr uint32_t LAPIC_TIMER_ICR = 0x380;
constexpr uint32_t LAPIC_TIMER_CCR = 0x390; // Current Count
constexpr uint32_t LAPIC_TIMER_DCR = 0x3E0; // Divide Config

using IRQHandler = std::function<void(uint8_t vector)>;

class LAPIC {
public:
    explicit LAPIC(uint8_t cpu_id);

    uint32_t read (uint32_t offset) const;
    void     write(uint32_t offset, uint32_t val);

    // Returns true if an interrupt should be injected into CPU
    bool  pending_irq(uint8_t& out_vector) const;
    void  signal_eoi();

    void tick(uint64_t cycles); // advance APIC timer

    void set_irq_handler(IRQHandler fn) { irq_handler_ = std::move(fn); }

private:
    uint8_t cpu_id_;
    std::array<uint32_t, 0x400 / 4> regs_{};
    IRQHandler irq_handler_;

    std::bitset<256> irr_; // interrupt request
    std::bitset<256> isr_; // in-service
    uint64_t timer_counter_ = 0;
};

} // namespace emu::hal
