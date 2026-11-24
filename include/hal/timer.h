#pragma once
#include <cstdint>

namespace emu::hal {

// HPET — High Precision Event Timer
// MMIO base: 0xFED00000, 1 KB register block
class HPET {
public:
    static constexpr uint64_t MMIO_BASE = 0xFED00000ULL;
    static constexpr uint64_t MMIO_SIZE = 0x400;

    HPET();

    uint64_t read(uint64_t offset);
    void     write(uint64_t offset, uint64_t val);

    // Advance main counter by `ns` nanoseconds worth of ticks.
    void     tick(uint64_t ns);

    bool     pending_irq() const { return irq_pending_; }
    void     clear_irq()         { irq_pending_ = false; }

private:
    static constexpr uint64_t PERIOD_FEMTOS = 69841279; // ~14.318 MHz
    static constexpr int NUM_TIMERS = 3;

    uint64_t general_cap_id_;
    uint64_t general_config_;
    uint64_t main_counter_;

    struct Timer {
        uint64_t config_cap;
        uint64_t comparator;
        uint64_t fsb_route;
    } timers_[NUM_TIMERS];

    bool irq_pending_ = false;

    void check_timers();
};

} // namespace emu::hal
