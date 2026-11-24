#include "hal/timer.h"

namespace emu::hal {

HPET::HPET() {
    // General Capabilities: rev ID=1, num_timers-1=2, counter_size=1 (64-bit),
    // legacy_replacement=1, vendor_id=0x8086, period in femtoseconds
    general_cap_id_ = (PERIOD_FEMTOS << 32) |
                      (0x8086ULL << 16) |
                      (1ULL << 15) |  // legacy replacement capable
                      (1ULL << 13) |  // counter size 64-bit
                      ((NUM_TIMERS - 1) << 8) |
                      1;              // rev ID
    general_config_ = 0;
    main_counter_   = 0;

    for (auto& t : timers_) {
        t.config_cap  = (1ULL << 4); // capable of periodic
        t.comparator  = ~0ULL;
        t.fsb_route   = 0;
    }
}

uint64_t HPET::read(uint64_t offset) {
    if (offset == 0x000) return general_cap_id_;
    if (offset == 0x010) return general_config_;
    if (offset == 0x020) return 0; // general interrupt status
    if (offset == 0x0F0) return main_counter_;

    // Timer N registers: base 0x100 + N*0x20
    for (int n = 0; n < NUM_TIMERS; n++) {
        uint64_t base = 0x100 + n * 0x20;
        if (offset == base + 0x00) return timers_[n].config_cap;
        if (offset == base + 0x08) return timers_[n].comparator;
        if (offset == base + 0x10) return timers_[n].fsb_route;
    }
    return 0;
}

void HPET::write(uint64_t offset, uint64_t val) {
    if (offset == 0x010) { general_config_ = val; return; }
    if (offset == 0x020) return; // ack interrupt status
    if (offset == 0x0F0) { main_counter_ = val; return; }

    for (int n = 0; n < NUM_TIMERS; n++) {
        uint64_t base = 0x100 + n * 0x20;
        if (offset == base + 0x00) { timers_[n].config_cap = val;  return; }
        if (offset == base + 0x08) { timers_[n].comparator  = val; check_timers(); return; }
        if (offset == base + 0x10) { timers_[n].fsb_route   = val; return; }
    }
}

void HPET::tick(uint64_t ns) {
    if (!(general_config_ & 1)) return; // main counter not enabled
    // Convert ns to counter ticks: ticks = ns * 1e6 / PERIOD_FEMTOS
    main_counter_ += (ns * 1000000ULL) / PERIOD_FEMTOS;
    check_timers();
}

void HPET::check_timers() {
    for (int n = 0; n < NUM_TIMERS; n++) {
        if (!(timers_[n].config_cap & (1 << 2))) continue; // timer not enabled
        if (main_counter_ >= timers_[n].comparator) {
            irq_pending_ = true;
            // periodic: advance comparator
            if (timers_[n].config_cap & (1 << 3)) {
                uint64_t period = timers_[n].fsb_route;
                if (period) timers_[n].comparator += period;
            }
        }
    }
}

} // namespace emu::hal
