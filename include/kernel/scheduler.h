#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "cpu/cpu.h"
#include "kernel/dll_runner.h"
#include "memory/memory_map.h"

namespace emu::kernel {

enum class ThreadState {
    Ready,
    Waiting,
    Suspended,
    Finished,
    Faulted,
};

struct GuestThread {
    uint32_t              tid        = 0;
    uint64_t              handle     = 0;
    uint64_t              entry      = 0;
    uint64_t              param      = 0;
    uint64_t              stack_top  = 0;
    uint64_t              stack_size = 0;
    uint64_t              teb_va     = 0;
    cpu::Registers        regs{};
    ThreadState           state      = ThreadState::Ready;
    bool                  wait_all   = false;
    uint64_t              wake_rax   = 0;
    uint64_t              sleep_until = 0; // guest QPC tick; 0 means not asleep
    std::vector<uint64_t> wait_handles;
    uint64_t              wait_since = 0; // QPC tick when entered Waiting
    uint64_t              insns      = 0;
    uint64_t              slices     = 0;
    // Address armed by MONITORX/MONITOR. MWAITX sleeps until this qword
    // changes or its timer runs out.
    uint64_t              watch_addr = 0;
    uint64_t              watch_seen = 0;
    uint64_t              exit_code  = 0;
    std::string           name;
    std::string           stop_reason;
};

// Cooperative round-robin scheduler over guest threads.
// Each guest thread owns a saved cpu::Registers context and its own stack/TEB.
// Context switches happen via cpu_.regs() without modifying emu::cpu::CPU.
class Scheduler {
public:
    static constexpr uint64_t kDefaultQuantum = 10'000ULL;
    static constexpr uint64_t kDefaultBudget  = 1'500'000'000ULL;

    Scheduler(memory::MemoryMap& mem, cpu::CPU& cpu, DllRunner& runner);

    // Register the primary executable thread (tid = 8, main stack & TEB).
    void add_main_thread(uint64_t entry,
                         uint64_t a1 = 0,
                         uint64_t a2 = 0,
                         uint64_t a3 = 0,
                         uint64_t a4 = 0);

    // Register a worker thread with its own allocated stack and TEB.
    void add_worker_thread(const PendingThread& pt);

    // Run round-robin until all threads finish/fault/block or total_budget is reached.
    void run(uint64_t total_budget = kDefaultBudget,
             uint64_t quantum      = kDefaultQuantum);

    const std::vector<GuestThread>& threads() const { return threads_; }
    uint64_t total_insns() const { return total_insns_; }

private:
    memory::MemoryMap&       mem_;
    cpu::CPU&                cpu_;
    DllRunner&               runner_;
    std::vector<GuestThread> threads_;
    uint64_t                 total_insns_ = 0;

    void ingest_pending();
    void wake_waiting_threads();
    void report_thread_fault(const GuestThread& t) const;
    // 0: rip is live. 1: resumed a null call. 2: thread faulted (rip stayed 0).
    int take_null_rip(GuestThread& t);
    // 0: not a wait opcode. 1: MONITOR/MONITORX, RIP advanced.
    // 2: MWAIT/MWAITX, thread parked in Waiting.
    int consume_wait_insn(GuestThread& t);
    void print_summary() const;
};

} // namespace emu::kernel
