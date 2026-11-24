#include "kernel/scheduler.h"
#include "cpu/mnemonic_names.h"
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <vector>


static uint64_t g_rip_ring[32];
static unsigned g_rip_ring_i = 0;

// debug: BASALT_PROBE=rva,rva,... (hex, relative to exe base 0x140000000)
static std::vector<uint64_t> probe_list() {
    std::vector<uint64_t> v;
    if (const char* e = std::getenv("BASALT_PROBE")) {
        char* p = const_cast<char*>(e);
        while (*p) { v.push_back(0x140000000ULL + std::strtoull(p, &p, 16)); if (*p) ++p; }
    }
    return v;
}
static const std::vector<uint64_t> g_probes = probe_list();
// SIGTERM (e.g. from `timeout`) stops the scheduler cleanly so the summary shows where threads spin
static volatile std::sig_atomic_t g_stop = 0;

namespace emu::kernel {

namespace {
const char* state_name(ThreadState st) {
    switch (st) {
        case ThreadState::Ready:     return "ready";
        case ThreadState::Waiting:   return "waiting";
        case ThreadState::Suspended: return "suspended";
        case ThreadState::Finished:  return "finished";
        case ThreadState::Faulted:   return "faulted";
    }
    return "unknown";
}
} // namespace

Scheduler::Scheduler(memory::MemoryMap& mem, cpu::CPU& cpu, DllRunner& runner)
    : mem_(mem), cpu_(cpu), runner_(runner) {}

void Scheduler::add_main_thread(uint64_t entry,
                                uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4) {
    GuestThread t{};
    t.tid        = 8;
    t.handle     = ~1ULL;
    t.entry      = entry;
    t.param      = a1;
    t.stack_top  = DllRunner::kMainStackTop;
    t.stack_size = DllRunner::kMainStackSize;
    t.teb_va     = DllRunner::kMainTeb;
    t.state      = ThreadState::Ready;
    t.name       = "main";

    t.regs             = cpu::Registers{};
    t.regs.rsp         = (t.stack_top & ~0xFULL) - 0x40 - 8;
    t.regs.rip         = entry;
    t.regs.rcx         = a1;
    t.regs.rdx         = a2;
    t.regs.r8          = a3;
    t.regs.r9          = a4;
    t.regs.rflags      = 0x202;
    t.regs.msr_gs_base = t.teb_va;

    mem_.write64(t.regs.rsp, DllRunner::kSentinel);
    threads_.push_back(std::move(t));

    std::fprintf(stderr, "  [sched] added main thread tid=8 entry=0x%llx (%s) stack_top=0x%llx\n",
                 static_cast<unsigned long long>(entry),
                 runner_.where(entry).c_str(),
                 static_cast<unsigned long long>(DllRunner::kMainStackTop));
}

void Scheduler::add_worker_thread(const PendingThread& pt) {
    uint64_t ssz  = pt.stack_size ? pt.stack_size : DllRunner::kMainStackSize;
    uint64_t stop = runner_.alloc_stack(ssz);
    uint64_t teb  = runner_.alloc_teb(stop, ssz, pt.tid);

    GuestThread t{};
    t.tid        = pt.tid;
    t.handle     = pt.handle;
    t.entry      = pt.entry;
    t.param      = pt.param;
    t.stack_top  = stop;
    t.stack_size = ssz;
    t.teb_va     = teb;
    t.state      = pt.suspended ? ThreadState::Suspended : ThreadState::Ready;
    t.name       = "thread-" + std::to_string(pt.tid);

    t.regs             = cpu::Registers{};
    t.regs.rsp         = (t.stack_top & ~0xFULL) - 0x40 - 8;
    t.regs.rip         = pt.entry;
    t.regs.rcx         = pt.param;
    t.regs.rflags      = 0x202;
    t.regs.msr_gs_base = teb;

    mem_.write64(t.regs.rsp, DllRunner::kSentinel);
    threads_.push_back(std::move(t));

    std::fprintf(stderr, "  [sched] spawned %s tid=%u handle=0x%llx entry=0x%llx (%s) param=0x%llx stack_top=0x%llx%s\n",
                 threads_.back().name.c_str(), pt.tid,
                 static_cast<unsigned long long>(pt.handle),
                 static_cast<unsigned long long>(pt.entry),
                 runner_.where(pt.entry).c_str(),
                 static_cast<unsigned long long>(pt.param),
                 static_cast<unsigned long long>(stop),
                 pt.suspended ? " [suspended]" : "");
}

void Scheduler::ingest_pending() {
    auto created = runner_.take_pending_threads();
    for (const auto& pt : created) {
        add_worker_thread(pt);
    }

    auto resumed = runner_.take_resumed_threads();
    for (uint64_t h : resumed) {
        for (auto& t : threads_) {
            if (t.handle == h && t.state == ThreadState::Suspended) {
                t.state = ThreadState::Ready;
                std::fprintf(stderr, "  [sched] resumed %s tid=%u\n", t.name.c_str(), t.tid);
            }
        }
    }
}

void Scheduler::wake_waiting_threads() {
    for (auto& t : threads_) {
        if (t.state != ThreadState::Waiting) continue;
        if (t.wait_handles.empty()) {
            t.regs.rax = 0;
            t.state = ThreadState::Ready;
            continue;
        }
        if (t.wait_all) {
            bool all_sig = true;
            for (uint64_t h : t.wait_handles) {
                if (!runner_.is_event_signaled(h)) {
                    all_sig = false;
                    break;
                }
            }
            if (all_sig) {
                for (uint64_t h : t.wait_handles) runner_.try_acquire_event(h);
                t.wait_handles.clear();
                t.regs.rax = 0; // WAIT_OBJECT_0
                t.state = ThreadState::Ready;
            }
        } else {
            for (size_t i = 0; i < t.wait_handles.size(); ++i) {
                if (runner_.is_event_signaled(t.wait_handles[i])) {
                    runner_.try_acquire_event(t.wait_handles[i]);
                    t.wait_handles.clear();
                    t.regs.rax = static_cast<uint64_t>(i); // WAIT_OBJECT_0 + i
                    t.state = ThreadState::Ready;
                    break;
                }
            }
        }
    }
}

void Scheduler::report_thread_fault(const GuestThread& t) const {
    const auto& r = cpu_.regs();
    uint64_t rip = cpu_.fault() ? cpu_.fault_rip() : r.rip;
    std::fprintf(stderr, "  [sched] %s (tid=%u) STOP: %s at 0x%llx (%s)\n",
                 t.name.c_str(), t.tid, t.stop_reason.c_str(),
                 static_cast<unsigned long long>(rip), runner_.where(rip).c_str());
    if (cpu_.fault()) {
        std::fprintf(stderr, "     fault=%d (%s) mnemonic=%s\n",
                     cpu_.fault(),
                     cpu_.fault() == 1 ? "undecodable" : "unimplemented",
                     cpu::mnemonic_name(cpu_.fault_mnemonic()));
    }
    std::fprintf(stderr, "     bytes:");
    for (int i = 0; i < 16; ++i) std::fprintf(stderr, " %02x", mem_.read8(rip + i));
    std::fprintf(stderr, "\n     rax=%llx rcx=%llx rdx=%llx rsp=%llx r8=%llx r9=%llx\n",
                 static_cast<unsigned long long>(r.rax), static_cast<unsigned long long>(r.rcx),
                 static_cast<unsigned long long>(r.rdx), static_cast<unsigned long long>(r.rsp),
                 static_cast<unsigned long long>(r.r8),  static_cast<unsigned long long>(r.r9));
    std::fprintf(stderr, "     thread insns executed: %llu\n",
                 static_cast<unsigned long long>(t.insns));
}

void Scheduler::print_summary() const {
    std::fprintf(stderr, "\n  [sched] summary (%zu thread(s), %llu total insns):\n",
                 threads_.size(), static_cast<unsigned long long>(total_insns_));
    for (const auto& t : threads_) {
        std::string extra = t.stop_reason;
        if (t.state == ThreadState::Waiting && !t.wait_handles.empty()) {
            extra += "waiting(wait_all=" + std::to_string(t.wait_all ? 1 : 0) + ") on [";
            for (size_t i = 0; i < t.wait_handles.size(); ++i) {
                if (i) extra += ", ";
                extra += runner_.describe_handle(t.wait_handles[i]);
            }
            extra += "]";
        }
        extra += " rip=" + runner_.where(t.regs.rip);
        std::fprintf(stderr, "    tid=%-4u %-12s entry=0x%-12llx state=%-9s insns=%-10llu slices=%-6llu %s\n",
                     t.tid, t.name.c_str(),
                     static_cast<unsigned long long>(t.entry),
                     state_name(t.state),
                     static_cast<unsigned long long>(t.insns),
                     static_cast<unsigned long long>(t.slices),
                     extra.c_str());
    }
}

void Scheduler::run(uint64_t total_budget, uint64_t quantum) {
    if (quantum == 0) quantum = kDefaultQuantum;
    runner_.set_scheduler_mode(true);
    std::signal(SIGTERM, [](int) { g_stop = 1; });
    ingest_pending();

    size_t cur = threads_.empty() ? 0 : threads_.size() - 1;

    while (total_insns_ < total_budget && !g_stop) {
        ingest_pending();
        wake_waiting_threads();

        if (threads_.empty()) break;

        // Round-robin: find next Ready thread.
        size_t next = threads_.size();
        for (size_t offset = 1; offset <= threads_.size(); ++offset) {
            size_t idx = (cur + offset) % threads_.size();
            if (threads_[idx].state == ThreadState::Ready) {
                next = idx;
                break;
            }
        }

        if (next == threads_.size()) {
            bool any_waiting = false;
            for (const auto& t : threads_)
                if (t.state == ThreadState::Waiting) any_waiting = true;
            if (any_waiting) {
                std::fprintf(stderr, "  [sched] all remaining threads blocked on unsignaled events; stopping:\n");
                for (const auto& t : threads_) {
                    if (t.state != ThreadState::Waiting) continue;
                    std::fprintf(stderr, "    [deadlock-diag] %s (tid=%u, rip=%s) waiting(wait_all=%d) on:",
                                 t.name.c_str(), t.tid,
                                 runner_.where(t.regs.rip).c_str(),
                                 t.wait_all ? 1 : 0);
                    for (uint64_t h : t.wait_handles) {
                        std::fprintf(stderr, " %s", runner_.describe_handle(h).c_str());
                    }
                    std::fprintf(stderr, "\n");
                }
            }
            break;
        }

        cur = next;
        GuestThread& t = threads_[cur];

        // Context switch IN via cpu_.regs().
        cpu_.clear_fault();
        cpu_.regs() = t.regs;
        runner_.set_current_tid(t.tid);
        runner_.clear_abort();
        ++t.slices;

        uint64_t slice_insns = 0;
        while (slice_insns < quantum && total_insns_ < total_budget) {
            auto& r = cpu_.regs();

            if (r.rip == DllRunner::kSentinel) {
                t.state       = ThreadState::Finished;
                t.exit_code   = r.rax;
                t.stop_reason = "returned (rv=" + std::to_string(r.rax) + ")";
                std::fprintf(stderr, "  [sched] %s (tid=%u) finished rv=0x%llx after %llu insns\n",
                             t.name.c_str(), t.tid,
                             static_cast<unsigned long long>(r.rax),
                             static_cast<unsigned long long>(t.insns));
                break;
            }

            if (const Thunk* tk = runner_.loader().thunk_at(r.rip)) {
                uint64_t before = runner_.insn_count();
                runner_.handle_thunk(*tk);
                uint64_t delta = runner_.insn_count() - before;
                t.insns      += delta;
                total_insns_ += delta;
                slice_insns  += delta;

                if (runner_.aborted()) {
                    t.state       = ThreadState::Faulted;
                    t.stop_reason = "fault in thunk callback (" + tk->name + ")";
                    break;
                }

                // Pop return address from guest stack.
                r.rip = mem_.read64(r.rsp);
                r.rsp += 8;

                WaitRequest wr = runner_.take_wait_request();
                if (wr.active) {
                    t.state        = ThreadState::Waiting;
                    t.wait_all     = wr.wait_all;
                    t.wait_handles = std::move(wr.handles);
                    break;
                }

                if (runner_.take_yield_request()) {
                    break;
                }
                continue;
            }

            if (!runner_.in_image(r.rip)) {
                // dump the last rips executed so the jump source is visible
                for (unsigned k = 0; k < 32; ++k) {
                    uint64_t v = g_rip_ring[(g_rip_ring_i + k) & 31];
                    if (v) std::fprintf(stderr, "    [ring] %s\n", runner_.where(v).c_str());
                }
                t.state       = ThreadState::Faulted;
                t.stop_reason = "wild-jump";
                report_thread_fault(t);
                break;
            }


            if (runner_.trace_from() != 0 && r.rip == runner_.trace_from()) {
                runner_.set_trace_active(true);
            }
            if (runner_.trace_active() && runner_.consume_trace_step()) {
                std::fprintf(stderr, "    [trace] tid=%u insns=%llu rip=0x%llx (%s) rax=0x%llx rcx=0x%llx rdx=0x%llx\n",
                             t.tid,
                             static_cast<unsigned long long>(total_insns_),
                             static_cast<unsigned long long>(r.rip),
                             runner_.where(r.rip).c_str(),
                             static_cast<unsigned long long>(r.rax),
                             static_cast<unsigned long long>(r.rcx),
                             static_cast<unsigned long long>(r.rdx));
            }

            g_rip_ring[g_rip_ring_i++ & 31] = r.rip;
            if ((total_insns_ & 0xFFFFFFULL) == 0) {
                std::fprintf(stderr, "  [progress] insns=%llu rip=%s\n",
                             static_cast<unsigned long long>(total_insns_),
                             runner_.where(r.rip).c_str());
                std::fflush(stderr);
            }
            for (uint64_t pa : g_probes) if (pa == r.rip) {
                static uint32_t probe_hits = 0;
                if (++probe_hits > 400) break;
                char str[65]; int n = 0;
                for (; n < 64; ++n) { uint8_t c = mem_.read8(r.rcx + n); if (c < 0x20 || c > 0x7e) break; str[n] = char(c); }
                str[n] = 0;
                std::fprintf(stderr, "    [probe] tid=%u rva=0x%llx rax=0x%llx rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx [rcx+c04]=%d ret=0x%llx str(rcx)=\"%s\"\n",
                             t.tid, (unsigned long long)(r.rip - 0x140000000ULL), (unsigned long long)r.rax,
                             (unsigned long long)r.rcx, (unsigned long long)r.rdx, (unsigned long long)r.r8,
                             (unsigned long long)r.r9, (int)mem_.read32(r.rcx + 0xc04),
                             (unsigned long long)(mem_.read64(r.rsp) - 0x140000000ULL), str);
            }
            cpu_.step();
            ++slice_insns;
            ++t.insns;
            ++total_insns_;
            runner_.add_insn_count(1);

            if (cpu_.fault()) {
                t.state       = ThreadState::Faulted;
                t.stop_reason = "cpu-fault";
                report_thread_fault(t);
                break;
            }
            if (cpu_.halted()) {
                t.state       = ThreadState::Faulted;
                t.stop_reason = "cpu-halt";
                report_thread_fault(t);
                break;
            }
        }

        // Context switch OUT via cpu_.regs().
        t.regs = cpu_.regs();
    }

    if (total_insns_ >= total_budget) {
        std::fprintf(stderr, "  [sched] global instruction budget reached (%llu insns)\n",
                     static_cast<unsigned long long>(total_insns_));
        std::fprintf(stderr, "  [sched] last rips:");
        for (unsigned k = 0; k < 32; ++k) {
            uint64_t v = g_rip_ring[(g_rip_ring_i + k) & 31];
            if (v) std::fprintf(stderr, " %s", runner_.where(v).c_str());
        }
        std::fprintf(stderr, "\n");
    }

    runner_.set_scheduler_mode(false);
    print_summary();
}

} // namespace emu::kernel
