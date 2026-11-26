#include <map>
#include "kernel/scheduler.h"
#include "host/guest_window.h"
#include "cpu/mnemonic_names.h"
#include "cpu/native_run.h"
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <vector>
extern "C" uint64_t basalt_last_addr;


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

// The title's CRT lives behind jmp stubs in the exe. Running those on the host
// turns a multi-megabyte copy or a byte-by-byte search into one call.
static bool crt_fast(emu::memory::MemoryMap& mem, emu::cpu::Registers& r) {
    constexpr uint64_t kBase = 0x140000000ULL;
    uint64_t rva = r.rip - kBase;
    bool stub = rva >= 0x5f40540 && rva <= 0x5f407f0 && ((rva & 0xf) == 0);
    bool scan = rva == 0x4e4ccc0;
    // DirectStorage wait. EnqueueRequest already copied the bytes, but the
    // title spins while a status method stays 0. Once Submit has set the
    // flag at +0x78, the wait is over.
    if (rva == 0x4f65820) {
        if (mem.read8(r.rdx + 0x78) != 1) return false;
        r.rax = 1;
        r.rip = mem.read64(r.rsp);
        r.rsp += 8;
        return true;
    }
    if (!stub && !scan) return false;

    auto ret = [&](uint64_t rax) {
        r.rax = rax;
        r.rip = mem.read64(r.rsp);
        r.rsp += 8;
    };
    auto span = [&](uint64_t addr, uint64_t n) -> uint8_t* {
        if (n > (256ULL << 20)) return nullptr;
        return mem.raw_ptr(addr, n ? n : 1);
    };
    auto slen = [&](uint64_t addr) -> uint64_t {
        uint64_t n = 0;
        while (n < (16ULL << 20)) {
            uint8_t* p = span(addr + n, 4096);
            if (!p) return ~0ULL;
            for (uint32_t i = 0; i < 4096; ++i) {
                if (!p[i]) return n + i;
            }
            n += 4096;
        }
        return n;
    };

    if (scan) {
        uint64_t n = r.r8;
        if (n > (1ULL << 20)) return false;
        uint64_t hs = slen(r.rcx);
        uint64_t ns = slen(r.rdx);
        if (hs == ~0ULL || ns == ~0ULL) return false;
        uint8_t* h = span(r.rcx, hs + 1);
        uint8_t* nd = span(r.rdx, (n > ns ? n : ns) + 1);
        if (!h || !nd) return false;
        uint64_t found = 0;
        if (hs && n) {
            const char* p = reinterpret_cast<char*>(h);
            const char* end = p + hs;
            while (p < end) {
                const void* hit = std::memchr(p, nd[0], static_cast<size_t>(end - p));
                if (!hit) break;
                uint64_t i = static_cast<const uint8_t*>(hit) - h;
                if (std::strncmp(reinterpret_cast<char*>(h + i),
                                 reinterpret_cast<char*>(nd), n) == 0) {
                    found = r.rcx + i;
                    break;
                }
                if (!h[i + 1]) break;
                p = reinterpret_cast<const char*>(hit) + 1;
            }
        }
        ret(found);
        return true;
    }

    switch (rva) {
    case 0x5f40540: { // memchr
        uint8_t* p = span(r.rcx, r.r8);
        if (!p) return false;
        void* f = std::memchr(p, static_cast<int>(r.rdx & 0xff), r.r8);
        ret(f ? r.rcx + (static_cast<uint8_t*>(f) - p) : 0);
        return true;
    }
    case 0x5f40550: { // memcmp
        uint8_t* a = span(r.rcx, r.r8);
        uint8_t* b = span(r.rdx, r.r8);
        if (!a || !b) return false;
        int d = std::memcmp(a, b, r.r8);
        ret(static_cast<uint64_t>(static_cast<int64_t>(d)));
        return true;
    }
    case 0x5f40560: // memcpy
    case 0x5f40570: { // memmove
        uint8_t* d = span(r.rcx, r.r8);
        uint8_t* s = span(r.rdx, r.r8);
        if (!d || !s) return false;
        std::memmove(d, s, r.r8);
        ret(r.rcx);
        return true;
    }
    case 0x5f40580: { // memset
        uint8_t* d = span(r.rcx, r.r8);
        if (!d) return false;
        std::memset(d, static_cast<int>(r.rdx & 0xff), r.r8);
        ret(r.rcx);
        return true;
    }
    case 0x5f40590: { // strchr
        uint64_t n = slen(r.rcx);
        if (n == ~0ULL) return false;
        uint8_t* p = span(r.rcx, n + 1);
        if (!p) return false;
        void* f = std::strchr(reinterpret_cast<char*>(p), static_cast<int>(r.rdx & 0xff));
        ret(f ? r.rcx + (static_cast<uint8_t*>(f) - p) : 0);
        return true;
    }
    case 0x5f405a0: { // strrchr
        uint64_t n = slen(r.rcx);
        if (n == ~0ULL) return false;
        uint8_t* p = span(r.rcx, n + 1);
        if (!p) return false;
        void* f = std::strrchr(reinterpret_cast<char*>(p), static_cast<int>(r.rdx & 0xff));
        ret(f ? r.rcx + (static_cast<uint8_t*>(f) - p) : 0);
        return true;
    }
    case 0x5f405b0: { // strstr
        uint64_t n = slen(r.rcx);
        uint64_t m = slen(r.rdx);
        if (n == ~0ULL || m == ~0ULL) return false;
        uint8_t* h = span(r.rcx, n + 1);
        uint8_t* nd = span(r.rdx, m + 1);
        if (!h || !nd) return false;
        char* f = std::strstr(reinterpret_cast<char*>(h), reinterpret_cast<char*>(nd));
        ret(f ? r.rcx + (reinterpret_cast<uint8_t*>(f) - h) : 0);
        return true;
    }
    case 0x5f407c0: { // strcat
        uint64_t n = slen(r.rcx);
        uint64_t m = slen(r.rdx);
        if (n == ~0ULL || m == ~0ULL) return false;
        uint8_t* d = span(r.rcx, n + m + 1);
        uint8_t* s = span(r.rdx, m + 1);
        if (!d || !s) return false;
        std::memcpy(d + n, s, m + 1);
        ret(r.rcx);
        return true;
    }
    case 0x5f407d0: { // strcmp
        uint64_t n = slen(r.rcx);
        uint64_t m = slen(r.rdx);
        if (n == ~0ULL || m == ~0ULL) return false;
        uint8_t* a = span(r.rcx, n + 1);
        uint8_t* b = span(r.rdx, m + 1);
        if (!a || !b) return false;
        int d = std::strcmp(reinterpret_cast<char*>(a), reinterpret_cast<char*>(b));
        ret(static_cast<uint64_t>(static_cast<int64_t>(d)));
        return true;
    }
    case 0x5f407e0: { // strcpy
        uint64_t m = slen(r.rdx);
        if (m == ~0ULL) return false;
        uint8_t* d = span(r.rcx, m + 1);
        uint8_t* s = span(r.rdx, m + 1);
        if (!d || !s) return false;
        std::memcpy(d, s, m + 1);
        ret(r.rcx);
        return true;
    }
    case 0x5f407f0: { // strlen
        uint64_t n = slen(r.rcx);
        if (n == ~0ULL) return false;
        ret(n);
        return true;
    }
    default:
        return false;
    }
}

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
    uint64_t now = runner_.guest_qpc();
    for (auto& t : threads_) {
        if (t.state != ThreadState::Waiting) continue;
        if (t.watch_addr && mem_.read64(t.watch_addr) != t.watch_seen) {
            t.watch_addr = 0;
            t.sleep_until = 0;
            t.state = ThreadState::Ready;
            continue;
        }
        if (t.sleep_until) {
            if (now >= t.sleep_until) {
                t.sleep_until = 0;
                t.regs.rax = 0;
                t.state = ThreadState::Ready;
            }
            continue;
        }
        if (t.wait_handles.empty()) {
            // throttle timeout-0 poll threads: sleep 500k QPC ticks (50ms at 10MHz)
            t.sleep_until = now + 500000;
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
                for (uint64_t h : t.wait_handles) runner_.try_acquire_event(h, t.tid);
                t.wait_handles.clear();
                t.regs.rax = t.wake_rax;
                t.state = ThreadState::Ready;
            }
        } else {
            bool woke = false;
            for (size_t i = 0; i < t.wait_handles.size(); ++i) {
                if (runner_.is_event_signaled(t.wait_handles[i])) {
                    runner_.try_acquire_event(t.wait_handles[i], t.tid);
                    t.wait_handles.clear();
                    t.regs.rax = t.wake_rax ? t.wake_rax : static_cast<uint64_t>(i);
                    t.state = ThreadState::Ready;
                    woke = true;
                    break;
                }
            }
            if (!woke && t.wait_since && now > t.wait_since + 2000000) {
                static int force_wake_log = 0;
                if (force_wake_log < 20) {
                    ++force_wake_log;
                    std::fprintf(stderr, "    [sched] force-wake tid=%u after %llu QPC ticks\n",
                                 t.tid, static_cast<unsigned long long>(now - t.wait_since));
                }
                t.wait_handles.clear();
                t.regs.rax = 0x102; // WAIT_TIMEOUT
                t.state = ThreadState::Ready;
            }
        }
    }
}

int Scheduler::consume_wait_insn(GuestThread& t) {
    auto& r = cpu_.regs();
    if (mem_.read8(r.rip) != 0x0F || mem_.read8(r.rip + 1) != 0x01) return 0;
    const uint8_t op = mem_.read8(r.rip + 2);
    // MONITOR / MONITORX arm the address in RAX. No register result.
    if (op == 0xC8 || op == 0xFA) {
        t.watch_addr = r.rax;
        r.rip += 3;
        return 1;
    }
    // MWAIT / MWAITX. ECX bit 1 selects the MWAITX timer in EBX (TSC ticks).
    // The waiter gives the core to other guest threads until the monitored
    // qword changes or that timer expires.
    if (op == 0xC9 || op == 0xFB) {
        r.rip += 3;
        if (!t.watch_addr) return 1;
        t.watch_seen = mem_.read64(t.watch_addr);
        uint64_t ticks = (r.rcx & 2) ? static_cast<uint32_t>(r.rbx) : 10000;
        if (ticks < 200) ticks = 200;
        if (ticks > 200000) ticks = 200000;
        t.sleep_until = runner_.guest_qpc() + ticks;
        t.state = ThreadState::Waiting;
        static int logs = 0;
        if (logs++ < 4)
            std::fprintf(stderr, "  [cpu] mwait tid=%u addr=0x%llx val=0x%llx ticks=%llu\n",
                         t.tid, static_cast<unsigned long long>(t.watch_addr),
                         static_cast<unsigned long long>(t.watch_seen),
                         static_cast<unsigned long long>(ticks));
        return 2;
    }
    return 0;
}

int Scheduler::take_null_rip(GuestThread& t) {
    static uint16_t streak[256];
    auto& r = cpu_.regs();
    const unsigned slot = t.tid & 255;
    if (r.rip != 0) {
        streak[slot] = 0;
        return 0;
    }
    const uint64_t ret = mem_.read64(r.rsp);
    if (!runner_.in_image(ret) || streak[slot] >= 4) {
        t.state = ThreadState::Faulted;
        t.stop_reason = "null-rip";
        static int null_logs = 0;
        if (null_logs++ < 8)
            std::fprintf(stderr, "  [cpu] null rip tid=%u streak=%u ret=%s\n",
                         t.tid, streak[slot], runner_.where(ret).c_str());
        report_thread_fault(t);
        return 2;
    }
    ++streak[slot];
    r.rax = (ret - 0x140000000ULL == 0x4f6584a) ? 1 : 0;
    r.rip = ret;
    r.rsp += 8;
    static int resumes = 0;
    if (resumes++ < 8)
        std::fprintf(stderr, "    [cpu] null call tid=%u resume %s\n",
                     t.tid, runner_.where(r.rip).c_str());
    return 1;
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
    {
        uint64_t tlsarr = mem_.read64(r.msr_gs_base + 0x58);
        uint64_t tlsblk = tlsarr ? mem_.read64(tlsarr) : 0;
        std::fprintf(stderr, "     [rcx]=%llx [rcx+16]=%llx tls_tid=%x gs=%llx\n",
                     (unsigned long long)mem_.read64(r.rcx),
                     (unsigned long long)mem_.read64(r.rcx + 16),
                     tlsblk ? mem_.read32(tlsblk + 0x1454) : 0xdead,
                     (unsigned long long)r.msr_gs_base);
    }
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
        {
            char b[160];
            uint64_t ta = mem_.read64(t.regs.msr_gs_base + 0x58);
            uint64_t tb = ta ? mem_.read64(ta) : 0;
            std::snprintf(b, sizeof b, " rcx=%llx [rcx]=%llx tls_tid=%x",
                (unsigned long long)t.regs.rcx, (unsigned long long)(t.regs.rcx > 0x10000 ? mem_.read64(t.regs.rcx) : 0),
                tb ? mem_.read32(tb + 0x1454) : 0xdead);
            extra += b;
        }
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
    if (cpu_.identity()) {
        runner_.loader().plant_traps(mem_);
        std::fprintf(stderr, "  [cpu] title code runs on the host CPU\n");
    }

    size_t cur = threads_.empty() ? 0 : threads_.size() - 1;

    while (total_insns_ < total_budget && !g_stop &&
           !emu::host::GuestWindow::instance().closed()) {
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
            uint64_t soon = ~0ULL;
            for (const auto& t : threads_)
                if (t.state == ThreadState::Waiting && t.sleep_until && t.sleep_until < soon)
                    soon = t.sleep_until;
            if (soon != ~0ULL) {
                runner_.advance_qpc_to(soon);
                continue;
            }
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

            // A return lands on the sentinel, or two bytes past it when the
            // stacked return was adjusted by a short call encoding.
            if (r.rip >= DllRunner::kSentinel && r.rip < DllRunner::kSentinel + 0x10) {
                t.state       = ThreadState::Finished;
                t.exit_code   = r.rax;
                t.stop_reason = "returned (rv=" + std::to_string(r.rax) + ")";
                std::fprintf(stderr, "  [sched] %s (tid=%u) finished rv=0x%llx after %llu insns\n",
                             t.name.c_str(), t.tid,
                             static_cast<unsigned long long>(r.rax),
                             static_cast<unsigned long long>(t.insns));
                break;
            }

            {
                uint64_t ibase = 0, iend = 0;
                if (runner_.image_span(r.rip, ibase, iend)) {
                    static uint64_t interp_lo = 0, interp_hi = 0; static bool interp_init = false;
                    if (!interp_init) { interp_init = true; if (const char* e = std::getenv("BASALT_INTERP")) { unsigned long long a=0,b=0; if (std::sscanf(e, "%llx,%llx", &a, &b) == 2) { interp_lo = 0x140000000ULL + a; interp_hi = 0x140000000ULL + b; } } }
                    if (cpu_.identity() && r.rip >= 0x10000 && r.rip < 0x400000000ULL && !(r.rip >= interp_lo && r.rip < interp_hi)) {
                        static int entry_logs = 0;
                        if (entry_logs < 4) {
                            ++entry_logs;
                            uint8_t b[8]{};
                            for (int i = 0; i < 8; ++i) b[i] = mem_.read8(r.rip + i);
                            std::fprintf(stderr,
                                         "  [native] enter rip=%s bytes=%02x %02x %02x %02x %02x %02x %02x %02x fs=%llx gs=%llx\n",
                                         runner_.where(r.rip).c_str(),
                                         b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                                         static_cast<unsigned long long>(r.msr_fs_base),
                                         static_cast<unsigned long long>(r.msr_gs_base));
                            std::fprintf(stderr, "  [native] rsp=%llx rflags=%llx\n",
                                         static_cast<unsigned long long>(r.rsp),
                                         static_cast<unsigned long long>(r.rflags));
                            std::fflush(stderr);
                        }
                        // clwb over a multi-gigabyte range. The flush changes nothing.
                        if (r.rip >= 0x144ecc83bULL && r.rip < 0x144ecc858ULL &&
                            static_cast<uint32_t>(r.rdx) == 0) {
                            r.rip = 0x144ecc858ULL;
                            continue;
                        }
                        // div ecx with ecx == 0. The title hits this and the fault
                        // would otherwise be retried for the rest of the run.
                        if (mem_.read8(r.rip) == 0xF7 && mem_.read8(r.rip + 1) == 0xF1 &&
                            static_cast<uint32_t>(r.rcx) == 0) {
                            static int divs = 0;
                            if (divs < 4) {
                                ++divs;
                                std::fprintf(stderr, "  [native] skip div0 at %s\n",
                                             runner_.where(r.rip).c_str());
                            }
                            r.rax = 0;
                            r.rdx = 0;
                            r.rip += 2;
                            continue;
                        }
                        // call [rax+0x50] where the slot holds text, not code.
                        // The next instruction requires eax == ebx.
                        if (r.rip == 0x14086f9beULL) {
                            uint64_t tgt = mem_.read64(r.rax + 0x50);
                            if (tgt < 0x10000ULL || tgt >= 0x400000000ULL) {
                                static int bad_calls = 0;
                                if (bad_calls < 4) {
                                    ++bad_calls;
                                    std::fprintf(stderr,
                                                 "  [native] skip call [rax+50]=0x%llx at %s\n",
                                                 static_cast<unsigned long long>(tgt),
                                                 runner_.where(r.rip).c_str());
                                }
                                r.rax = r.rbx;
                                r.rip += 3;
                                continue;
                            }
                        }
                        // memset(0) of a fresh allocation. The pages are already zero,
                        // and filling them would pin gigabytes of RAM for nothing.
                        if (mem_.read8(r.rip) == 0xF3 && mem_.read8(r.rip + 1) == 0xAA &&
                            (r.rax & 0xff) == 0 && (r.rflags & 0x400) == 0 &&
                            r.rcx > (1u << 20)) {
                            static int skip_logs = 0;
                            if (skip_logs < 8) {
                                ++skip_logs;
                                std::fprintf(stderr, "  [native] skip zero-fill %llu bytes at %s\n",
                                             static_cast<unsigned long long>(r.rcx),
                                             runner_.where(r.rdi).c_str());
                            }
                            r.rdi += r.rcx;
                            r.rcx = 0;
                            r.rip += 2;
                            continue;
                        }
                        {
                            const int waited = consume_wait_insn(t);
                            if (waited == 2) break;
                            if (waited == 1) continue;
                        }
                        uint32_t c0 = 0, c1 = 0;
                        asm volatile("rdtsc" : "=a"(c0), "=d"(c1));
                        auto stop = native_slice(r);
                        uint32_t d0 = 0, d1 = 0;
                        asm volatile("rdtsc" : "=a"(d0), "=d"(d1));
                        (void)c1;
                        (void)d1;
                        uint64_t n = (static_cast<uint64_t>(d0 - c0)) / 4;
                        if (n < 1) n = 1;
                        if (n > 20'000'000) n = 20'000'000;
                        // A trap is one guest instruction plus the host signal.
                        // Counting the signal time made a Sleep loop burn the budget.
                        if (stop == cpu::NativeStop::Trap && n > 64) n = 64;
                        if (r.rip >= 0x142157654ULL && r.rip < 0x1421583b8ULL) {
                            static uint64_t inf_n[256];
                            if ((++inf_n[t.tid & 255] & 0x3fff) == 1)
                                std::fprintf(stderr, "  [inflate] stop=%d n_est=%llu tid=%u n=%llu in=%llx end=%llx out=%llx\n", (int)stop, (unsigned long long)n, t.tid,
                                             (unsigned long long)inf_n[t.tid & 255], (unsigned long long)r.r12,
                                             (unsigned long long)r.rbp, (unsigned long long)r.rsi);
                            static int dumps = 0;
                            if (dumps < 12 && r.r12 >= 0x1400000000ULL && r.r12 < 0x1400200000ULL) {
                                ++dumps;
                                const uint8_t* b = reinterpret_cast<const uint8_t*>(r.r12 & ~0xfULL);
                                std::fprintf(stderr, "  [inflate-in] %llx:", (unsigned long long)(r.r12 & ~0xfULL));
                                for (int i = 0; i < 48; ++i) std::fprintf(stderr, " %02x", mem_.read8(reinterpret_cast<uint64_t>(b) + i));
                                const uint8_t* h = reinterpret_cast<const uint8_t*>(0x1400000000ULL);
                                std::fprintf(stderr, "\n  [region-head]");
                                for (int i = 0; i < 48; ++i) std::fprintf(stderr, " %02x", mem_.read8(reinterpret_cast<uint64_t>(h) + i));
                                std::fprintf(stderr, "\n");
                            }
                        }
                        uint64_t before = total_insns_;
                        slice_insns += n;
                        t.insns += n;
                        total_insns_ += n;
                        runner_.add_insn_count(n);
                        {
                            const int nr = take_null_rip(t);
                            if (nr == 2) break;
                            if (nr == 1) continue;
                        }
                        if ((before >> 24) != (total_insns_ >> 24)) {
                            std::fprintf(stderr, "  [progress] insns=%llu rip=%s\n",
                                         static_cast<unsigned long long>(total_insns_),
                                         runner_.where(r.rip).c_str());
                            std::fflush(stderr);
                        }
                        // Signal all waiting worker events every ~64M insns
                        if ((before >> 26) != (total_insns_ >> 26)) {
                            runner_.signal_all_waiting_events();
                        }
                        // A multi-gigabyte rep stos commits pages until the kernel
                        // kills the process. Stop the string op once RAM is tight.
                        if ((r.rip & 1) == 0) {
                            static int rss_checks = 0;
                            if ((++rss_checks & 31) == 0) {
                                unsigned long resident = 0;
                                if (FILE* f = std::fopen("/proc/self/statm", "r")) {
                                    if (std::fscanf(f, "%*u %lu", &resident) != 1) resident = 0;
                                    std::fclose(f);
                                }
                                if (resident > (6ull << 30) / 4096 &&
                                    mem_.read8(r.rip) == 0xF3) {
                                    std::fprintf(stderr, "  [native] stopped a string fill at %s (ram)\n",
                                                 runner_.where(r.rip).c_str());
                                    r.rcx = 0;
                                    r.rip += 2;
                                }
                            }
                        }
                        // A zeroed control-byte table has no empty marker, so this
                        // probe walks the same groups forever. Return "not found".
                        if (r.rip == 0x14293ee20ULL || r.rip == 0x14293ef6fULL) {
                            static int mounts = 0;
                            if (mounts < 4) {
                                ++mounts;
                                uint32_t idx = mem_.read32(0x146e08b2cULL);
                                uint64_t arr = mem_.read64(r.msr_gs_base + 0x58);
                                uint64_t blk = arr ? mem_.read64(arr + static_cast<uint64_t>(idx) * 8) : 0;
                                std::fprintf(stderr,
                                             "  [tls] mount %s idx=%u flag=%u\n",
                                             runner_.where(r.rip).c_str(), idx,
                                             blk ? mem_.read8(blk + 8) : 0);
                            }
                        }
                        // Render lock spin range 0x1454f50f0..0x1454f5160.
                        // The game hits many instructions in this range (0x54f50f7,
                        // 0x54f5118, 0x54f5126, 0x54f5137, 0x54f5142, 0x54f5148).
                        if (r.rip >= 0x1454f50f0ULL && r.rip < 0x1454f5160ULL) {
                            static uint64_t spins = 0;
                            spins += n;
                            if (spins > 500000ULL) {
                                spins = 0;
                                break;
                            }
                        }
                        if (r.rip >= 0x144d9dab0ULL && r.rip < 0x144d9dae0ULL) {
                            static uint64_t spins2 = 0;
                            spins2 += n;
                            if (spins2 > 500000ULL) {
                                spins2 = 0;
                                break;
                            }
                        }
                        if (r.rip >= 0x144f2a440ULL && r.rip < 0x144f2a510ULL) {
                            static uint64_t spins3 = 0;
                            spins3 += n;
                            if (spins3 > 500000ULL) {
                                spins3 = 0;
                                break;
                            }
                        }
                        // tid=16 timeout-0 poll spin at game+0x1e1018f
                        // Cumulative force-return: after enough total spins,
                        // pop return address and signal workers.
                        if (r.rip >= 0x141e10180ULL && r.rip < 0x141e101a0ULL) {
                            static uint64_t spins4 = 0;
                            static uint64_t cumul4 = 0;
                            spins4 += n;
                            if (spins4 > 500000ULL) {
                                cumul4 += spins4;
                                spins4 = 0;
                                if (cumul4 > 5000000ULL) {
                                    r.rip = mem_.read64(r.rsp);
                                    r.rsp += 8;
                                    r.rax = 0;
                                    static int skip_logs4 = 0;
                                    if (skip_logs4++ < 4)
                                        std::fprintf(stderr, "  [native] poll force-return after %lluM cumul insns\n",
                                                     static_cast<unsigned long long>(cumul4 / 1000000));
                                    cumul4 = 0;
                                    runner_.signal_all_waiting_events();
                                } else {
                                    break;
                                }
                            }
                        }
                        // main thread list-walk at game+0x1de2c46..0x1de2c9d.
                        // The inner scan reloads ecx from [r14+4]. The outer walk
                        // stops when the sentinel node at r14+0x60 has [+0x94] == -1,
                        // which is the dword at r14+0xf4. Most of the time is inside
                        // the call at 0x145b65d10, so the slice timer lands there and
                        // the 80-byte window never accumulates. The return address
                        // 0x141de2c51 sits on that frame; the walk saved r14 at
                        // ret_slot+0x108 (push r14/rsi/rdi/rbx, sub rsp, 0xe8).
                        // spins5 fires at 500K, cumul5 force-returns at 2M.
                        {
                            uint64_t list = 0;
                            bool in_body = r.rip >= 0x141de2c46ULL && r.rip < 0x141de2ca0ULL;
                            if (in_body && r.r14 > 0x10000) list = r.r14;
                            if (!in_body && r.rsp > 0x10000) {
                                for (int s = 0; s < 48; ++s) {
                                    uint64_t slot = r.rsp + static_cast<uint64_t>(s) * 8;
                                    if (mem_.read64(slot) != 0x141de2c51ULL) continue;
                                    in_body = true;
                                    uint64_t saved = mem_.read64(slot + 0x108);
                                    if (saved > 0x10000 && saved + 0x100 < memory::XBSS_RAM_SIZE &&
                                        mem_.read64(saved + 8) > 0x10000)
                                        list = saved;
                                    break;
                                }
                            }
                            if (in_body) {
                                static uint64_t spins5 = 0;
                                static uint64_t cumul5 = 0;
                                if (list > 0x10000 && list + 0x100 < memory::XBSS_RAM_SIZE) {
                                    if (mem_.read32(list + 0xf4) == 0) {
                                        mem_.write32(list + 0xf4, 0xffffffffu);
                                        static int walks = 0;
                                        if (walks++ < 4)
                                            std::fprintf(stderr,
                                                         "  [native] list end marked, count=%u\n",
                                                         mem_.read32(list + 4));
                                    }
                                    uint32_t cnt = mem_.read32(list + 4);
                                    if (cnt > 1000000u) {
                                        mem_.write32(list + 4, 0);
                                        if (r.rip >= 0x141de2c5dULL && r.rip < 0x141de2c91ULL)
                                            r.rcx = 0;
                                        static int caps = 0;
                                        if (caps++ < 4)
                                            std::fprintf(stderr,
                                                         "  [native] list-walk count %u capped\n", cnt);
                                    }
                                }
                                spins5 += n;
                                if (spins5 > 500000ULL) {
                                    cumul5 += spins5;
                                    spins5 = 0;
                                    if (cumul5 > 2000000ULL) {
                                        if (r.rip >= 0x141de2c46ULL && r.rip < 0x141de2ca0ULL) {
                                            r.rip = 0x141de2c9dULL;
                                            r.rax = 0;
                                        }
                                        static int skip_logs = 0;
                                        if (skip_logs++ < 4)
                                            std::fprintf(stderr, "  [native] list-walk force-return after %lluM cumul insns\n",
                                                         static_cast<unsigned long long>(cumul5 / 1000000));
                                        cumul5 = 0;
                                        runner_.signal_all_waiting_events();
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                        // Hot-spinning threads at exe+0x6100..0x6300 (tid=88,108,116)
                        // These are internal polling loops; force-return after cumul
                        if (r.rip >= 0x140006100ULL && r.rip < 0x140006300ULL) {
                            static uint64_t spins6 = 0;
                            static uint64_t cumul6 = 0;
                            spins6 += n;
                            if (spins6 > 500000ULL) {
                                cumul6 += spins6;
                                spins6 = 0;
                                if (cumul6 > 5000000ULL) {
                                    r.rip = mem_.read64(r.rsp);
                                    r.rsp += 8;
                                    r.rax = 0;
                                    static int skip_logs6 = 0;
                                    if (skip_logs6++ < 4)
                                        std::fprintf(stderr, "  [native] low-addr spin force-return after %lluM cumul\n",
                                                     static_cast<unsigned long long>(cumul6 / 1000000));
                                    cumul6 = 0;
                                } else {
                                    break;
                                }
                            }
                        }
                        if (r.rip == 0x1454f5126ULL && r.rcx == 0x1478f6940ULL &&
                            r.rsi != 0xFFFFFFFF00000000ULL) {
                            uint32_t owner = static_cast<uint32_t>(r.rsi >> 32);
                            bool live = false;
                            if (r.rsi != 0) {
                                for (const auto& th : threads_) {
                                    if (th.state == ThreadState::Finished || th.state == ThreadState::Faulted)
                                        continue;
                                    uint64_t teb = th.regs.msr_gs_base;
                                    if (teb < 0x10000) continue;
                                    uint64_t arr = mem_.read64(teb + 0x58);
                                    if (arr < 0x10000) continue;
                                    uint64_t tls = mem_.read64(arr);
                                    if (tls < 0x10000) continue;
                                    if (mem_.read32(tls + 0x1454) == owner) { live = true; break; }
                                }
                            }
                            if (!live) {
                                mem_.write64(r.rcx, 0xFFFFFFFF00000000ULL);
                                r.rsi = 0xFFFFFFFF00000000ULL;
                                static int locks = 0;
                                if (locks++ < 2)
                                    std::fprintf(stderr, "  [native] render lock free, owner=%u\n", owner);
                            }
                        }
                        // The published sample lags the counter the producer already
                        // stored. The reader at this instruction is the clock the
                        // render wait compares with its deadline.
                        if (r.rip == 0x1400065f4ULL) {
                            uint64_t published = mem_.read64(0x149c3e0a0ULL);
                            uint64_t counter = mem_.read64(0x149c3e0a8ULL);
                            if (published < counter) {
                                mem_.write64(0x149c3e0a0ULL, counter);
                                static int clocks = 0;
                                if (clocks++ < 2)
                                    std::fprintf(stderr, "  [native] render clock %llu -> %llu\n",
                                                 static_cast<unsigned long long>(published),
                                                 static_cast<unsigned long long>(counter));
                            }
                        }
                        if (r.rip >= 0x140054e1fULL && r.rip < 0x140054e50ULL) {
                            static int budget_logs = 0;
                            if (budget_logs < 2) {
                                ++budget_logs;
                                std::fprintf(stderr,
                                             "  [native] budget al=%u edi=%u b8=%u c1=%u acc=%u "
                                             "b0=%u b4=%u open=%llx be=%u caller=%llx job=%llx\n",
                                             static_cast<unsigned>(r.rax & 0xff),
                                             static_cast<unsigned>(r.rdi & 0xffffffffu),
                                             mem_.read32(0x149c3e0b8ULL),
                                             mem_.read8(0x149c3e0c1ULL),
                                             mem_.read32(0x1478f6968ULL),
                                             mem_.read32(0x149c3e0b0ULL),
                                             mem_.read32(0x149c3e0b4ULL),
                                             static_cast<unsigned long long>(mem_.read64(0x149c3e090ULL)),
                                             mem_.read8(0x149c3e0beULL),
                                             static_cast<unsigned long long>(mem_.read64(r.rsp + 0x48)),
                                             static_cast<unsigned long long>(mem_.read64(0x14a210d18ULL)));
                                for (const auto& t : threads_) {
                                    if (t.state == ThreadState::Finished || t.state == ThreadState::Faulted)
                                        continue;
                                    uint64_t fn = t.param > 0x10000 ? mem_.read64(t.param) : 0;
                                    std::fprintf(stderr,
                                                 "    [native] tid=%u state=%u rip=%llx fn=%llx\n",
                                                 t.tid, static_cast<unsigned>(t.state),
                                                 static_cast<unsigned long long>(t.regs.rip),
                                                 static_cast<unsigned long long>(fn));
                                }
                                std::fflush(stderr);
                            }
                        }
                        // The list walk stops when the embedded end node at +0xf4 is -1.
                        // A zero there is an uninitialised end marker, so the walk repeats.
                        if (r.rip == 0x141de2c5dULL && r.r14 > 0x10000) {
                            uint64_t mark = r.r14 + 0xf4;
                            if (mem_.read32(mark) == 0) {
                                mem_.write32(mark, 0xffffffffu);
                                static int walks = 0;
                                if (walks++ < 2)
                                    std::fprintf(stderr, "  [native] list end marked, count=%u\n",
                                                 mem_.read32(r.r14 + 4));
                            }
                        }
                        // A full name table never finds an empty slot and doubles
                        // forever. Leave the insert; the caller continues.
                        // Swiss-table groups whose control bytes are zero look full,
                        // so the probe never inserts. Mark the current group empty.
                        // Same grow, wider groups (stride 0x190). Past a few thousand
                        // slots the fill never returns and no draw is recorded.
                        // The load-factor check stays true, so every insert rebuilds the
                        // table and the frame that would draw never runs.
                        // A directory count in the millions makes path lookup consume
                        // the whole run. Keep a small prefix and let the caller move on.
                        if (r.rip == 0x1413bc5ceULL && r.rcx < 0x10000) {
                            if (r.rdx > 0x10000) mem_.write8(r.rdx + 0x10, 0);
                            r.rip = 0x1413bc6c7ULL;
                        }
                        if (r.rip == 0x1413bc7aeULL && r.rcx < 0x10000)
                            r.rip = 0x1413bc8f7ULL;
                        if (r.rip == 0x1413bc7aeULL && r.rcx > 0x10000 && mem_.read32(r.rcx) != 0) {
                            mem_.write32(r.rcx + 4, 0);
                            r.rip = 0x1413bc8f7ULL;
                            static int kept2 = 0;
                            if (kept2++ < 2)
                                std::fprintf(stderr, "  [native] hash insert kept\n");
                        }
                        if (r.rip == 0x140048ca1ULL && r.rcx > 0x10000) {
                            uint32_t cnt = mem_.read32(r.rcx + 0xc04);
                            if (cnt > 4096) {
                                mem_.write32(r.rcx + 0xc04, 64);
                                static int dir_logs = 0;
                                if (dir_logs++ < 4)
                                    std::fprintf(stderr, "  [native] directory count %u capped\n", cnt);
                            }
                        }
                        if (r.rip >= 0x142edd8d4ULL && r.rip < 0x142edd92aULL) {
                            static uint64_t walks = 0;
                            walks += n;
                            if (walks > 2000000ULL) {
                                std::fprintf(stderr, "  [native] object walk did not end, leaving it\n");
                                r.rip = 0x142edd96fULL;
                                walks = 0;
                            }
                        }
                        // The table pointer is 0x30 here: the container was never
                        // created, and the grow faults on that address forever.
                        if (r.rip == 0x141dc543bULL && r.rbx < 0x10000) {
                            static int logs = 0;
                            if (logs++ < 2)
                                std::fprintf(stderr, "  [native] skip empty hash container\n");
                            r.rip = 0x141dc5570ULL;
                        }
                        if (r.rip == 0x141dc5385ULL && r.rbx < 0x10000)
                            r.rip = 0x141dc53c1ULL;
                        if (r.rip == 0x141cd3defULL && r.rcx < 0x10000) {
                            if (r.rdx > 0x10000) mem_.write8(r.rdx + 0x10, 0);
                            r.rip = 0x141cd3ef3ULL;
                        }
                        if (r.rip == 0x145a292efULL && r.rcx < 0x10000)
                            r.rip = 0x145a2935bULL;
                        if (r.rip == 0x145a292efULL && r.rcx > 0x10000 && mem_.read32(r.rcx) != 0) {
                            mem_.write32(r.rcx + 4, 0);
                            r.rip = 0x145a2935bULL;
                        }
                        if (r.rip >= 0x141cd3f85ULL && r.rip < 0x141cd3f90ULL) {
                            static uint64_t wraps = 0;
                            wraps += n;
                            if (wraps > 50000ULL) {
                                r.rip = 0x141cd3f79ULL;
                                wraps = 0;
                            }
                        }
                        if (r.rip >= 0x145a2933cULL && r.rip < 0x145a2934dULL && r.rbx > 64ull * 0x190) {
                            mem_.write32(r.rdi, 64);
                            mem_.write32(r.rdi + 4, 0);
                            r.r15 = 0;
                            r.rcx = 0;
                            r.rbx = 64ull * 0x190;
                            static int wide_logs = 0;
                            if (wide_logs < 4) {
                                ++wide_logs;
                                std::fprintf(stderr, "  [native] capped hash grow at %s\n",
                                             runner_.where(r.rdi).c_str());
                            }
                        }
                        if (r.rip >= 0x141db0579ULL && r.rip < 0x141db064dULL) {
                            static uint64_t groups = 0;
                            groups += n;
                            if (groups > 100000ULL) {
                                uint64_t cap = mem_.read32(0x1477b10b0ULL);
                                uint64_t ptr = mem_.read64(0x1477b10b8ULL);
                                static int hash_logs = 0;
                                if (!ptr || ptr < 0x10000) {
                                    // cap is non-zero but the storage pointer is null,
                                    // so the probe reloads address 0 forever.
                                    constexpr uint64_t kTable = 0x0A0000000ULL;
                                    constexpr int kGroups = 16;
                                    if (uint8_t* p = mem_.raw_ptr(kTable, kGroups * 0x90)) {
                                        std::memset(p, 0, kGroups * 0x90);
                                        for (int g = 0; g < kGroups; ++g)
                                            std::memset(p + g * 0x90, 0x80, 16);
                                    }
                                    mem_.write32(0x1477b10b0ULL, kGroups);
                                    mem_.write64(0x1477b10b8ULL, kTable);
                                    ptr = kTable;
                                    cap = kGroups;
                                }
                                if (hash_logs < 4) {
                                    ++hash_logs;
                                    uint8_t b0 = 0;
                                    if (uint8_t* p = mem_.raw_ptr(ptr, 1)) b0 = p[0];
                                    std::fprintf(stderr, "  [native] hash probe cap=%llu ptr=0x%llx ctrl=%02x\n",
                                                 static_cast<unsigned long long>(cap),
                                                 static_cast<unsigned long long>(ptr), b0);
                                }
                                r.rip = 0x141db0518ULL;
                                groups = 0;
                            }
                        }
                        if (r.rip >= 0x141549b6bULL && r.rip < 0x141549b90ULL) {
                            static uint64_t lookups = 0;
                            lookups += n;
                            if (lookups > 50000ULL) {
                                std::fprintf(stderr, "  [native] name lookup did not end, missing\n");
                                r.rax = 0;
                                r.rip = 0x141549b99ULL;
                                lookups = 0;
                            }
                        }
                        if ((r.rip >= 0x141b8e77bULL && r.rip < 0x141b8e7aaULL) ||
                            (r.rip >= 0x141b8e833ULL && r.rip < 0x141b8e99bULL)) {
                            static uint64_t grows = 0;
                            grows += n;
                            if (grows > 2000000ULL) {
                                std::fprintf(stderr, "  [native] name-table grow did not end, leaving it\n");
                                r.rip = 0x141b8ea60ULL;
                                grows = 0;
                            }
                        }
                        if ((r.rip >= 0x14292d610ULL && r.rip < 0x14292d670ULL) ||
                            (r.rip >= 0x14292db11ULL && r.rip < 0x14292db60ULL)) {
                            static uint64_t probes = 0;
                            probes += n;
                            if (probes > 4000000ULL) {
                                std::fprintf(stderr, "  [native] hash probe did not end, leaving it\n");
                                r.rip = 0x14292dc46ULL;
                                probes = 0;
                            }
                        }
                        if (stop == cpu::NativeStop::Trap && r.rip == 0x14293ee21ULL) {
                            uint32_t idx = mem_.read32(0x146e08b2cULL);
                            uint64_t arr = mem_.read64(r.msr_gs_base + 0x58);
                            uint64_t blk = arr ? mem_.read64(arr + static_cast<uint64_t>(idx) * 8) : 0;
                            std::fprintf(stderr, "  [tls] mount enter idx=%u flag=%u gs=%llx\n",
                                         idx, blk ? mem_.read8(blk + 8) : 0,
                                         static_cast<unsigned long long>(r.msr_gs_base));
                            mem_.write8(0x14293ee20ULL, 0x41);
                            r.rip = 0x14293ee20ULL;
                            continue;
                        }
                        if (stop == cpu::NativeStop::Trap && r.rip &&
                            runner_.loader().thunk_at(r.rip - 1))
                            r.rip -= 1;
                        if (stop == cpu::NativeStop::Syscall) {
                            static int sys_logs = 0;
                            if (sys_logs < 16) {
                                ++sys_logs;
                                std::fprintf(stderr, "  [native] syscall rax=0x%llx rip=%s lstar=0x%llx\n",
                                             static_cast<unsigned long long>(r.rax),
                                             runner_.where(r.rip).c_str(),
                                             static_cast<unsigned long long>(r.msr_lstar));
                            }
                            if (r.msr_lstar) {
                                r.rcx = r.rip;
                                r.r11 = r.rflags;
                                r.rip = r.msr_lstar;
                            } else {
                                r.rax = 0;
                            }
                            break;
                        }
                        if (stop == cpu::NativeStop::Fault &&
                            basalt_last_addr >= memory::XBSS_RAM_SIZE &&
                            basalt_last_addr < (0x400000000ULL << 4) &&
                            mem_.back_sparse(basalt_last_addr)) {
                            // Page now sits at its own address: run it again natively.
                            continue;
                        }
                        if (stop == cpu::NativeStop::Fault) {
                            uint8_t op = mem_.read8(r.rip);
                            if ((op == 0xCC || op == 0xF4) && runner_.loader().thunk_at(r.rip)) {
                                stop = cpu::NativeStop::Trap;
                            } else {
                            static int fault_logs = 0;
                            if (fault_logs < 24) {
                                ++fault_logs;
                                uint8_t b[8]{};
                                for (int i = 0; i < 8; ++i) b[i] = mem_.read8(r.rip + i);
                                std::fprintf(stderr,
                                             "  [native] fault rip=%s bytes=%02x %02x %02x %02x %02x %02x %02x %02x\n",
                                             runner_.where(r.rip).c_str(),
                                             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
                            }
                            uint8_t op0 = mem_.read8(r.rip);
                            uint8_t op1 = mem_.read8(r.rip + 1);
                            uint8_t op2 = mem_.read8(r.rip + 2);
                            if (op0 == 0x0F && op1 == 0x01 &&
                                (op2 == 0xC8 || op2 == 0xC9 || op2 == 0xFA || op2 == 0xFB)) {
                                const int waited = consume_wait_insn(t);
                                if (waited == 2) break;
                                if (waited == 1) continue;
                            }
                            if (op0 == 0xF3 && (op1 == 0xAA || op1 == 0xAB)) {
                                uint64_t n = r.rcx > 65536 ? 65536 : r.rcx;
                                int sz = op1 == 0xAA ? 1 : 4;
                                for (uint64_t i = 0; i < n; ++i) {
                                    if (sz == 1) mem_.write8(r.rdi + i, static_cast<uint8_t>(r.rax));
                                    else mem_.write32(r.rdi + i * 4, static_cast<uint32_t>(r.rax));
                                }
                                r.rdi += n * static_cast<uint64_t>(sz);
                                r.rcx -= n;
                                if (r.rcx == 0) r.rip += 2;
                            } else {
                            cpu_.step();
                            ++slice_insns; ++t.insns; ++total_insns_;
                            runner_.add_insn_count(1);
                            if (cpu_.fault()) {
                                t.state = ThreadState::Faulted;
                                t.stop_reason = "cpu-fault";
                                report_thread_fault(t);
                                break;
                            }
                            }
                            }
                        }
                        if (!runner_.loader().thunk_at(r.rip)) break;
                    } else {
                    int burst = 8192;
                    while (burst-- && slice_insns < quantum && total_insns_ < total_budget) {
                        if (r.rip < ibase || r.rip >= iend) break;
                        for (uint64_t pa : g_probes) if (pa == r.rip) {
                            static uint32_t bhits[256] = {};
                            if (++bhits[(t.tid / 4) & 255] > 40) break;
                            std::fprintf(stderr, "    [bprobe] tid=%u rva=0x%llx rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx r12=0x%llx rsi=0x%llx inend=0x%llx outend=0x%llx in8=%016llx ret=0x%llx\n",
                                         t.tid, (unsigned long long)(r.rip - 0x140000000ULL), (unsigned long long)r.rcx,
                                         (unsigned long long)r.rdx, (unsigned long long)r.r8, (unsigned long long)r.r9,
                                         (unsigned long long)r.r12, (unsigned long long)r.rsi,
                                         (unsigned long long)mem_.read64(r.rsp + 0xa0), (unsigned long long)mem_.read64(r.rsp + 0x90),
                                         (unsigned long long)mem_.read64(r.r12), (unsigned long long)(mem_.read64(r.rsp) - 0x140000000ULL));
                            std::fprintf(stderr, "    [bstack] tid=%u", t.tid);
                            for (int k = 0, n = 0; k < 2400 && n < 14; ++k) { uint64_t v = mem_.read64(r.rsp + 8ULL * k); if (v >= ibase + 0x1000 && v < iend && ++n) std::fprintf(stderr, " +%x:%llx", k * 8, (unsigned long long)(v - 0x140000000ULL)); }
                            std::fprintf(stderr, "\n");
                        }
                        if (crt_fast(mem_, r)) {
                            ++slice_insns;
                            ++t.insns;
                            ++total_insns_;
                            runner_.add_insn_count(1);
                            continue;
                        }
                        if ((total_insns_ & 0xFFFFFFULL) == 0) {
                            std::fprintf(stderr, "  [progress] insns=%llu rip=%s\n",
                                         static_cast<unsigned long long>(total_insns_),
                                         runner_.where(r.rip).c_str());
                        }
                        // Bounded copy the title calls as exe+0x5352510. Doing it
                        // here keeps the archive walk on the host instead of one
                        // interpreted byte at a time.
                        if (r.rip == 0x145352510ULL) {
                            uint64_t lim = r.r8 ? r.r8 - 1 : 0;
                            if (lim > (1u << 20)) lim = 1u << 20;
                            uint8_t* dst = mem_.raw_ptr(r.rcx, lim + 1);
                            uint8_t* src = mem_.raw_ptr(r.rdx, lim + 1);
                            if (dst && src) {
                                uint64_t i = 0;
                                for (; i < lim && src[i]; ++i) dst[i] = src[i];
                                dst[i] = 0;
                                r.rax = r.rcx;
                                r.rip = mem_.read64(r.rsp);
                                r.rsp += 8;
                                ++slice_insns;
                                ++t.insns;
                                ++total_insns_;
                                runner_.add_insn_count(1);
                                continue;
                            }
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
                            burst = 0;
                            break;
                        }
                    }
                    if (t.state == ThreadState::Faulted) break;
                    continue;
                    }
                }
            }

            if (const Thunk* tk = runner_.loader().thunk_at(r.rip)) {
                { static std::map<std::string,uint64_t> h; static uint64_t n=0;
                  h[std::to_string(t.tid)+" "+tk->name+" ret="+std::to_string(mem_.read64(r.rsp))]++;
                  if ((++n & 0x3fff)==0) { std::fprintf(stderr,"[thunk-hist]\n");
                    for (auto& [k,v]: h) if (v>200) std::fprintf(stderr,"  %8llu %s\n",(unsigned long long)v,k.c_str()); } }
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
                    t.wake_rax = wr.wake_rax;
                    if (wr.sleep_until) {
                        t.sleep_until = wr.sleep_until;
                        t.wait_handles.clear();
                        t.wait_since = runner_.guest_qpc();
                        t.state = ThreadState::Waiting;
                        break;
                    }
                    if (r.rip == 0x140056a0dULL) {
                        static int barrier_logs = 0;
                        static int main_dumps = 0;
                        if (barrier_logs < 8) {
                            ++barrier_logs;
                            std::fprintf(stderr,
                                         "    [sync] barrier wait tid=%u h=0x%llx remaining=%u\n",
                                         t.tid,
                                         wr.handles.empty() ? 0ull
                                                            : static_cast<unsigned long long>(wr.handles[0]),
                                         static_cast<unsigned>(r.rsi));
                        }
                        if (t.tid == 8 && main_dumps < 1) {
                            ++main_dumps;
                            std::fprintf(stderr,
                                         "    [sync] main barrier h=0x%llx remaining=%u\n",
                                         wr.handles.empty() ? 0ull
                                                            : static_cast<unsigned long long>(wr.handles[0]),
                                         static_cast<unsigned>(r.rsi));
                            for (int i = 0; i < 48; ++i) {
                                uint64_t q = mem_.read64(r.rsp + static_cast<uint64_t>(i) * 8);
                                if (q >= 0x140000000ULL && q < 0x150000000ULL)
                                    std::fprintf(stderr, "      rsp+0x%02x %s\n",
                                                 i * 8, runner_.where(q).c_str());
                            }
                        }
                    }
                    t.state        = ThreadState::Waiting;
                    t.wait_all     = wr.wait_all;
                    t.wait_handles = std::move(wr.handles);
                    t.wait_since   = runner_.guest_qpc();
                    break;
                }

                if (runner_.take_yield_request()) {
                    break;
                }
                continue;
            }

            {
                const int nr = take_null_rip(t);
                if (nr == 2) break;
                if (nr == 1) continue;
            }
            if (!runner_.in_image(r.rip)) {
                auto call_return = [&](uint64_t q) {
                    if (!runner_.in_image(q) || q < 0x140000010ULL) return false;
                    auto b = [&](int back) { return mem_.read8(q - static_cast<uint64_t>(back)); };
                    if (b(5) == 0xE8 || b(5) == 0xE9) return true;
                    for (int back = 2; back <= 7; ++back) {
                        if (b(back) != 0xFF) continue;
                        unsigned reg = (b(back - 1) >> 3) & 7;
                        if (reg == 2 || reg == 4) return true; // call or jmp
                    }
                    return false;
                };
                uint64_t ret = mem_.read64(r.rsp);
                if (!call_return(ret)) {
                    for (int i = 1; i < 64; ++i) {
                        uint64_t q = mem_.read64(r.rsp + static_cast<uint64_t>(i) * 8);
                        if (!call_return(q)) continue;
                        ret = q;
                        r.rsp += static_cast<uint64_t>(i) * 8;
                        break;
                    }
                }
                static int wild_resume = 0;
                if (runner_.in_image(ret) && (r.rip == 0xdeadbeefdeadbeefULL || r.rip < 0x10000ULL || wild_resume < 200)) {
                    if (r.rip != 0xdeadbeefdeadbeefULL && r.rip >= 0x10000ULL) ++wild_resume;
                    static int wild_logs = 0;
                    if (wild_logs < 24) {
                        ++wild_logs;
                        std::fprintf(stderr, "    [cpu] wild call rip=0x%llx rax=0x%llx resume %s\n",
                                     static_cast<unsigned long long>(r.rip),
                                     static_cast<unsigned long long>(r.rax),
                                     runner_.where(ret).c_str());
                        if (true)
                            for (unsigned k = 16; k < 32; ++k) {
                                uint64_t v = g_rip_ring[(g_rip_ring_i + k) & 31];
                                if (v) std::fprintf(stderr, "      [ring] tid=%u %s\n", t.tid, runner_.where(v).c_str());
                            }
                    }
                    // Poison is an empty slot. The caller at exe+0x4fac3d7
                    // treats a non-zero result as "already done" and retries.
                    r.rax = (r.rip == 0xdeadbeefdeadbeefULL || r.rip < 0x10000ULL) ? 0 : 1;
                    r.rip = ret;
                    r.rsp += 8;
                    continue;
                }
                if (r.rip >= 0x100000000ULL && r.rip < 0x140000000ULL)
                    std::fprintf(stderr,
                                 "    [cpu] heap jump tid=%u rip=0x%llx rax=0x%llx [rax]=0x%llx\n",
                                 t.tid,
                                 static_cast<unsigned long long>(r.rip),
                                 static_cast<unsigned long long>(r.rax),
                                 static_cast<unsigned long long>(mem_.read64(r.rax)));
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
                std::fprintf(stderr, "    [probe2] r12=0x%llx rsi=0x%llx inend=0x%llx outend=0x%llx in8=%016llx\n",
                             (unsigned long long)r.r12, (unsigned long long)r.rsi,
                             (unsigned long long)mem_.read64(r.rsp + 0xa0), (unsigned long long)mem_.read64(r.rsp + 0x90),
                             (unsigned long long)mem_.read64(r.r12));
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
        emu::host::GuestWindow::instance().pump();
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

    int images = 0;
    mem_.visit_extra_ram([&](uint64_t base, const uint8_t* p, uint64_t n) {
        if (images >= 2) return;
        uint64_t lim = n < (64ULL << 20) ? n : (64ULL << 20);
        for (uint64_t i = 0; i + 24 < lim; ++i) {
            if (p[i] == 0x89 && p[i + 1] == 'P' && p[i + 2] == 'N' && p[i + 3] == 'G') {
                uint64_t end = i + 8;
                for (; end + 4 < lim; ++end) {
                    if (p[end] == 'I' && p[end + 1] == 'E' && p[end + 2] == 'N' && p[end + 3] == 'D') {
                        end += 8;
                        break;
                    }
                }
                uint64_t len = end - i;
                if (len < 32 || len > (8ULL << 20)) continue;
                char path[64];
                std::snprintf(path, sizeof path, "runs/launch-%d.png", images);
                if (FILE* f = std::fopen(path, "wb")) {
                    std::fwrite(p + i, 1, len, f);
                    std::fclose(f);
                    std::fprintf(stderr, "  [img] %s from guest 0x%llx (%llu bytes)\n",
                                 path, static_cast<unsigned long long>(base + i),
                                 static_cast<unsigned long long>(len));
                    ++images;
                    i = end;
                }
            }
        }
    });

    uint64_t dram_pages = 0, dram_hot = 0;
    int sigs = 0;
    mem_.visit_resident_dram([&](uint64_t base, const uint8_t* p, uint64_t n) {
        dram_pages += n / 4096;
        for (uint64_t off = 0; off + 4096 <= n; off += 4096) {
            for (int s = 0; s < 8; ++s) {
                uint32_t w = 0;
                std::memcpy(&w, p + off + static_cast<uint64_t>(s) * 512, 4);
                if (w) { ++dram_hot; break; }
            }
        }
        for (uint64_t i = 0; i + 32 < n && sigs < 8; ++i) {
            bool png = p[i] == 0x89 && p[i + 1] == 'P' && p[i + 2] == 'N' && p[i + 3] == 'G';
            bool bmp = p[i] == 'B' && p[i + 1] == 'M';
            bool dds = p[i] == 'D' && p[i + 1] == 'D' && p[i + 2] == 'S' && p[i + 3] == ' ';
            if (!png && !bmp && !dds) continue;
            ++sigs;
            std::fprintf(stderr, "  [img] guest 0x%llx %s\n",
                         static_cast<unsigned long long>(base + i),
                         png ? "PNG" : bmp ? "BMP" : "DDS");
            if (!bmp || i + 54 > n) continue;
            uint32_t pix_off = 0, hdr = 0, width = 0;
            int32_t height = 0;
            uint16_t bpp = 0;
            std::memcpy(&pix_off, p + i + 10, 4);
            std::memcpy(&hdr, p + i + 14, 4);
            std::memcpy(&width, p + i + 18, 4);
            std::memcpy(&height, p + i + 22, 4);
            std::memcpy(&bpp, p + i + 28, 2);
            if (hdr < 40 || width < 8 || width > 3840 || height == 0 ||
                (bpp != 24 && bpp != 32))
                continue;
            uint32_t ah = static_cast<uint32_t>(height < 0 ? -height : height);
            if (ah > 2160) continue;
            uint64_t row = (static_cast<uint64_t>(width) * bpp / 8 + 3) & ~3ull;
            if (i + pix_off + row * ah > n) continue;
            std::vector<uint8_t> rgba(static_cast<size_t>(width) * ah * 4);
            for (uint32_t y = 0; y < ah; ++y) {
                uint32_t src_y = height > 0 ? ah - 1 - y : y;
                const uint8_t* rowp = p + i + pix_off + static_cast<uint64_t>(src_y) * row;
                for (uint32_t x = 0; x < width; ++x) {
                    size_t d = (static_cast<size_t>(y) * width + x) * 4;
                    rgba[d + 0] = rowp[x * (bpp / 8) + 2];
                    rgba[d + 1] = rowp[x * (bpp / 8) + 1];
                    rgba[d + 2] = rowp[x * (bpp / 8) + 0];
                    rgba[d + 3] = 255;
                }
            }
            emu::host::GuestWindow::instance().show_rgba(rgba.data(),
                                                         static_cast<int>(width),
                                                         static_cast<int>(ah));
        }
    });
    std::fprintf(stderr, "  [mem] DRAM resident=%llu pages hot=%llu signatures=%d\n",
                 static_cast<unsigned long long>(dram_pages),
                 static_cast<unsigned long long>(dram_hot), sigs);
}

} // namespace emu::kernel
