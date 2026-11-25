#include "cpu/native_run.h"

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

extern "C" {
extern uint8_t basalt_guest_ymm[];
extern uint8_t basalt_in_guest;
extern uint8_t basalt_syscall_sel;
extern uint8_t basalt_stop;
extern uint8_t basalt_last_sig;
extern uint64_t basalt_last_addr;
extern uint64_t basalt_regs_ptr;
extern uint64_t basalt_host_rsp;
void basalt_native_enter(uint64_t* gpr, uint64_t fs, uint64_t gs);
void basalt_native_return();
void basalt_sig_entry(int, siginfo_t*, void*);

static emu::cpu::Registers* g_regs = nullptr;
// Per-thread CPU timer: ITIMER_VIRTUAL counts every host thread, so busy
// workers made slices end after a few microseconds.
static thread_local timer_t g_slice_timer;
static thread_local bool g_slice_timer_ok = false;
static void basalt_disarm_slice() {
    if (!g_slice_timer_ok) return;
    struct itimerspec off{};
    timer_settime(g_slice_timer, 0, &off, nullptr);
}
static int g_stop = 0;

void basalt_on_signal(int sig, siginfo_t*, void* ucp) {
    auto* uc = static_cast<ucontext_t*>(ucp);
    auto* gr = uc->uc_mcontext.gregs;
    char line[80];
    int n = 0;
    auto put = [&](char c) { if (n < 79) line[n++] = c; };
    auto hex = [&](uint64_t v) {
        for (int i = 15; i >= 0; --i) {
            int d = (v >> (i * 4)) & 0xf;
            put(d < 10 ? '0' + d : 'a' + d - 10);
        }
    };
    put('s'); put('i'); put('g'); put(' ');
    put('0' + (sig / 10) % 10); put('0' + sig % 10); put(' ');
    hex(static_cast<uint64_t>(gr[REG_RIP]));
    put('\n');
    write(2, line, n);
    if (!basalt_in_guest || !g_regs) {
        if (sig == SIGVTALRM || sig == SIGALRM || sig == SIGSYS) {
            if (sig == SIGSYS) gr[REG_RAX] = -38;
            return;
        }
        char b[64];
        int n = 0;
        const char* m = "native signal outside guest\n";
        while (m[n]) { b[n] = m[n]; ++n; }
        write(2, b, n);
        _exit(1);
    }
    basalt_in_guest = 0;
    basalt_syscall_sel = 0;
    basalt_disarm_slice();
    auto& g = *g_regs;
    g.r8 = gr[REG_R8];   g.r9 = gr[REG_R9];   g.r10 = gr[REG_R10]; g.r11 = gr[REG_R11];
    g.r12 = gr[REG_R12]; g.r13 = gr[REG_R13]; g.r14 = gr[REG_R14]; g.r15 = gr[REG_R15];
    g.rdi = gr[REG_RDI]; g.rsi = gr[REG_RSI]; g.rbp = gr[REG_RBP]; g.rbx = gr[REG_RBX];
    g.rdx = gr[REG_RDX]; g.rax = gr[REG_RAX]; g.rcx = gr[REG_RCX];
    g.rsp = gr[REG_RSP]; g.rip = gr[REG_RIP]; g.rflags = gr[REG_EFL];
    std::memcpy(&g.ymm[0], basalt_guest_ymm, 16 * 32);
    if (sig == SIGTRAP) g_stop = 1;
    else if (sig == SIGVTALRM || sig == SIGALRM) g_stop = 2;
    else if (sig == SIGSYS) g_stop = 4;
    else g_stop = 3;
    gr[REG_RIP] = reinterpret_cast<greg_t>(basalt_native_return);
    gr[REG_RSP] = static_cast<greg_t>(basalt_host_rsp);
}
} // extern "C"

namespace emu::cpu {

alignas(64) static char g_alt_stack[8 << 20];

static void arm(int usec) {
    if (!g_slice_timer_ok) {
        struct sigevent sev{};
        sev.sigev_notify = SIGEV_THREAD_ID;
        sev.sigev_signo = SIGVTALRM;
        sev._sigev_un._tid = static_cast<pid_t>(syscall(SYS_gettid));
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &g_slice_timer) != 0) {
            std::fprintf(stderr, "  [cpu] timer_create failed: %d\n", errno);
            return;
        }
        g_slice_timer_ok = true;
    }
    struct itimerspec it{};
    if (usec > 0) {
        it.it_value.tv_sec = usec / 1000000;
        it.it_value.tv_nsec = (usec % 1000000) * 1000L;
    }
    timer_settime(g_slice_timer, 0, &it, nullptr);
}

NativeStop native_slice(Registers& regs) {
    static bool ready = false;
    if (!ready) {
        stack_t ss{};
        ss.ss_sp = g_alt_stack;
        ss.ss_size = sizeof g_alt_stack;
        if (sigaltstack(&ss, nullptr) != 0)
            std::fprintf(stderr, "  [cpu] sigaltstack failed: %d\n", errno);
        struct sigaction sa{};
        sa.sa_sigaction = basalt_sig_entry;
        sigemptyset(&sa.sa_mask);
        for (int s : {SIGSEGV, SIGBUS, SIGTRAP, SIGILL, SIGVTALRM, SIGSYS, SIGFPE})
            sigaddset(&sa.sa_mask, s);
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
        for (int s : {SIGSEGV, SIGBUS, SIGTRAP, SIGILL, SIGVTALRM, SIGSYS, SIGFPE}) {
            if (sigaction(s, &sa, nullptr) != 0)
                std::fprintf(stderr, "  [cpu] sigaction %d failed: %d\n", s, errno);
        }
        // Host code lives above 16 GB. Syscalls from the title (below that)
        // are reported instead of being run on this machine.
        unsigned long off = 0x400000000UL;
        unsigned long len = (1UL << 47) - off;
        if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, off, len,
                  &basalt_syscall_sel) != 0)
            std::fprintf(stderr, "  [cpu] syscall dispatch failed: %d\n", errno);
        basalt_syscall_sel = 0;
        ready = true;
    }
    std::memcpy(basalt_guest_ymm, &regs.ymm[0], 16 * 32);
    uint32_t host_mx = 0;
    asm volatile("stmxcsr %0" : "=m"(host_mx));
    uint32_t guest_mx = regs.mxcsr | 0x1F80u;
    asm volatile("ldmxcsr %0" :: "m"(guest_mx));
    g_regs = &regs;
    basalt_regs_ptr = reinterpret_cast<uint64_t>(&regs);
    basalt_stop = 2;
    basalt_last_sig = 0;
    basalt_in_guest = 0;
    basalt_syscall_sel = 0;
    arm(20000);
    basalt_native_enter(&regs.rax, regs.msr_fs_base, regs.msr_gs_base);
    arm(0);
    std::memcpy(&regs.ymm[0], basalt_guest_ymm, 16 * 32);
    basalt_syscall_sel = 0;
    asm volatile("stmxcsr %0" : "=m"(regs.mxcsr));
    asm volatile("ldmxcsr %0" :: "m"(host_mx));
    g_regs = nullptr;
    basalt_regs_ptr = 0;
    int stop = basalt_stop;
    { static int k = 0; if ((++k & 0xfff) == 1) std::fprintf(stderr, "  [slice] sig=%d stop=%d rip=%llx addr=%llx rcx=%llx r10=%llx\n", basalt_last_sig, stop, (unsigned long long)regs.rip, (unsigned long long)basalt_last_addr, (unsigned long long)regs.rcx, (unsigned long long)regs.r10); }
    if (stop == 1) return NativeStop::Trap;
    if (stop == 4) return NativeStop::Syscall;
    if (stop == 3) return NativeStop::Fault;
    return NativeStop::Slice;
}

} // namespace emu::cpu
