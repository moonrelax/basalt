#include "kernel/xbox_launcher.h"
#include "kernel/loader.h"
#include "kernel/dll_runner.h"
#include "kernel/scheduler.h"
#include "kernel/xbox_gdk_stubs.h"
#include "memory/memory_map.h"
#include "memory/mmu.h"
#include "cpu/cpu.h"
#include "hal/timer.h"
#include "hal/interrupt_controller.h"
#include "gpu/command_processor.h"
#include "bus/pcie_bus.h"

#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
namespace emu::kernel {

// ─── helpers ──────────────────────────────────────────────────────────────────

static const char* SEP =
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

static void banner(const char* title) {
    fprintf(stderr, "\n%s", SEP);
    fprintf(stderr, "  %s\n", title);
    fprintf(stderr, "%s\n", SEP);
}

static uint64_t file_size_bytes(const std::string& p) {
    struct stat st{};
    if (stat(p.c_str(), &st) != 0) return 0;
    return static_cast<uint64_t>(st.st_size);
}

static bool file_exists(const std::string& p) {
    return access(p.c_str(), F_OK) == 0;
}

// Files commonly found in a GDK package root. Only the config is required;
// the executable name is read from it.
struct KnownFile {
    const char* name;
    bool        required;
};

static const KnownFile KNOWN_FILES[] = {
    { "MicrosoftGame.Config", true  },
    { "msvcp140.dll",         false },
    { "vcruntime140.dll",     false },
};

// ─── constructor ──────────────────────────────────────────────────────────────

XboxLauncher::XboxLauncher(const std::string& game_dir)
    : game_dir_(game_dir) {}

void XboxLauncher::fail(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(last_reason_, sizeof(last_reason_), fmt, ap);
    va_end(ap);
    fprintf(stderr, "[launch] FAIL: %s\n", last_reason_);
}

// ─── step: validate ─────────────────────────────────────────────────────────

bool XboxLauncher::step_validate() {
    banner("STEP 1 — Validating game directory");
    fprintf(stderr, "  game dir : %s\n\n", game_dir_.c_str());

    if (!file_exists(game_dir_)) {
        fail("game directory does not exist: %s", game_dir_.c_str());
        return false;
    }

    bool any_critical_missing = false;

    for (auto& kf : KNOWN_FILES) {
        std::string path = game_dir_ + "/" + kf.name;
        bool exists = file_exists(path);
        uint64_t sz = exists ? file_size_bytes(path) : 0;

        const char* status = "OK";
        if (!exists) {
            status = kf.required ? "MISSING  [REQUIRED]" : "absent   (optional)";
            if (kf.required) any_critical_missing = true;
        }

        fprintf(stderr, "  %-36s  %s", kf.name, status);
        if (exists)
            fprintf(stderr, "  (%.1f MB)", (double)sz / (1024.0 * 1024.0));
        fprintf(stderr, "\n");
    }

    fprintf(stderr, "\n");

    if (any_critical_missing) {
        fail("one or more required files are missing in %s", game_dir_.c_str());
        return false;
    }

    fprintf(stderr, "  Validation complete.\n");
    return true;
}

// ─── step: find exe ────────────────────────────────────────────────────────

// Reads <Executable Name="..."> from MicrosoftGame.Config, falls back to the
// first .exe in the package root.
std::string title_exe_name(const std::string& dir) {
    std::ifstream f(dir + "/MicrosoftGame.Config");
    std::string cfg((std::istreambuf_iterator<char>(f)), {});
    auto t = cfg.find("<Executable ");
    if (t != std::string::npos) {
        auto n = cfg.find("Name=\"", t);
        if (n != std::string::npos) {
            n += 6;
            auto e = cfg.find('"', n);
            if (e != std::string::npos) return cfg.substr(n, e - n);
        }
    }
    std::error_code ec;
    for (auto& de : fs::directory_iterator(dir, ec))
        if (de.path().extension() == ".exe") return de.path().filename().string();
    return {};
}

bool XboxLauncher::step_find_exe(std::string& exe_path) {
    banner("STEP 2 — Locating title executable");

    std::string name = title_exe_name(game_dir_);
    exe_path = game_dir_ + "/" + name;
    if (name.empty() || !file_exists(exe_path)) {
        fail("no title executable found in %s", game_dir_.c_str());
        exe_path.clear();
        return false;
    }
    fprintf(stderr, "  found %s (%.1f MB)\n", exe_path.c_str(),
            (double)file_size_bytes(exe_path) / (1024.0 * 1024.0));
    return true;
}


// ─── step: load exe ─────────────────────────────────────────────────────────

bool XboxLauncher::step_load_exe(const std::string& exe_path) {
    banner("STEP 3 — Loading PE32+ executable");

    // Load the real executable
    fprintf(stderr, "  Loading %s ...\n", exe_path.c_str());

    // Header-only validation: a throwaway MemoryMap would commit 16 GB of
    // zeroed DRAM and get OOM-killed. The runner does the real load.
    std::ifstream f(exe_path, std::ios::binary);
    uint8_t hdr[0x400] = {};
    f.read(reinterpret_cast<char*>(hdr), sizeof(hdr));
    auto rd32 = [&](size_t o) { uint32_t v; memcpy(&v, hdr + o, 4); return v; };
    auto rd64 = [&](size_t o) { uint64_t v; memcpy(&v, hdr + o, 8); return v; };
    uint32_t pe = (f.gcount() >= 0x40 && hdr[0] == 'M' && hdr[1] == 'Z') ? rd32(0x3C) : 0;
    bool ok = pe && pe + 0x58 <= sizeof(hdr) && rd32(pe) == 0x00004550
              && (hdr[pe + 0x18] | (hdr[pe + 0x19] << 8)) == 0x20B;
    if (!ok) {
        // Encrypted packages are not supported.
        fail("PE32+ load failed for %s", exe_path.c_str());
        fprintf(stderr, "\n  %s\n", last_reason_);
        return false;
    }
    uint64_t base  = rd64(pe + 0x30);
    uint32_t entry = rd32(pe + 0x28);
    uint32_t size  = rd32(pe + 0x50);

    fprintf(stderr, "\n  LOADED:\n"
            "    base       = 0x%016llX\n"
            "    entry      = 0x%016llX\n"
            "    image_size = 0x%X bytes (%.1f MB)\n",
            (unsigned long long)base,
            (unsigned long long)(base + entry),
            (unsigned)size,
            (double)size / (1024.0 * 1024.0));
    return true;
}

// ─── step: GDK environment ──────────────────────────────────────────────────

bool XboxLauncher::step_setup_gdk(const std::string& exe_path) {
    banner("STEP 4 — Setting up Xbox GDK environment");

    // Show stub table
    XboxGdkStubs::print_stub_table();

    // Show what DLLs are present in the dump
    fprintf(stderr, "\n  DLLs present in package:\n");
    const char* dlls[] = {
        "msvcp140.dll", "vcruntime140.dll", "concrt140.dll",
        "XCurl.dll", "libHttpClient.GDK.dll",
        nullptr
    };
    for (int i = 0; dlls[i]; ++i) {
        std::string p = game_dir_ + "/" + dlls[i];
        uint64_t sz = file_exists(p) ? file_size_bytes(p) : 0;
        fprintf(stderr, "    %-40s  %s", dlls[i],
                sz ? "present" : "absent ");
        if (sz) fprintf(stderr, "  (%.1f KB)", (double)sz / 1024.0);
        fprintf(stderr, "\n");
    }
    return true;
}

// ─── step: attempt CPU execution ────────────────────────────────────────────

bool XboxLauncher::step_run() {
    banner("STEP 5 — Running guest CPU execution");

    fprintf(stderr,
            "  Emulated Xbox Series S hardware:\n"
            "    CPU   8× Zen 2 cores @ 3.6 GHz (SMT)\n"
            "    GPU   RDNA 2, 4 TFLOPS (Series S)\n"
            "    RAM   10 GiB GDDR6 unified\n"
            "    SSD   512 GB NVMe (emulated via game dir)\n\n"
            "  Setting RIP → entry point...\n");

    // Fresh address space: DllRunner maps the title DLLs and the exe, then
    // calls DllMain for each and finally the exe entry point.
    emu::memory::MemoryMap mem;
    emu::memory::MMU       mmu(mem);
    emu::gpu::CommandProcessor gpu;
    emu::hal::HPET         hpet;
    emu::hal::LAPIC        lapic(0);
    emu::cpu::CPU          cpu;

    // Wire up CPU ↔ memory
    if (mem.identity()) cpu.set_identity(emu::memory::XBSS_RAM_SIZE);
    else cpu.set_dram(mem.dram_base(), mem.dram_bytes());
    cpu.set_mem_raw([&](uint64_t addr, uint64_t n) -> uint8_t* {
        return mem.raw_ptr(addr, n);
    });
    cpu.set_mem_read([&](uint64_t addr, int sz) -> uint64_t {
        switch (sz) {
            case 1: return mem.read8(addr);
            case 2: return mem.read16(addr);
            case 4: return mem.read32(addr);
            case 8: return mem.read64(addr);
            default: return 0;
        }
    });
    cpu.set_mem_write([&](uint64_t addr, uint64_t val, int sz) {
        switch (sz) {
            case 1: mem.write8(addr,  static_cast<uint8_t>(val));  break;
            case 2: mem.write16(addr, static_cast<uint16_t>(val)); break;
            case 4: mem.write32(addr, static_cast<uint32_t>(val)); break;
            case 8: mem.write64(addr, val);                        break;
        }
    });
    lapic.set_irq_handler([&](uint8_t vec) { cpu.raise_interrupt(vec); });

    (void)mmu; (void)gpu; (void)hpet;
    emu::kernel::DllRunner runner(mem, cpu);
    if (trace_from_ != 0) runner.set_trace_from(trace_from_);
    runner.run_all(game_dir_, false);
    if (auto exe = runner.load_exe(game_dir_)) {
        emu::kernel::Scheduler sched(mem, cpu, runner);
        sched.add_main_thread(exe->entry_point);
        uint64_t budget = max_insns_ ? max_insns_ : emu::kernel::Scheduler::kDefaultBudget;
        runner.set_insn_budget(budget);
        sched.run(budget);
    }

    return true;
}

// ─── main launch sequence ─────────────────────────────────────────────────────

LaunchResult XboxLauncher::launch() {
    fprintf(stderr, "\n");
    banner("basalt — Xbox Series launch sequence");
    fprintf(stderr, "  package: %s\n", game_dir_.c_str());

    if (!step_validate())
        return { false, 1, {} };

    std::string exe_path;
    if (!step_find_exe(exe_path)) {
        LaunchResult r{ false, 2, {} };
        memcpy(r.reason, last_reason_, sizeof(r.reason));
        return r;
    }
    if (!step_load_exe(exe_path)) {
        LaunchResult r{ false, 3, {} };
        memcpy(r.reason, last_reason_, sizeof(r.reason));
        return r;
    }
    step_setup_gdk(exe_path);
    step_run();

    banner("Launch Sequence Complete");
    fprintf(stderr,
            "  Executable    : %s\n"
            "  CPU execution : title DLLs + exe entry point under the interpreter\n\n"
            "  Remaining work to reach gameplay:\n"
            "    1. Xbox GDK / kernel services (threads, events, file IO)\n"
            "    2. Multi-core scheduling of guest threads\n"
            "    3. D3D12 / RDNA 2 command processor + shader translation\n"
            "    4. Audio and input\n\n",
            exe_path.c_str());

    return { true, 5, {} };
}


} // namespace emu::kernel
