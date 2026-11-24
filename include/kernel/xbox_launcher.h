#pragma once
#include <string>
#include <cstdint>

namespace emu::kernel {

// Xbox Series launch sequence for an unpacked GDK title directory.
// Steps:
//   1. validate      — check MicrosoftGame.Config and runtime DLLs
//   2. find_exe      — executable name from MicrosoftGame.Config
//   3. load_exe      — PE32+ header check
//   4. setup_gdk     — Xbox GDK import stubs
//   5. run           — title DLLs + exe entry point under the interpreter
//
// Each step logs progress to stderr. The sequence stops and reports at the
// first hard failure, so the user can see exactly how far we got.

struct LaunchResult {
    bool   ok;
    int    last_step;      // 1-5, how far we got
    char   reason[256];    // why we stopped
};

class XboxLauncher {
public:
    // game_dir : unpacked (unencrypted) GDK title directory
    explicit XboxLauncher(const std::string& game_dir);

    void set_max_insns(uint64_t n)   { max_insns_ = n; }
    void set_trace_from(uint64_t va) { trace_from_ = va; }

    LaunchResult launch();

private:
    std::string game_dir_;
    uint64_t    max_insns_  = 0;
    uint64_t    trace_from_ = 0;

    bool step_validate();
    bool step_find_exe(std::string& exe_path);
    bool step_load_exe(const std::string& exe_path);
    bool step_setup_gdk(const std::string& exe_path);
    bool step_run();

    char last_reason_[256] = {};
    void fail(const char* fmt, ...) __attribute__((format(printf,2,3)));
};

} // namespace emu::kernel
