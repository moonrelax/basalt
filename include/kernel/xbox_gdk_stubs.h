#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace emu::kernel {

// Xbox GDK (Game Development Kit) import stub table.
//
// When the title executable is loaded, its import directory references
// functions from the Xbox GDK runtime (XGameRuntime.lib, XCurl, XStorage …).
// Since we don't have those DLLs in runnable form on Linux, every import is
// patched to a stub that:
//   1. Logs the call + arguments (RAX / RCX / RDX)
//   2. Returns a plausible default (S_OK = 0 or E_NOTIMPL = 0x80004001)
//   3. Writes any OUT params to known safe values
//
// The CPU emulator hits these stubs via the import address table (IAT) which
// we fill with addresses of the stub trampoline region.

struct GdkStub {
    const char* module;   // DLL name (e.g. "XGameRuntime.dll")
    const char* name;     // exported symbol name
    uint32_t    ret_val;  // what RAX should contain after the call
    const char* note;     // human-readable description
};

class XboxGdkStubs {
public:
    // Print the full stub table to stderr (for --launch diagnostic output).
    static void print_stub_table();

    // Return all stubs (for the import patcher to iterate).
    static const std::vector<GdkStub>& stubs();
};

} // namespace emu::kernel
