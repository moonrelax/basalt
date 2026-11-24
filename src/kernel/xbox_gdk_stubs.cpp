#include "kernel/xbox_gdk_stubs.h"
#include <cstdio>
#include <vector>

namespace emu::kernel {

// ── Xbox GDK stub table ───────────────────────────────────────────────────────
// Sources: Xbox GDK headers, public GDK documentation.
// Functions commonly imported by GDK titles.

static const std::vector<GdkStub> STUBS = {

    // ── XGameRuntime bootstrap glue (resolved dynamically via GetProcAddress) ─
    { "XGameRuntime.dll", "InitializeApiImpl",
      0x00000000, // S_OK
      "initializes XGameRuntime API dispatch (handled in dll_runner)" },

    { "XGameRuntime.dll", "InitializeApiImplEx",
      0x00000000, // S_OK
      "initializes XGameRuntime API dispatch Ex (handled in dll_runner)" },

    { "XGameRuntime.dll", "InitializeApiImplEx2",
      0x00000000, // S_OK
      "initializes XGameRuntime API dispatch Ex2 (handled in dll_runner)" },

    { "XGameRuntime.dll", "QueryApiImpl",
      0x00000000, // S_OK
      "returns fake COM object per IID (64-slot vtable, handled in dll_runner)" },

    { "XGameRuntime.dll", "UninitializeApiImpl",
      0x00000000,
      "uninitializes XGameRuntime API dispatch (handled in dll_runner)" },

    // ── Title identity ────────────────────────────────────────────────────────
    { "XGameRuntime.dll", "XGameGetXboxTitleId",
      0x00000000, // S_OK
      "returns TitleId=0x00000000 via OUT param (RCX)" },

    { "XGameRuntime.dll", "XGameGetXboxTitleIdAsString",
      0x00000000,
      "fills OUT buffer with \"00000000\"" },

    { "XGameRuntime.dll", "XGameGetParameter",
      0x00000000,
      "returns game parameter string from MicrosoftGame.Config" },

    // ── System / device type ─────────────────────────────────────────────────
    { "XGameRuntime.dll", "XSystemGetDeviceType",
      0x00000003, // XSystemDeviceType_XboxSeries (0x3)
      "returns Xbox Series S device type" },

    { "XGameRuntime.dll", "XSystemGetConsoleId",
      0x00000000,
      "fills 128-byte OUT buffer with synthetic console GUID" },

    { "XGameRuntime.dll", "XSystemGetAppSpecificDeviceId",
      0x00000000,
      "returns app-specific device ID blob" },

    // ── Package / identity ────────────────────────────────────────────────────
    { "XGameRuntime.dll", "XPackageGetCurrentProcessPackageIdentifier",
      0x00000000,
      "fills XPackageIdentifier with a placeholder MSAAppId" },

    { "XGameRuntime.dll", "XPackageEnumeratePackages",
      0x00000000,
      "enumerates installed DLC packages (stub: none)" },

    { "XGameRuntime.dll", "XPackageMountWithUiAsync",
      0x00000000,
      "mounts package — stub returns S_OK immediately" },

    // ── Memory ────────────────────────────────────────────────────────────────
    { "xmem.dll", "XMemVirtualAlloc",
      0x00000000,
      "allocates virtual memory (64 KiB+ aligned, handled in dll_runner)" },

    { "xmem.dll", "XMemVirtualFree",
      0x00000001,
      "frees virtual memory (handled in dll_runner)" },

    { "xmem.dll", "XMemAlloc",
      0x00000000,
      "allocates physical/virtual memory with attributes (handled in dll_runner)" },

    { "xmem.dll", "XMemFree",
      0x00000000,
      "frees XMemAlloc block (handled in dll_runner)" },

    { "xmem.dll", "XMemAllocDefault",
      0x00000000,
      "default XMem allocator implementation (handled in dll_runner)" },

    { "xmem.dll", "XMemFreeDefault",
      0x00000000,
      "default XMem free implementation (handled in dll_runner)" },

    { "xmem.dll", "XMemSetAllocationHooks",
      0x00000000,
      "registers custom XMem alloc/free hooks (handled in dll_runner)" },

    { "xmem.dll", "XMemGetAllocationHysteresis",
      0x00000000,
      "returns allocation hysteresis threshold (handled in dll_runner)" },

    { "xmem.dll", "XMemSetAllocationHysteresis",
      0x00000001,
      "sets allocation hysteresis threshold (handled in dll_runner)" },

    { "XGameRuntime.dll", "XMemAllocatePhysical",
      0x00000000,
      "allocates GPU-visible physical memory (handled in dll_runner)" },

    { "XGameRuntime.dll", "XMemFreePhysical",
      0x00000001,
      "frees physical memory (handled in dll_runner)" },

    // ── Storage / XVD ─────────────────────────────────────────────────────────
    { "XGameRuntime.dll", "XStorageQueryQuotaUsageAsync",
      0x00000000,
      "queries title storage quota (stub: returns 0 used)" },

    { "XGameRuntime.dll", "XStorageUploadToBlobByUri",
      0x80004001, // E_NOTIMPL
      "uploads save to cloud (stub: not implemented)" },

    // ── XAsync (async task framework) ─────────────────────────────────────────
    { "XGameRuntime.dll", "XAsyncGetStatus",
      0x00000000, // S_OK (task complete)
      "returns async task status — always complete in stub" },

    { "XGameRuntime.dll", "XAsyncGetResult",
      0x00000000,
      "returns async task result buffer" },

    { "XGameRuntime.dll", "XAsyncCancel",
      0x00000000,
      "cancels async task (stub: no-op)" },

    { "XGameRuntime.dll", "XAsyncSetCallbackContext",
      0x00000000,
      "sets callback context pointer" },

    { "XGameRuntime.dll", "XAsyncRun",
      0x00000000,
      "queues async task on thread pool" },

    { "XGameRuntime.dll", "XTaskQueueCreate",
      0x00000000,
      "creates task queue (stub: returns fake handle 0xFEEDF00D)" },

    { "XGameRuntime.dll", "XTaskQueueDispatch",
      0x00000001, // TRUE = items dispatched
      "dispatches queued callbacks (stub: immediate)" },

    { "XGameRuntime.dll", "XTaskQueueCloseHandle",
      0x00000000,
      "closes task queue handle" },

    // ── Store / license ───────────────────────────────────────────────────────
    { "XGameRuntime.dll", "XStoreQueryGameLicenseAsync",
      0x00000000,
      "queries game license (stub: licensed=true)" },

    { "XGameRuntime.dll", "XStoreQueryGameLicenseResult",
      0x00000000,
      "returns license result — always licensed in stub" },

    { "XGameRuntime.dll", "XStoreIsLicenseActive",
      0x00000001, // TRUE
      "returns license active state" },

    // ── Game save / XGameSave ─────────────────────────────────────────────────
    { "XGameRuntime.dll", "XGameSaveInitializeProviderAsync",
      0x00000000,
      "initializes save provider (stub: succeeds)" },

    { "XGameRuntime.dll", "XGameSaveCreateContainer",
      0x00000000,
      "creates save container handle" },

    { "XGameRuntime.dll", "XGameSaveSubmitUpdateAsync",
      0x00000000,
      "submits save data update (stub: no-op)" },

    { "XGameRuntime.dll", "XGameSaveCloseContainer",
      0x00000000,
      "closes save container" },

    // ── User / sign-in ────────────────────────────────────────────────────────
    { "XGameRuntime.dll", "XUserAddAsync",
      0x00000000,
      "adds Xbox user (stub: returns synthetic user handle)" },

    { "XGameRuntime.dll", "XUserAddResult",
      0x00000000,
      "returns added user handle" },

    { "XGameRuntime.dll", "XUserGetId",
      0x00000000,
      "returns XUID for user (stub: 0x0009000000000001)" },

    { "XGameRuntime.dll", "XUserGetGamertag",
      0x00000000,
      "fills gamertag buffer with \"Player1\"" },

    { "XGameRuntime.dll", "XUserGetSignInState",
      0x00000002, // XUserSignInState_SignedInOnline
      "returns user sign-in state" },

    { "XGameRuntime.dll", "XUserGetPrivilegeDenyReasonAsync",
      0x00000000,
      "checks privilege restrictions (stub: no restrictions)" },

    // ── Networking / XCurl ────────────────────────────────────────────────────
    { "XCurl.dll", "XCurlMultiCreate",
      0x00000000,
      "creates libcurl multi handle (stub: returns fake ptr)" },

    { "XCurl.dll", "XCurlEasyPerform",
      0x00000000,
      "performs HTTP request (stub: fails gracefully)" },

    { "libHttpClient.GDK.dll", "HCInitialize",
      0x00000000,
      "initializes HTTP client (stub: S_OK)" },

    { "libHttpClient.GDK.dll", "HCHttpCallCreate",
      0x00000000,
      "creates HTTP call handle" },

    { "libHttpClient.GDK.dll", "HCHttpCallPerformAsync",
      0x00000000,
      "performs HTTP call asynchronously (stub: immediate success)" },

    // ── AMD FidelityFX / upscaling ────────────────────────────────────────────
    { "amd_fidelityfx_loader_xbox.dll", "ffxGetInterface",
      0x00000000,
      "returns FidelityFX backend interface (stub: null)" },

    { "amd_fidelityfx_upscaler_xbox.dll", "ffxFsr2ContextCreate",
      0x00000000,
      "creates FSR2 upscaler context (stub: S_OK)" },

    { "amd_fidelityfx_upscaler_xbox.dll", "ffxFsr2ContextDispatch",
      0x00000000,
      "dispatches FSR2 upscale pass (stub: no-op)" },


    // ── Telemetry / ERA ───────────────────────────────────────────────────────
    { "XGameRuntime.dll", "XGameEventWrite",
      0x00000000,
      "writes telemetry event (stub: discarded)" },

    { "XGameRuntime.dll", "XboxAnaylticsRecordEvent",
      0x00000000,
      "analytics event (stub: discarded)" },

    // ── Thread / fiber ────────────────────────────────────────────────────────
    { "XGameRuntime.dll", "XThreadSetTimingInterval",
      0x00000000,
      "sets thread scheduler quantum (stub: no-op)" },

    { "XGameRuntime.dll", "XThreadAssignToProcessor",
      0x00000000,
      "pins thread to Zen 2 core (stub: no-op)" },
};

// ─────────────────────────────────────────────────────────────────────────────

const std::vector<GdkStub>& XboxGdkStubs::stubs() {
    return STUBS;
}

void XboxGdkStubs::print_stub_table() {
    fprintf(stderr,
            "  Xbox GDK import stubs (%zu entries):\n"
            "  %-40s  %-32s  %s\n"
            "  %s\n",
            STUBS.size(),
            "Function", "Module", "Return",
            "────────────────────────────────────────────────────────────────────────────");

    for (auto& s : STUBS) {
        fprintf(stderr, "  %-40s  %-32s  0x%08X\n",
                s.name, s.module, s.ret_val);
    }
    fprintf(stderr, "\n");
}

} // namespace emu::kernel
