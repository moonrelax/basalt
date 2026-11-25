#include "gpu/swapchain.h"

#include "gpu/d3d12_xs.h"
#include "host/guest_window.h"
#include "memory/memory_map.h"

#include <cstdio>
#include <cstring>

namespace emu::gpu {

bool present(memory::MemoryMap& mem, uint64_t resource_obj, const char* splash_path) {
    const Resource* r = device().resource(resource_obj);
    static int logs = 0;
    if (!r || !r->va || !r->width || !r->height) {
        if (logs < 4) {
            ++logs;
            std::fprintf(stderr, "    [swapchain] present resource 0x%llx has no buffer\n",
                         static_cast<unsigned long long>(resource_obj));
        }
        return false;
    }
    uint64_t bytes = static_cast<uint64_t>(r->width) * r->height * 4;
    uint8_t* px = mem.raw_ptr(r->va, bytes);
    if (!px) return false;
    (void)splash_path;
    uint32_t n = r->width * r->height;
    uint32_t step = n / 48;
    if (step < 1) step = 1;
    uint32_t first = 0;
    bool have = false;
    bool varied = false;
    for (uint32_t i = 0; i < n; i += step) {
        uint32_t p = 0;
        std::memcpy(&p, px + static_cast<uint64_t>(i) * 4, 4);
        if ((p & 0x00ffffff) == 0) continue;
        if (!have) { first = p; have = true; continue; }
        if (p != first) { varied = true; break; }
    }
    if (!varied) {
        if (logs < 4) {
            ++logs;
            std::fprintf(stderr, "    [swapchain] present %ux%u empty\n", r->width, r->height);
        }
        return false;
    }
    emu::host::GuestWindow::instance().show_rgba(px, static_cast<int>(r->width),
                                                 static_cast<int>(r->height));
    return true;
}

bool clear_render_target(memory::MemoryMap& mem, uint64_t cpu_handle, const float rgba[4]) {
    const Resource* r = device().rtv(cpu_handle);
    if (!r) r = device().resource(cpu_handle);
    static int logs = 0;
    if (!r || !r->va || !r->width || !r->height) {
        if (logs < 6) {
            ++logs;
            std::fprintf(stderr, "    [swapchain] clear handle 0x%llx has no target\n",
                         static_cast<unsigned long long>(cpu_handle));
        }
        return false;
    }
    uint8_t px[4];
    for (int i = 0; i < 4; ++i) {
        float c = rgba ? rgba[i] : 0.f;
        if (c < 0.f) c = 0.f;
        if (c > 1.f) c = 1.f;
        px[i] = static_cast<uint8_t>(c * 255.f + 0.5f);
    }
    uint64_t bytes = static_cast<uint64_t>(r->width) * r->height * 4;
    uint8_t* dst = mem.raw_ptr(r->va, bytes);
    if (!dst) return false;
    for (uint64_t i = 0; i < bytes; i += 4)
        std::memcpy(dst + i, px, 4);
    if (logs < 6) {
        ++logs;
        std::fprintf(stderr, "    [swapchain] clear %ux%u rgba %u,%u,%u,%u\n",
                     r->width, r->height, px[0], px[1], px[2], px[3]);
    }
    return true;
}

} // namespace emu::gpu
