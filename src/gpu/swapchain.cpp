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

bool blit_if_frame(memory::MemoryMap& mem, uint64_t src, uint64_t dst_obj) {
    const Resource* dst = device().resource(dst_obj);
    if (!dst || dst->width != 1280 || dst->height != 720 || !src) return false;
    uint64_t bytes = static_cast<uint64_t>(dst->width) * dst->height * 4;
    uint8_t* from = mem.raw_ptr(src, bytes);
    uint8_t* to = mem.raw_ptr(dst->va, bytes);
    if (!from || !to) return false;
    uint32_t n = dst->width * dst->height;
    uint32_t step = n / 48;
    uint32_t first = 0;
    bool have = false, varied = false;
    for (uint32_t i = 0; i < n; i += step) {
        uint32_t p = 0;
        std::memcpy(&p, from + static_cast<uint64_t>(i) * 4, 4);
        if ((p & 0x00ffffff) == 0) continue;
        if (!have) { first = p; have = true; continue; }
        if (p != first) { varied = true; break; }
    }
    if (!varied) return false;
    bool run = false;
    for (uint32_t i = 0; i + 4 < 64; ++i) {
        uint32_t a = 0, b = 0, c = 0;
        std::memcpy(&a, from + static_cast<uint64_t>(i) * 4, 4);
        std::memcpy(&b, from + static_cast<uint64_t>(i + 1) * 4, 4);
        std::memcpy(&c, from + static_cast<uint64_t>(i + 2) * 4, 4);
        if (a && a == b && b == c) { run = true; break; }
    }
    if (!run) return false;
    std::memcpy(to, from, bytes);
    std::fprintf(stderr, "    [draw] frame at 0x%llx -> backbuffer\n",
                 static_cast<unsigned long long>(src));
    return true;
}

} // namespace emu::gpu
