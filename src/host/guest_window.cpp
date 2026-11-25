#include "host/guest_window.h"

#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <vector>

namespace emu::host {

namespace {
// SDL2 constants. RGBA32 on little-endian is ABGR8888.
constexpr uint32_t kInitVideo = 0x20;
constexpr int kWindowPosCentered = 0x2FFF0000;
constexpr uint32_t kWindowShown = 0x4;
constexpr uint32_t kRendererAccelerated = 0x2;
constexpr int kTextureStreaming = 1;
constexpr uint32_t kFormatRgba32 = 0x16862004; // SDL_PIXELFORMAT_ABGR8888
constexpr uint32_t kEventQuit = 0x100;
constexpr int kWinW = 1280;
constexpr int kWinH = 720;
}

GuestWindow& GuestWindow::instance() {
    static GuestWindow w;
    return w;
}

bool GuestWindow::load() {
    if (lib_) return true;
    if (tried_) return false;
    tried_ = true;
    lib_ = dlopen("libSDL2-2.0.so.0", RTLD_NOW);
    if (!lib_) {
        std::fprintf(stderr, "  [window] SDL2 not loaded (%s)\n", dlerror());
        return false;
    }
    auto sym = [&](const char* name) { return dlsym(lib_, name); };
    init_ = reinterpret_cast<InitFn>(sym("SDL_Init"));
    create_window_ = reinterpret_cast<CreateWindowFn>(sym("SDL_CreateWindow"));
    create_renderer_ = reinterpret_cast<CreateRendererFn>(sym("SDL_CreateRenderer"));
    create_texture_ = reinterpret_cast<CreateTextureFn>(sym("SDL_CreateTexture"));
    update_texture_ = reinterpret_cast<UpdateTextureFn>(sym("SDL_UpdateTexture"));
    render_clear_ = reinterpret_cast<RenderFn>(sym("SDL_RenderClear"));
    render_copy_ = reinterpret_cast<RenderCopyFn>(sym("SDL_RenderCopy"));
    render_present_ = reinterpret_cast<PresentFn>(sym("SDL_RenderPresent"));
    poll_event_ = reinterpret_cast<PollFn>(sym("SDL_PollEvent"));
    destroy_texture_ = reinterpret_cast<DestroyFn>(sym("SDL_DestroyTexture"));
    quit_ = reinterpret_cast<QuitFn>(sym("SDL_Quit"));
    get_error_ = reinterpret_cast<ErrorFn>(sym("SDL_GetError"));
    if (!init_ || !create_window_ || !create_renderer_ || !create_texture_ ||
        !update_texture_ || !render_clear_ || !render_copy_ || !render_present_ ||
        !poll_event_) {
        std::fprintf(stderr, "  [window] SDL2 is missing entry points\n");
        lib_ = nullptr;
        return false;
    }
    return true;
}

bool GuestWindow::open() {
    if (window_) return true;
    if (!load()) return false;
    if (init_(kInitVideo) != 0) {
        std::fprintf(stderr, "  [window] SDL_Init failed: %s\n", get_error_ ? get_error_() : "?");
        return false;
    }
    window_ = create_window_("basalt", kWindowPosCentered, kWindowPosCentered,
                             kWinW, kWinH, kWindowShown);
    if (!window_) {
        std::fprintf(stderr, "  [window] CreateWindow failed: %s\n", get_error_ ? get_error_() : "?");
        return false;
    }
    renderer_ = create_renderer_(window_, -1, kRendererAccelerated);
    if (!renderer_) {
        std::fprintf(stderr, "  [window] CreateRenderer failed: %s\n", get_error_ ? get_error_() : "?");
        return false;
    }
    render_clear_(renderer_);
    render_present_(renderer_);
    std::fprintf(stderr, "  [window] opened %dx%d\n", kWinW, kWinH);
    std::fflush(stderr);
    return true;
}

void GuestWindow::pump() {
    if (!window_ || !poll_event_) return;
    alignas(8) unsigned char ev[256];
    while (poll_event_(ev)) {
        uint32_t type = 0;
        std::memcpy(&type, ev, sizeof type);
        if (type == kEventQuit) {
            closed_ = true;
            std::fprintf(stderr, "  [window] closed by user\n");
        }
    }
}

void GuestWindow::present() {
    if (!renderer_ || !texture_) return;
    render_clear_(renderer_);
    render_copy_(renderer_, texture_, nullptr, nullptr);
    render_present_(renderer_);
}

void GuestWindow::show_rgba(const uint8_t* rgba, int width, int height) {
    if (!rgba || width < 1 || height < 1) return;
    if (!open()) return;
    if (width != tex_w_ || height != tex_h_ || !texture_) {
        if (texture_ && destroy_texture_) destroy_texture_(texture_);
        texture_ = create_texture_(renderer_, kFormatRgba32, kTextureStreaming, width, height);
        tex_w_ = width;
        tex_h_ = height;
        if (!texture_) {
            std::fprintf(stderr, "  [window] texture %dx%d failed: %s\n",
                         width, height, get_error_ ? get_error_() : "?");
            return;
        }
    }
    if (update_texture_(texture_, nullptr, rgba, width * 4) != 0) return;
    present();
    std::fprintf(stderr, "  [window] frame %dx%d\n", width, height);
    std::fflush(stderr);
}

bool GuestWindow::load_png(const char* path, std::vector<uint8_t>& rgba, int& width, int& height) {
    width = height = 0;
    rgba.clear();
    if (!path || !path[0]) return false;
    void* png = dlopen("libpng16.so.16", RTLD_NOW);
    if (!png) return false;
    using BeginFn = int (*)(void*, const void*, size_t);
    using FinishFn = int (*)(void*, const void*, void*, int32_t, void*);
    using FreeFn = void (*)(void*);
    auto begin = reinterpret_cast<BeginFn>(dlsym(png, "png_image_begin_read_from_memory"));
    auto finish = reinterpret_cast<FinishFn>(dlsym(png, "png_image_finish_read"));
    auto freep = reinterpret_cast<FreeFn>(dlsym(png, "png_image_free"));
    if (!begin || !finish) {
        dlclose(png);
        return false;
    }
    FILE* f = std::fopen(path, "rb");
    if (!f) {
        dlclose(png);
        return false;
    }
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz < 32 || sz > (16 << 20)) {
        std::fclose(f);
        dlclose(png);
        return false;
    }
    std::vector<uint8_t> file(static_cast<size_t>(sz));
    if (std::fread(file.data(), 1, file.size(), f) != file.size()) {
        std::fclose(f);
        dlclose(png);
        return false;
    }
    std::fclose(f);
    alignas(8) unsigned char image[128]{};
    auto u32 = [&](int off) -> uint32_t& {
        return *reinterpret_cast<uint32_t*>(image + off);
    };
    u32(8) = 1; // PNG_IMAGE_VERSION
    if (!begin(image, file.data(), file.size())) {
        if (freep) freep(image);
        dlclose(png);
        return false;
    }
    uint32_t w = u32(12), h = u32(16);
    u32(20) = 0x03; // PNG_FORMAT_RGBA
    if (w < 1 || h < 1 || w > 4096 || h > 4096) {
        if (freep) freep(image);
        dlclose(png);
        return false;
    }
    rgba.resize(static_cast<size_t>(w) * h * 4);
    int ok = finish(image, nullptr, rgba.data(), 0, nullptr);
    if (freep) freep(image);
    dlclose(png);
    if (!ok) {
        rgba.clear();
        return false;
    }
    width = static_cast<int>(w);
    height = static_cast<int>(h);
    return true;
}

void GuestWindow::show_png_file(const char* path) {
    static int shown = 0;
    if (shown >= 4) return;
    std::vector<uint8_t> rgba;
    int w = 0, h = 0;
    if (!load_png(path, rgba, w, h)) return;
    ++shown;
    show_rgba(rgba.data(), w, h);
}

} // namespace emu::host
