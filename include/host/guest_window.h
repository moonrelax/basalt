#pragma once
#include <cstdint>
#include <vector>

namespace emu::host {

// A real desktop window. Pixels shown here come from a guest buffer.
class GuestWindow {
public:
    static GuestWindow& instance();

    // Opens a 1280x720 window on the current display. Safe to call again.
    bool open();
    // Keep the window responsive. Does not redraw.
    void pump();
    // Copy a tightly packed RGBA8 image into the window and show it.
    void show_rgba(const uint8_t* rgba, int width, int height);
    // Decode a PNG the game just opened and show those pixels.
    void show_png_file(const char* path);
    // Decode a PNG into tightly packed RGBA8. False if it is not a readable image.
    bool load_png(const char* path, std::vector<uint8_t>& rgba, int& width, int& height);
    bool closed() const { return closed_; }

private:
    bool load();
    void present();

    void* lib_ = nullptr;
    void* window_ = nullptr;
    void* renderer_ = nullptr;
    void* texture_ = nullptr;
    int tex_w_ = 0;
    int tex_h_ = 0;
    bool closed_ = false;
    bool tried_ = false;
    std::vector<uint8_t> frame_;

    using InitFn = int (*)(uint32_t);
    using CreateWindowFn = void* (*)(const char*, int, int, int, int, uint32_t);
    using CreateRendererFn = void* (*)(void*, int, uint32_t);
    using CreateTextureFn = void* (*)(void*, uint32_t, int, int, int);
    using UpdateTextureFn = int (*)(void*, const void*, const void*, int);
    using RenderFn = int (*)(void*);
    using RenderCopyFn = int (*)(void*, void*, const void*, const void*);
    using PresentFn = void (*)(void*);
    using PollFn = int (*)(void*);
    using DestroyFn = void (*)(void*);
    using QuitFn = void (*)();
    using ErrorFn = const char* (*)();

    InitFn init_ = nullptr;
    CreateWindowFn create_window_ = nullptr;
    CreateRendererFn create_renderer_ = nullptr;
    CreateTextureFn create_texture_ = nullptr;
    UpdateTextureFn update_texture_ = nullptr;
    RenderFn render_clear_ = nullptr;
    RenderCopyFn render_copy_ = nullptr;
    PresentFn render_present_ = nullptr;
    PollFn poll_event_ = nullptr;
    DestroyFn destroy_texture_ = nullptr;
    QuitFn quit_ = nullptr;
    ErrorFn get_error_ = nullptr;
};

} // namespace emu::host
