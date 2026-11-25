#pragma once

#include <cstdint>
#include <vector>

namespace emu::gpu {

// Contract for the HLE side (dll_runner), which does not live in this module.
// ExecuteCommandLists calls submit(). PresentX m35 calls present(backbuffer_va).
// Pixels are produced only by rasterizing the draws in the list.

inline constexpr uint32_t kRtWidth = 1280;
inline constexpr uint32_t kRtHeight = 720;

struct ShaderView {
    const uint8_t* bytes = nullptr;
    uint32_t size = 0;
};

// Tightly packed floats: x, y, r, g, b, a. Clip space, color 0..1.
struct VertexView {
    const uint8_t* data = nullptr;
    uint32_t stride = 0;
    uint32_t count = 0;
};

struct DrawCall {
    uint32_t vertex_count = 0;
    uint32_t instance_count = 1;
    uint32_t start_vertex = 0;
    uint32_t start_instance = 0;
    bool indexed = false;
    uint32_t index_count = 0;
    uint32_t start_index = 0;
    const uint32_t* indices = nullptr;
    VertexView vertices{};
    ShaderView rdna2{};
};

struct CommandList {
    bool clear = false;
    float clear_rgba[4] = {};
    std::vector<DrawCall> draws;
};

void submit(const CommandList& cmdlist);

// Dumps the 1280x720 RT to /tmp/basalt-present.png when at least two
// different non-black colors are present. Returns false for an empty
// or flat target and writes no file.
bool present(uint64_t backbuffer_va);

const uint8_t* render_target();
uint32_t distinct_colors();
uint64_t last_present_va();

} // namespace emu::gpu
