#pragma once
#include <cstdint>

namespace emu::memory { class MemoryMap; }

namespace emu::gpu {

// Present one guest backbuffer into the desktop window.
// If the GPU has not drawn yet, the title splash is scaled into the buffer.
bool present(memory::MemoryMap& mem, uint64_t resource_obj, const char* splash_path);

// ID3D12GraphicsCommandList::ClearRenderTargetView. Fills the bound resource.
bool clear_render_target(memory::MemoryMap& mem, uint64_t cpu_handle, const float rgba[4]);

} // namespace emu::gpu
