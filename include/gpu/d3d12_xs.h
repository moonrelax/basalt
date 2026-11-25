#pragma once
#include <cstdint>
#include <unordered_map>

namespace emu::gpu {

// Xbox device / queue / descriptor heap / resource tracking.
// The game talks to these through the D3D12 vtable; this only remembers
// the objects that later get presented.

struct Resource {
    uint64_t obj    = 0;
    uint64_t va     = 0; // guest RGBA8 pixels
    uint32_t width  = 0;
    uint32_t height = 0;
};

struct DescriptorHeap {
    uint64_t obj   = 0;
    uint64_t cpu   = 0; // guest base of the descriptor storage
    uint32_t count = 0;
};

class Device {
public:
    void add_resource(uint64_t obj, uint64_t va, uint32_t width, uint32_t height);
    void add_heap(uint64_t obj, uint64_t cpu, uint32_t count);
    void bind_rtv(uint64_t cpu_handle, uint64_t resource_obj);
    const Resource* resource(uint64_t obj) const;
    const DescriptorHeap* heap(uint64_t obj) const;
    const Resource* rtv(uint64_t cpu_handle) const;

private:
    std::unordered_map<uint64_t, Resource> resources_;
    std::unordered_map<uint64_t, DescriptorHeap> heaps_;
    std::unordered_map<uint64_t, uint64_t> rtvs_;
};

Device& device();

} // namespace emu::gpu
