#include "gpu/d3d12_xs.h"

namespace emu::gpu {

void Device::add_resource(uint64_t obj, uint64_t va, uint32_t width, uint32_t height) {
    resources_[obj] = Resource{obj, va, width, height};
    if (width == 1280 && height == 720) backbuffer_ = obj;
}

void Device::add_heap(uint64_t obj, uint64_t cpu, uint32_t count) {
    heaps_[obj] = DescriptorHeap{obj, cpu, count};
}

void Device::bind_rtv(uint64_t cpu_handle, uint64_t resource_obj) {
    if (cpu_handle) rtvs_[cpu_handle] = resource_obj;
}

const Resource* Device::rtv(uint64_t cpu_handle) const {
    auto it = rtvs_.find(cpu_handle);
    if (it == rtvs_.end()) return nullptr;
    return resource(it->second);
}

const Resource* Device::resource(uint64_t obj) const {
    auto it = resources_.find(obj);
    return it == resources_.end() ? nullptr : &it->second;
}

const DescriptorHeap* Device::heap(uint64_t obj) const {
    auto it = heaps_.find(obj);
    return it == heaps_.end() ? nullptr : &it->second;
}

Device& device() {
    static Device d;
    return d;
}

} // namespace emu::gpu
