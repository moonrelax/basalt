#include "memory/memory_map.h"
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <sys/mman.h>

namespace emu::memory {

MemoryRegion make_lazy_ram(uint64_t base, uint64_t size, std::string name) {
    MemoryRegion r{};
    r.base = base; r.size = size; r.type = RegionType::RAM; r.name = std::move(name);
    void* p = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) throw std::bad_alloc();
    r.ext = std::shared_ptr<uint8_t>(static_cast<uint8_t*>(p),
                                     [size](uint8_t* q){ munmap(q, size); });
    return r;
}

MemoryMap::MemoryMap() {
    // Pre-allocate 16 GB RAM region
    MemoryRegion ram{};
    ram.base = 0;
    ram.size = XBSS_RAM_SIZE;
    ram.type = RegionType::RAM;
    ram.name = "DRAM";
    ram.data.resize(XBSS_RAM_SIZE, 0);
    regions_.push_back(std::move(ram));
}

void MemoryMap::add_region(MemoryRegion region) {
    regions_.push_back(std::move(region));
    // Sort by base address for fast lookup
    std::sort(regions_.begin(), regions_.end(),
        [](const MemoryRegion& a, const MemoryRegion& b){ return a.base < b.base; });
}

void MemoryMap::remove_region(uint64_t base) {
    regions_.erase(
        std::remove_if(regions_.begin(), regions_.end(),
            [base](const MemoryRegion& r){ return r.base == base; }),
        regions_.end()
    );
}

std::optional<std::reference_wrapper<MemoryRegion>>
MemoryMap::find_region(uint64_t paddr) {
    // reverse: highest base wins, so overlays (MMIO) shadow the DRAM backing
    for (auto it = regions_.rbegin(); it != regions_.rend(); ++it) {
        if (paddr >= it->base && paddr < it->base + it->size)
            return *it;
    }
    return std::nullopt;
}

std::optional<std::reference_wrapper<const MemoryRegion>>
MemoryMap::find_region(uint64_t paddr) const {
    for (auto it = regions_.crbegin(); it != regions_.crend(); ++it) {
        if (paddr >= it->base && paddr < it->base + it->size)
            return *it;
    }
    return std::nullopt;
}

template<typename T>
T MemoryMap::read_impl(uint64_t paddr) const {
    auto opt = find_region(paddr);
    if (!opt) return static_cast<T>(0xDEADBEEFDEADBEEFULL);

    const MemoryRegion& r = opt->get();
    uint64_t offset = paddr - r.base;

    if (r.type == RegionType::MMIO) {
        if (r.read_cb) return static_cast<T>(r.read_cb(offset, sizeof(T)));
        return 0;
    }

    if (offset + sizeof(T) > r.len()) return 0;
    T val;
    std::memcpy(&val, r.bytes() + offset, sizeof(T));
    return val;
}

template<typename T>
void MemoryMap::write_impl(uint64_t paddr, T val) {
    auto opt = find_region(paddr);
    if (!opt) return; // bus error — TODO: raise #MC or similar

    MemoryRegion& r = opt->get();
    uint64_t offset = paddr - r.base;

    if (r.type == RegionType::ROM) return; // silent ignore write to ROM
    if (r.type == RegionType::MMIO) {
        if (r.write_cb) r.write_cb(offset, static_cast<uint64_t>(val), sizeof(T));
        return;
    }

    if (offset + sizeof(T) > r.len()) return;
    std::memcpy(r.bytes() + offset, &val, sizeof(T));
}

uint8_t  MemoryMap::read8 (uint64_t a) const { return read_impl<uint8_t>(a);  }
uint16_t MemoryMap::read16(uint64_t a) const { return read_impl<uint16_t>(a); }
uint32_t MemoryMap::read32(uint64_t a) const { return read_impl<uint32_t>(a); }
uint64_t MemoryMap::read64(uint64_t a) const { return read_impl<uint64_t>(a); }

void MemoryMap::write8 (uint64_t a, uint8_t  v) { write_impl(a, v); }
void MemoryMap::write16(uint64_t a, uint16_t v) { write_impl(a, v); }
void MemoryMap::write32(uint64_t a, uint32_t v) { write_impl(a, v); }
void MemoryMap::write64(uint64_t a, uint64_t v) { write_impl(a, v); }

uint8_t* MemoryMap::raw_ptr(uint64_t paddr, uint64_t size) {
    auto opt = find_region(paddr);
    if (!opt) return nullptr;
    MemoryRegion& r = opt->get();
    if (r.type == RegionType::MMIO) return nullptr;
    uint64_t offset = paddr - r.base;
    if (offset + size > r.len()) return nullptr;
    return r.bytes() + offset;
}

} // namespace emu::memory
