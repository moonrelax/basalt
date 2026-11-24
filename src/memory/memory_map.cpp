#include "memory/memory_map.h"
#include <algorithm>
#include <stdexcept>
#include <cstdio>
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
    // 16 GB of guest DRAM, committed only on touch. Filling the vector up
    // front asked this 14 GB machine for the whole block and the kernel
    // killed the process.
    regions_.push_back(make_lazy_ram(0, XBSS_RAM_SIZE, "DRAM"));
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

uint8_t* MemoryMap::sparse_bytes(uint64_t paddr, bool create) const {
    if (paddr < XBSS_RAM_SIZE) return nullptr;
    uint64_t key = paddr & ~(kSparsePage - 1);
    auto it = sparse_.find(key);
    if (it != sparse_.end()) return it->second.get();
    if (!create || sparse_bytes_ >= kSparseCap) return nullptr;
    auto buf = std::make_unique<uint8_t[]>(kSparsePage);
    std::memset(buf.get(), 0, kSparsePage);
    uint8_t* p = buf.get();
    sparse_.emplace(key, std::move(buf));
    sparse_bytes_ += kSparsePage;
    if (sparse_.size() == 1)
        std::fprintf(stderr, "  [mem] backing guest page 0x%llx (above physical RAM)\n",
                     static_cast<unsigned long long>(key));
    return p;
}

template<typename T>
T MemoryMap::read_impl(uint64_t paddr) const {
    auto opt = find_region(paddr);
    if (!opt) {
        if (uint8_t* p = sparse_bytes(paddr, false)) {
            uint64_t off = paddr & (kSparsePage - 1);
            if (off + sizeof(T) <= kSparsePage) {
                T val;
                std::memcpy(&val, p + off, sizeof(T));
                return val;
            }
        }
        return static_cast<T>(0xDEADBEEFDEADBEEFULL);
    }

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
    if (!opt) {
        if (uint8_t* p = sparse_bytes(paddr, true)) {
            uint64_t off = paddr & (kSparsePage - 1);
            if (off + sizeof(T) <= kSparsePage)
                std::memcpy(p + off, &val, sizeof(T));
        }
        return;
    }

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

void MemoryMap::visit_extra_ram(const std::function<void(uint64_t, const uint8_t*, uint64_t)>& fn) const {
    for (const auto& r : regions_) {
        if (r.name == "DRAM" || r.type == RegionType::MMIO || !r.bytes()) continue;
        fn(r.base, r.bytes(), r.len());
    }
    for (const auto& [base, buf] : sparse_)
        fn(base, buf.get(), kSparsePage);
}

uint8_t* MemoryMap::raw_ptr(uint64_t paddr, uint64_t size) {
    auto opt = find_region(paddr);
    if (!opt) {
        if (size > kSparsePage) return nullptr;
        uint8_t* p = sparse_bytes(paddr, false);
        if (!p) return nullptr;
        if ((paddr & (kSparsePage - 1)) + size > kSparsePage) return nullptr;
        return p + (paddr & (kSparsePage - 1));
    }
    MemoryRegion& r = opt->get();
    if (r.type == RegionType::MMIO) return nullptr;
    uint64_t offset = paddr - r.base;
    if (offset + size > r.len()) return nullptr;
    return r.bytes() + offset;
}

} // namespace emu::memory
