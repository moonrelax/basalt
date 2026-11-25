#include "memory/memory_map.h"
#include <algorithm>
#include <stdexcept>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

namespace emu::memory {

namespace {
struct IdentityHold {
    void* lo = nullptr;
    size_t lo_n = 0;
    void* hi = nullptr;
    size_t hi_n = 0;
    ~IdentityHold() {
        if (lo && lo != MAP_FAILED) munmap(lo, lo_n);
        if (hi && hi != MAP_FAILED) munmap(hi, hi_n);
    }
};

void* map_fixed(uint64_t addr, uint64_t size) {
    void* p = mmap(reinterpret_cast<void*>(addr), size,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE,
                   -1, 0);
    return p == MAP_FAILED ? nullptr : p;
}
} // namespace

MemoryRegion make_lazy_ram(uint64_t base, uint64_t size, std::string name) {
    MemoryRegion r{};
    r.base = base; r.size = size; r.type = RegionType::RAM; r.name = std::move(name);
    // The host does not use the low 16 GB. Mapping the guest there means the
    // CPU can run title code directly, instead of one interpreted instruction
    // at a time. The MMIO hole stays unmapped so those accesses still fault.
    if (base == 0 && size == XBSS_RAM_SIZE) {
        auto hold = std::make_shared<IdentityHold>();
        hold->lo_n = XBSS_MMIO_BASE - 0x10000;
        hold->hi_n = XBSS_RAM_SIZE - 0x100000000ULL;
        hold->lo = map_fixed(0x10000, hold->lo_n);
        hold->hi = map_fixed(0x100000000ULL, hold->hi_n);
        if (hold->lo && hold->hi) {
            r.identity = true;
            r.ext = std::shared_ptr<uint8_t>(reinterpret_cast<uint8_t*>(0x10000),
                                             [hold](uint8_t*) {});
            std::fprintf(stderr, "  [mem] identity map 16 GB (code runs on the host CPU)\n");
            return r;
        }
    }
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
    if (it != sparse_.end()) return it->second;
    if (!create || sparse_bytes_ >= kSparseCap) return nullptr;
    // Same host address as the guest one, so the title's own code can use it.
    uint8_t* p = static_cast<uint8_t*>(map_fixed(key, kSparsePage));
    if (!p) {
        void* q = mmap(nullptr, kSparsePage, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (q == MAP_FAILED) return nullptr;
        p = static_cast<uint8_t*>(q);
    }
    sparse_.emplace(key, p);
    sparse_bytes_ += kSparsePage;
    if (sparse_.size() == 1)
        std::fprintf(stderr, "  [mem] backing guest page 0x%llx (above physical RAM)\n",
                     static_cast<unsigned long long>(key));
    return p;
}

uint8_t* MemoryMap::dram_fast(uint64_t paddr, uint64_t n) {
    return const_cast<uint8_t*>(static_cast<const MemoryMap*>(this)->dram_fast(paddr, n));
}

const uint8_t* MemoryMap::dram_fast(uint64_t paddr, uint64_t n) const {
    if (!n || paddr + n < paddr) return nullptr;
    uint64_t end = paddr + n;
    // Overlays (GPU, HPET, PCIe) live only in [0xE0000000, 0x100000000).
    bool plain = end <= XBSS_MMIO_BASE
              || (paddr >= 0x100000000ULL && end <= XBSS_RAM_SIZE);
    if (!plain || regions_.empty() || regions_[0].base != 0 || !regions_[0].bytes())
        return nullptr;
    if (regions_[0].identity) {
        if (paddr < 0x10000) return nullptr;
        return reinterpret_cast<const uint8_t*>(paddr);
    }
    return regions_[0].bytes() + paddr;
}

template<typename T>
T MemoryMap::read_impl(uint64_t paddr) const {
    if (const uint8_t* p = dram_fast(paddr, sizeof(T))) {
        T val;
        std::memcpy(&val, p, sizeof(T));
        return val;
    }
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
        return static_cast<T>(0);
    }

    const MemoryRegion& r = opt->get();
    uint64_t offset = paddr - r.base;

    // Identity DRAM is mapped at the guest address, with a hole left unmapped.
    // bytes() is only the low window's start, so bytes()+paddr faults in the hole.
    if (r.identity) return static_cast<T>(0);

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
    if (uint8_t* p = dram_fast(paddr, sizeof(T))) {
        std::memcpy(p, &val, sizeof(T));
        return;
    }
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

    if (r.identity) return;
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

void MemoryMap::visit_resident_dram(const std::function<void(uint64_t, const uint8_t*, uint64_t)>& fn) const {
    constexpr uint64_t page = 4096;
    auto walk = [&](uint64_t base, const uint8_t* bytes, uint64_t size) {
        if (!bytes || size < page) return;
        const size_t pages = static_cast<size_t>(size / page);
        std::vector<unsigned char> resident(pages);
        if (mincore(const_cast<uint8_t*>(bytes), size, resident.data()) != 0) return;
        size_t run = 0;
        bool in = false;
        for (size_t i = 0; i < pages; ++i) {
            bool on = (resident[i] & 1) != 0;
            if (on && !in) { run = i; in = true; }
            if (!on && in) {
                fn(base + run * page, bytes + run * page, (i - run) * page);
                in = false;
            }
        }
        if (in) fn(base + run * page, bytes + run * page, (pages - run) * page);
    };
    for (const auto& r : regions_) {
        if (r.name != "DRAM" || !r.bytes() || r.size == 0) continue;
        if (r.identity) {
            walk(0x10000, reinterpret_cast<const uint8_t*>(0x10000), XBSS_MMIO_BASE - 0x10000);
            walk(0x100000000ULL, reinterpret_cast<const uint8_t*>(0x100000000ULL),
                 XBSS_RAM_SIZE - 0x100000000ULL);
            continue;
        }
        walk(r.base, r.bytes(), r.size);
    }
}

void MemoryMap::visit_extra_ram(const std::function<void(uint64_t, const uint8_t*, uint64_t)>& fn) const {
    for (const auto& r : regions_) {
        if (r.name == "DRAM" || r.type == RegionType::MMIO || !r.bytes()) continue;
        fn(r.base, r.bytes(), r.len());
    }
    for (const auto& [base, buf] : sparse_)
        fn(base, buf, kSparsePage);
}

uint8_t* MemoryMap::raw_ptr(uint64_t paddr, uint64_t size) {
    if (uint8_t* p = dram_fast(paddr, size)) return p;
    auto opt = find_region(paddr);
    if (!opt) {
        if (size > kSparsePage) return nullptr;
        uint8_t* p = sparse_bytes(paddr, false);
        if (!p) return nullptr;
        if ((paddr & (kSparsePage - 1)) + size > kSparsePage) return nullptr;
        return p + (paddr & (kSparsePage - 1));
    }
    MemoryRegion& r = opt->get();
    if (r.identity || r.type == RegionType::MMIO) return nullptr;
    uint64_t offset = paddr - r.base;
    if (offset + size > r.len()) return nullptr;
    return r.bytes() + offset;
}

} // namespace emu::memory
