#pragma once
#include <cstdint>
#include <vector>
#include <memory>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>

namespace emu::memory {

// Xbox Series S memory layout (16 GB GDDR6, unified)
// Physical address space is 36-bit (64 GB addressable)
// GPU and CPU share the same physical pool — no discrete VRAM separation.

constexpr uint64_t XBSS_RAM_SIZE         = 0x400000000ULL; // 16 GB physical
constexpr uint64_t XBSS_MMIO_BASE        = 0xE0000000ULL;  // MMIO aperture start (low)
constexpr uint64_t XBSS_GPU_MMIO_BASE    = 0xFC000000ULL;  // RDNA2 register BAR
constexpr uint64_t XBSS_GPU_MMIO_SIZE    = 0x02000000ULL;
constexpr uint64_t XBSS_PCIE_ECAM_BASE   = 0xF0000000ULL;  // PCIe Enhanced Config
constexpr uint64_t XBSS_PCIE_ECAM_SIZE   = 0x01000000ULL;

enum class RegionType : uint8_t {
    RAM,
    ROM,
    MMIO,
    GPU_VRAM,  // GPU-visible region of unified memory
    INVALID,
};

struct MemoryRegion {
    uint64_t    base;
    uint64_t    size;
    RegionType  type;
    std::string name;

    // MMIO callbacks
    std::function<uint64_t(uint64_t offset, int sz)>              read_cb;
    std::function<void    (uint64_t offset, uint64_t val, int sz)> write_cb;

    // Backing store (RAM/ROM)
    std::vector<uint8_t> data;
    // Optional lazy backing (mmap MAP_NORESERVE) used instead of `data`, sized `size`.
    std::shared_ptr<uint8_t> ext;
    // Guest address and host address are the same. `ext` is not a base pointer.
    bool identity = false;
    uint8_t*       bytes()       { return ext ? ext.get() : data.data(); }
    const uint8_t* bytes() const { return ext ? ext.get() : data.data(); }
    uint64_t       len()   const { return ext ? size : data.size(); }
};

// Lazily-committed zeroed RAM region (pages materialize on first touch).
MemoryRegion make_lazy_ram(uint64_t base, uint64_t size, std::string name);

class MemoryMap {
public:
    MemoryMap();

    void add_region(MemoryRegion region);
    void remove_region(uint64_t base);

    uint8_t  read8 (uint64_t paddr) const;
    uint16_t read16(uint64_t paddr) const;
    uint32_t read32(uint64_t paddr) const;
    uint64_t read64(uint64_t paddr) const;

    void write8 (uint64_t paddr, uint8_t  val);
    void write16(uint64_t paddr, uint16_t val);
    void write32(uint64_t paddr, uint32_t val);
    void write64(uint64_t paddr, uint64_t val);

    std::optional<std::reference_wrapper<MemoryRegion>> find_region(uint64_t paddr);
    std::optional<std::reference_wrapper<const MemoryRegion>> find_region(uint64_t paddr) const;

    // Direct pointer for DMA / bulk transfers (returns nullptr for MMIO regions)
    uint8_t* raw_ptr(uint64_t paddr, uint64_t size);
    // Base of the flat 16 GB mapping, or null before it exists.
    uint8_t* dram_base() {
        if (regions_.empty() || regions_[0].base != 0) return nullptr;
        return regions_[0].bytes();
    }
    uint64_t dram_bytes() const {
        if (regions_.empty() || regions_[0].base != 0) return 0;
        return regions_[0].len();
    }
    bool identity() const {
        return !regions_.empty() && regions_[0].identity;
    }

    // Walk RAM that is not the 16 GB DRAM vector: lazy reservations and pages
    // materialized for addresses the guest wrote above physical RAM.
    void visit_extra_ram(const std::function<void(uint64_t base, const uint8_t* p, uint64_t n)>& fn) const;
    // Pages of the 16 GB DRAM mapping that the kernel has actually committed.
    void visit_resident_dram(const std::function<void(uint64_t base, const uint8_t* p, uint64_t n)>& fn) const;

private:
    std::vector<MemoryRegion> regions_;
    // Addresses past physical DRAM. Xbox code places resource objects there;
    // dropping the writes made later virtual calls read 0xDEADBEEF.
    static constexpr uint64_t kSparsePage = 0x10000;
    static constexpr uint64_t kSparseCap  = 512ULL << 20;
    mutable std::unordered_map<uint64_t, uint8_t*> sparse_;
    mutable uint64_t sparse_bytes_ = 0;
    uint8_t* sparse_bytes(uint64_t paddr, bool create) const;
public:
    // Backs the page at its own host address so native code can reach it.
    bool back_sparse(uint64_t paddr) const { return sparse_bytes(paddr, true) != nullptr; }
private:
    // Guest RAM outside the MMIO hole. Null when the range is not plain DRAM.
    uint8_t* dram_fast(uint64_t paddr, uint64_t n);
    const uint8_t* dram_fast(uint64_t paddr, uint64_t n) const;

    template<typename T>
    T    read_impl (uint64_t paddr) const;
    template<typename T>
    void write_impl(uint64_t paddr, T val);
};

} // namespace emu::memory
