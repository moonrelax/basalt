#pragma once
#include <cstdint>
#include <vector>
#include <memory>
#include <functional>
#include <optional>
#include <string>

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

private:
    std::vector<MemoryRegion> regions_;

    template<typename T>
    T    read_impl (uint64_t paddr) const;
    template<typename T>
    void write_impl(uint64_t paddr, T val);
};

} // namespace emu::memory
