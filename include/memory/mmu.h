#pragma once
#include <cstdint>
#include <optional>
#include "memory_map.h"

namespace emu::memory {

// x86-64 paging: 4-level page tables (PML4 → PDPT → PD → PT)
// Xbox Series S runs in 64-bit long mode; PCID and SMEP/SMAP are present on Zen2.

constexpr int PAGE_SHIFT = 12;
constexpr uint64_t PAGE_SIZE  = 1ULL << PAGE_SHIFT;
constexpr uint64_t PAGE_MASK  = ~(PAGE_SIZE - 1);

// PTE flags (Intel/AMD compatible)
constexpr uint64_t PTE_P    = (1ULL << 0);  // present
constexpr uint64_t PTE_RW   = (1ULL << 1);  // read/write
constexpr uint64_t PTE_US   = (1ULL << 2);  // user/supervisor
constexpr uint64_t PTE_PWT  = (1ULL << 3);  // write-through
constexpr uint64_t PTE_PCD  = (1ULL << 4);  // cache disable
constexpr uint64_t PTE_A    = (1ULL << 5);  // accessed
constexpr uint64_t PTE_D    = (1ULL << 6);  // dirty
constexpr uint64_t PTE_PS   = (1ULL << 7);  // page size (huge page in PD/PDPT)
constexpr uint64_t PTE_NX   = (1ULL << 63); // no-execute

struct TLBEntry {
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t flags;
    bool     valid = false;
};

constexpr int TLB_SIZE = 1024; // power of two

class MMU {
public:
    explicit MMU(MemoryMap& phys);

    // Translate virtual → physical; triggers #PF on fault (returns nullopt)
    std::optional<uint64_t> translate(uint64_t vaddr, bool write, bool user) const;

    // Set CR3 (flushes TLB, except global pages)
    void set_cr3(uint64_t cr3);
    uint64_t cr3() const { return cr3_; }

    void flush_tlb();
    void flush_tlb_page(uint64_t vaddr);

    // Convenience wrappers that go through translation
    uint8_t  vread8 (uint64_t vaddr) const;
    uint16_t vread16(uint64_t vaddr) const;
    uint32_t vread32(uint64_t vaddr) const;
    uint64_t vread64(uint64_t vaddr) const;

    void vwrite8 (uint64_t vaddr, uint8_t  val);
    void vwrite16(uint64_t vaddr, uint16_t val);
    void vwrite32(uint64_t vaddr, uint32_t val);
    void vwrite64(uint64_t vaddr, uint64_t val);

private:
    MemoryMap& phys_;
    uint64_t   cr3_ = 0;

    mutable std::array<TLBEntry, TLB_SIZE> tlb_{};

    TLBEntry* tlb_lookup(uint64_t vaddr) const;
    void      tlb_insert(uint64_t vaddr, uint64_t paddr, uint64_t flags) const;

    uint64_t walk_page_tables(uint64_t vaddr, bool write, bool user) const;
};

} // namespace emu::memory
