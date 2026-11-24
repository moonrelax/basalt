#include <gtest/gtest.h>
#include "memory/memory_map.h"
#include "memory/mmu.h"

using namespace emu::memory;

// Build a minimal 4-level page table that maps vaddr → paddr.
static void setup_identity_map(MemoryMap& mm, uint64_t cr3,
                                uint64_t vaddr, uint64_t paddr) {
    auto write_entry = [&](uint64_t table_base, uint64_t idx, uint64_t entry) {
        mm.write64(table_base + idx * 8, entry);
    };

    uint64_t pml4_idx = (vaddr >> 39) & 0x1FF;
    uint64_t pdpt_idx = (vaddr >> 30) & 0x1FF;
    uint64_t pd_idx   = (vaddr >> 21) & 0x1FF;
    uint64_t pt_idx   = (vaddr >> 12) & 0x1FF;

    uint64_t pdpt = cr3 + 0x1000;
    uint64_t pd   = cr3 + 0x2000;
    uint64_t pt   = cr3 + 0x3000;

    write_entry(cr3, pml4_idx, pdpt | PTE_P | PTE_RW);
    write_entry(pdpt, pdpt_idx, pd  | PTE_P | PTE_RW);
    write_entry(pd,   pd_idx,   pt  | PTE_P | PTE_RW);
    write_entry(pt,   pt_idx,   paddr | PTE_P | PTE_RW);
}

TEST(MMU, TranslateIdentity) {
    MemoryMap mm;
    MMU mmu(mm);

    uint64_t cr3   = 0x100000; // page-aligned, within RAM
    uint64_t vaddr = 0xFFFF800000010000ULL;
    uint64_t paddr = 0x200000;

    setup_identity_map(mm, cr3, vaddr, paddr);
    mmu.set_cr3(cr3);

    auto result = mmu.translate(vaddr, false, false);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, paddr);
}

TEST(MMU, NotPresentFault) {
    MemoryMap mm;
    MMU mmu(mm);
    mmu.set_cr3(0x100000); // page tables all zero → not-present

    auto result = mmu.translate(0xFFFF800000020000ULL, false, false);
    EXPECT_FALSE(result.has_value());
}
