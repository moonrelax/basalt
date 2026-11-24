#include "memory/mmu.h"
#include <cstring>

namespace emu::memory {

MMU::MMU(MemoryMap& phys) : phys_(phys) {
    flush_tlb();
}

void MMU::set_cr3(uint64_t cr3) {
    cr3_ = cr3;
    flush_tlb(); // full TLB flush on CR3 switch (non-PCID path)
}

void MMU::flush_tlb() {
    for (auto& e : tlb_) e.valid = false;
}

void MMU::flush_tlb_page(uint64_t vaddr) {
    TLBEntry* e = tlb_lookup(vaddr);
    if (e) e->valid = false;
}

TLBEntry* MMU::tlb_lookup(uint64_t vaddr) const {
    uint64_t vpn = (vaddr >> PAGE_SHIFT);
    TLBEntry& e  = tlb_[vpn & (TLB_SIZE - 1)];
    if (e.valid && (e.vaddr >> PAGE_SHIFT) == vpn)
        return &e;
    return nullptr;
}

void MMU::tlb_insert(uint64_t vaddr, uint64_t paddr, uint64_t flags) const {
    uint64_t vpn = (vaddr >> PAGE_SHIFT);
    TLBEntry& e  = tlb_[vpn & (TLB_SIZE - 1)];
    e.vaddr = vaddr & PAGE_MASK;
    e.paddr = paddr & PAGE_MASK;
    e.flags = flags;
    e.valid = true;
}

uint64_t MMU::walk_page_tables(uint64_t vaddr, bool write, bool user) const {
    // 4-level paging: PML4 → PDPT → PD → PT
    // Each table has 512 8-byte entries.

    auto read_entry = [&](uint64_t base, uint64_t idx) -> uint64_t {
        return phys_.read64(base + idx * 8);
    };

    uint64_t pml4_idx = (vaddr >> 39) & 0x1FF;
    uint64_t pdpt_idx = (vaddr >> 30) & 0x1FF;
    uint64_t pd_idx   = (vaddr >> 21) & 0x1FF;
    uint64_t pt_idx   = (vaddr >> 12) & 0x1FF;

    uint64_t pml4e = read_entry(cr3_ & ~0xFFFULL, pml4_idx);
    if (!(pml4e & PTE_P)) return ~0ULL; // #PF not-present

    uint64_t pdpte = read_entry(pml4e & ~0xFFFULL, pdpt_idx);
    if (!(pdpte & PTE_P)) return ~0ULL;
    if (pdpte & PTE_PS) {
        // 1 GB huge page
        uint64_t paddr = (pdpte & ~0x3FFFFFFFULL) | (vaddr & 0x3FFFFFFFULL);
        tlb_insert(vaddr, paddr, pdpte);
        return paddr;
    }

    uint64_t pde = read_entry(pdpte & ~0xFFFULL, pd_idx);
    if (!(pde & PTE_P)) return ~0ULL;
    if (pde & PTE_PS) {
        // 2 MB huge page
        uint64_t paddr = (pde & ~0x1FFFFFULL) | (vaddr & 0x1FFFFFULL);
        tlb_insert(vaddr, paddr, pde);
        return paddr;
    }

    uint64_t pte = read_entry(pde & ~0xFFFULL, pt_idx);
    if (!(pte & PTE_P)) return ~0ULL;
    if (write && !(pte & PTE_RW)) return ~0ULL; // #PF write-protect

    uint64_t paddr = (pte & ~0xFFFULL) | (vaddr & 0xFFFULL);
    tlb_insert(vaddr, paddr, pte);
    return paddr;
}

std::optional<uint64_t> MMU::translate(uint64_t vaddr, bool write, bool user) const {
    TLBEntry* e = tlb_lookup(vaddr);
    if (e) {
        if (write && !(e->flags & PTE_RW)) return std::nullopt;
        if (user  && !(e->flags & PTE_US)) return std::nullopt;
        return e->paddr | (vaddr & ~PAGE_MASK);
    }

    uint64_t paddr = walk_page_tables(vaddr, write, user);
    if (paddr == ~0ULL) return std::nullopt;
    return paddr;
}

// Virtual read/write helpers
uint8_t  MMU::vread8 (uint64_t v) const { return phys_.read8 (*translate(v, false, false)); }
uint16_t MMU::vread16(uint64_t v) const { return phys_.read16(*translate(v, false, false)); }
uint32_t MMU::vread32(uint64_t v) const { return phys_.read32(*translate(v, false, false)); }
uint64_t MMU::vread64(uint64_t v) const { return phys_.read64(*translate(v, false, false)); }

void MMU::vwrite8 (uint64_t v, uint8_t  x) { phys_.write8 (*translate(v, true, false), x); }
void MMU::vwrite16(uint64_t v, uint16_t x) { phys_.write16(*translate(v, true, false), x); }
void MMU::vwrite32(uint64_t v, uint32_t x) { phys_.write32(*translate(v, true, false), x); }
void MMU::vwrite64(uint64_t v, uint64_t x) { phys_.write64(*translate(v, true, false), x); }

} // namespace emu::memory
