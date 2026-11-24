#include "bus/pcie_bus.h"
#include <cstring>

namespace emu::bus {

PCIeBus::PCIeBus() {
    for (auto& dev : cfg_space_) dev.fill(0xFFFFFFFF);
    init_host_bridge();
    init_gpu();
    init_nvme();
    init_usb();
}

static void write32(std::array<uint32_t,1024>& space, uint16_t off, uint32_t val) {
    space[off / 4] = val;
}

void PCIeBus::init_host_bridge() {
    auto& d = cfg_space_[0];
    write32(d, 0x00, 0x14621022); // VendorID=AMD(1022), DeviceID=1462 (Zen 2 host bridge)
    write32(d, 0x08, 0x06000000); // class=host bridge
    write32(d, 0x0C, 0x00000000);
}

void PCIeBus::init_gpu() {
    auto& d = cfg_space_[1];
    // RDNA 2 GPU — approximate Navi 2X PCI IDs
    write32(d, 0x00, 0x73401002); // VendorID=AMD(1002), DeviceID=7340 (Navi10 approx)
    write32(d, 0x08, 0x03000000); // class=display controller
    write32(d, 0x10, 0xC0000000 | 4); // BAR0 — 256MB, 64-bit, prefetchable
    write32(d, 0x14, 0x00000000); // BAR0 high
    write32(d, 0x18, 0xFCA00000 | 0); // BAR2 — MMIO
    write32(d, 0x2C, 0x73401002); // subsystem
}

void PCIeBus::init_nvme() {
    auto& d = cfg_space_[2];
    write32(d, 0x00, 0x51CF144D); // Samsung NVMe
    write32(d, 0x08, 0x01080200); // class=NVMe
    write32(d, 0x10, 0xFCB00000 | 4); // BAR0
}

void PCIeBus::init_usb() {
    auto& d = cfg_space_[3];
    write32(d, 0x00, 0x14321022); // AMD USB xHCI
    write32(d, 0x08, 0x0C033000); // class=USB xHCI
    write32(d, 0x10, 0xFCC00000 | 4);
}

uint32_t PCIeBus::config_read(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg) {
    if (bus != 0 || fn != 0 || dev >= NUM_DEVS) return 0xFFFFFFFF;
    return cfg_space_[dev][reg / 4];
}

void PCIeBus::config_write(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg, uint32_t val) {
    if (bus != 0 || fn != 0 || dev >= NUM_DEVS) return;
    cfg_space_[dev][reg / 4] = val;
}

uint64_t PCIeBus::mmio_read(uint64_t addr, int size) {
    uint64_t offset = addr - ECAM_BASE;
    uint8_t  bus = (offset >> 20) & 0xFF;
    uint8_t  dev = (offset >> 15) & 0x1F;
    uint8_t  fn  = (offset >> 12) & 0x07;
    uint16_t reg = offset & 0xFFF;
    uint32_t v   = config_read(bus, dev, fn, reg & ~3);
    // byte/word alignment within dword
    int shift = (reg & 3) * 8;
    if (size == 1) return (v >> shift) & 0xFF;
    if (size == 2) return (v >> shift) & 0xFFFF;
    return v;
}

void PCIeBus::mmio_write(uint64_t addr, uint64_t val, int size) {
    uint64_t offset = addr - ECAM_BASE;
    uint8_t  bus = (offset >> 20) & 0xFF;
    uint8_t  dev = (offset >> 15) & 0x1F;
    uint8_t  fn  = (offset >> 12) & 0x07;
    uint16_t reg = offset & 0xFFF;
    // RMW for sub-dword
    uint32_t cur  = config_read(bus, dev, fn, reg & ~3);
    int      shift = (reg & 3) * 8;
    uint32_t mask  = (size == 1 ? 0xFF : size == 2 ? 0xFFFF : 0xFFFFFFFF) << shift;
    cur = (cur & ~mask) | ((static_cast<uint32_t>(val) << shift) & mask);
    config_write(bus, dev, fn, reg & ~3, cur);
}

} // namespace emu::bus
