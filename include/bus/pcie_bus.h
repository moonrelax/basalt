#pragma once
#include <cstdint>
#include <array>

namespace emu::bus {

// PCIe Extended Configuration Access Mechanism (ECAM)
// Base address: 0xF0000000
// Address encoding: [27:20] bus, [19:15] device, [14:12] function, [11:0] register
class PCIeBus {
public:
    static constexpr uint64_t ECAM_BASE = 0xF0000000ULL;
    static constexpr uint64_t ECAM_SIZE = 0x10000000ULL; // 256 MB (256 buses)

    PCIeBus();

    uint32_t config_read (uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg);
    void     config_write(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg, uint32_t val);

    // MMIO dispatch from memory map
    uint64_t mmio_read (uint64_t addr, int size);
    void     mmio_write(uint64_t addr, uint64_t val, int size);

private:
    // Simple flat config space per function (4KB each)
    // bus 0: dev 0 = host bridge, dev 1 = GPU, dev 2 = NVMe, dev 3 = USB
    static constexpr int NUM_DEVS = 8;
    std::array<std::array<uint32_t, 1024>, NUM_DEVS> cfg_space_{};

    void init_host_bridge();
    void init_gpu();
    void init_nvme();
    void init_usb();
};

} // namespace emu::bus
