#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include "cpu/cpu.h"
#include "memory/memory_map.h"
#include "memory/mmu.h"
#include "gpu/command_processor.h"
#include "hal/interrupt_controller.h"
#include "hal/timer.h"
#include "bus/pcie_bus.h"
#include "kernel/loader.h"
#include "kernel/xbox_launcher.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n"
                "  basalt --launch <game_dir> [--max-insns N] [--trace-from exe+off|0xVA]\n"
                "  basalt <boot_image>   boot PE32+ or raw binary\n");
        return 1;
    }

    // ── GDK title launch sequence ──────────────────────────────
    // Usage: basalt --launch <game_dir> [--max-insns N] [--trace-from <exe+off|0xVA>]
    if (argc >= 3 && strcmp(argv[1], "--launch") == 0) {
        emu::kernel::XboxLauncher launcher(argv[2]);
        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "--max-insns") == 0 && i + 1 < argc) {
                launcher.set_max_insns(std::strtoull(argv[++i], nullptr, 0));
            } else if (strcmp(argv[i], "--trace-from") == 0 && i + 1 < argc) {
                std::string s = argv[++i];
                uint64_t va = 0;
                if (s.rfind("exe+", 0) == 0) {
                    va = 0x140000000ULL + std::strtoull(s.c_str() + 4, nullptr, 0);
                } else {
                    va = std::strtoull(s.c_str(), nullptr, 0);
                }
                launcher.set_trace_from(va);
            }
        }
        auto result = launcher.launch();
        // Always exit 0 — the user wants to see how far we got, not an error code.
        (void)result;
        return 0;
    }

    // ── Memory ────────────────────────────────────────────────────────────────
    auto mem = std::make_unique<emu::memory::MemoryMap>();
    auto mmu = std::make_unique<emu::memory::MMU>(*mem);

    // ── GPU ───────────────────────────────────────────────────────────────────
    auto gpu = std::make_unique<emu::gpu::CommandProcessor>();
    gpu->set_mem_read([&](uint64_t addr) -> uint32_t {
        return mem->read32(addr);
    });

    emu::memory::MemoryRegion gpu_mmio{};
    gpu_mmio.base = emu::memory::XBSS_GPU_MMIO_BASE;
    gpu_mmio.size = emu::memory::XBSS_GPU_MMIO_SIZE;
    gpu_mmio.type = emu::memory::RegionType::MMIO;
    gpu_mmio.name = "RDNA2_MMIO";
    gpu_mmio.read_cb  = [&](uint64_t off, int) -> uint64_t {
        return gpu->mmio_read(static_cast<uint32_t>(off));
    };
    gpu_mmio.write_cb = [&](uint64_t off, uint64_t val, int) {
        gpu->mmio_write(static_cast<uint32_t>(off), static_cast<uint32_t>(val));
    };
    mem->add_region(std::move(gpu_mmio));

    // ── HPET ─────────────────────────────────────────────────────────────────
    auto hpet = std::make_unique<emu::hal::HPET>();
    {
        emu::memory::MemoryRegion hpet_mmio{};
        hpet_mmio.base = emu::hal::HPET::MMIO_BASE;
        hpet_mmio.size = emu::hal::HPET::MMIO_SIZE;
        hpet_mmio.type = emu::memory::RegionType::MMIO;
        hpet_mmio.name = "HPET";
        hpet_mmio.read_cb  = [&](uint64_t off, int) -> uint64_t {
            return hpet->read(off);
        };
        hpet_mmio.write_cb = [&](uint64_t off, uint64_t val, int) {
            hpet->write(off, val);
        };
        mem->add_region(std::move(hpet_mmio));
    }

    // ── PCIe ECAM ────────────────────────────────────────────────────────────
    auto pcie = std::make_unique<emu::bus::PCIeBus>();
    {
        emu::memory::MemoryRegion pcie_mmio{};
        pcie_mmio.base = emu::bus::PCIeBus::ECAM_BASE;
        pcie_mmio.size = emu::bus::PCIeBus::ECAM_SIZE;
        pcie_mmio.type = emu::memory::RegionType::MMIO;
        pcie_mmio.name = "PCIe_ECAM";
        pcie_mmio.read_cb  = [&](uint64_t addr, int sz) -> uint64_t {
            return pcie->mmio_read(emu::bus::PCIeBus::ECAM_BASE + addr, sz);
        };
        pcie_mmio.write_cb = [&](uint64_t addr, uint64_t val, int sz) {
            pcie->mmio_write(emu::bus::PCIeBus::ECAM_BASE + addr, val, sz);
        };
        mem->add_region(std::move(pcie_mmio));
    }

    // ── LAPIC (core 0) ────────────────────────────────────────────────────────
    auto lapic = std::make_unique<emu::hal::LAPIC>(0);

    // ── CPU ───────────────────────────────────────────────────────────────────
    auto cpu = std::make_unique<emu::cpu::CPU>();
    cpu->set_mem_read([&](uint64_t addr, int sz) -> uint64_t {
        switch (sz) {
            case 1: return mem->read8(addr);
            case 2: return mem->read16(addr);
            case 4: return mem->read32(addr);
            case 8: return mem->read64(addr);
            default: return 0;
        }
    });
    cpu->set_mem_write([&](uint64_t addr, uint64_t val, int sz) {
        switch (sz) {
            case 1: mem->write8(addr,  static_cast<uint8_t>(val));  break;
            case 2: mem->write16(addr, static_cast<uint16_t>(val)); break;
            case 4: mem->write32(addr, static_cast<uint32_t>(val)); break;
            case 8: mem->write64(addr, val);                        break;
        }
    });

    lapic->set_irq_handler([&](uint8_t vec) {
        cpu->raise_interrupt(vec);
    });

    // ── Load boot image ───────────────────────────────────────────────────────
    emu::kernel::Loader loader(*mem);
    auto image = loader.load_pe(argv[1]);
    if (!image) {
        if (!loader.load_raw(argv[1], 0xFFFFFFF0)) {
            fprintf(stderr, "Failed to load: %s\n", argv[1]);
            return 1;
        }
        cpu->regs().rip = 0xFFFFFFF0;
    } else {
        cpu->regs().rip = image->entry_point;
        fprintf(stdout, "Loaded %s @ 0x%016llX, entry 0x%016llX\n",
                argv[1],
                (unsigned long long)image->base_vaddr,
                (unsigned long long)image->entry_point);
    }

    // ── Main loop ─────────────────────────────────────────────────────────────
    constexpr uint64_t CYCLES_PER_TICK = 1000;
    uint64_t tick = 0;

    while (!cpu->halted()) {
        cpu->run(CYCLES_PER_TICK);
        lapic->tick(CYCLES_PER_TICK);
        hpet->tick(CYCLES_PER_TICK); // 1 tick ~ 1 ns at 3.6 GHz
        ++tick;
    }

    fprintf(stdout, "CPU halted after %llu ticks\n", (unsigned long long)tick);
    // Halt diagnostics: why execution stopped and where.
    uint64_t at = cpu->fault() ? cpu->fault_rip() : cpu->regs().rip;
    fprintf(stdout, "fault=%d mnemonic=%d rip=0x%016llX (rva 0x%llX)\n  bytes:",
            cpu->fault(), cpu->fault_mnemonic(), (unsigned long long)at,
            (unsigned long long)(image ? at - image->base_vaddr : at));
    for (int i = 0; i < 16; ++i) fprintf(stdout, " %02X", mem->read8(at + i));
    fprintf(stdout, "\n");
    return 0;
}
