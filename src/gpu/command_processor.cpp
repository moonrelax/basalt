#include "gpu/command_processor.h"
#include <stdexcept>

namespace emu::gpu {

CommandProcessor::CommandProcessor() {
    regs_.fill(0);
}

uint32_t CommandProcessor::fetch_dw(RingBuffer& rb) {
    if (!mem_read_) return 0;
    uint32_t val = mem_read_(rb.base_addr + rb.rptr * 4);
    rb.rptr = (rb.rptr + 1) % rb.size_dw;
    return val;
}

void CommandProcessor::mmio_write(uint32_t offset, uint32_t val) {
    if (mmio_write_ext(offset, val)) return;
    uint32_t idx = (offset & 0xFFFF) / 4;
    if (idx < regs_.size()) regs_[idx] = val;

    switch (offset) {
        case MMIO_CP_RB0_BASE_LO:
            rings_[0].base_addr = (rings_[0].base_addr & 0xFFFFFFFF00000000ULL) | val;
            break;
        case MMIO_CP_RB0_BASE_HI:
            rings_[0].base_addr = (rings_[0].base_addr & 0x00000000FFFFFFFFULL) | ((uint64_t)val << 32);
            break;
        case MMIO_CP_RB0_CNTL:
            rings_[0].size_dw = 1u << ((val & 0x3F) + 1);
            rings_[0].enabled = !!(val & (1 << 28));
            break;
        case MMIO_CP_RB_WPTR:
            rings_[0].wptr = val;
            pump(); // CPU updated write pointer — process new packets
            break;
        default:
            break;
    }
}

uint32_t CommandProcessor::mmio_read(uint32_t offset) const {
    uint32_t ext_val = 0;
    if (mmio_read_ext(offset, ext_val)) return ext_val;
    switch (offset) {
        case MMIO_CP_RB_RPTR:   return rings_[0].rptr;
        case MMIO_GRBM_STATUS:  return 0;
        default: {
            uint32_t idx = (offset & 0xFFFF) / 4;
            return (idx < regs_.size()) ? regs_[idx] : 0;
        }
    }
}

void CommandProcessor::pump() {
    RingBuffer& rb = rings_[0];
    if (!rb.enabled || !mem_read_) return;

    while (rb.rptr != rb.wptr) {
        uint32_t header = fetch_dw(rb);
        process_packet(header, rb);
    }
}

void CommandProcessor::process_packet(uint32_t header, RingBuffer& rb) {
    uint8_t type = (header >> 30) & 0x3;

    switch (static_cast<PM4Type>(type)) {
        case PM4Type::TYPE0: {
            uint16_t base_reg = header & 0x7FFF;
            uint16_t count    = ((header >> 16) & 0x3FFF) + 1;
            for (uint16_t i = 0; i < count; ++i) {
                uint32_t val = fetch_dw(rb);
                uint32_t reg = base_reg + i;
                if (reg < regs_.size()) regs_[reg] = val;
            }
            break;
        }
        case PM4Type::TYPE2:
            break; // NOP filler

        case PM4Type::TYPE3: {
            uint8_t  op    = (header >> 8) & 0xFF;
            uint32_t count = (header & 0x3FFF) + 1; // dword payload count
            process_type3(op, count, rb);
            break;
        }
        default:
            // Drain unknown packet (assume count in [15:16])
            break;
    }
}

void CommandProcessor::process_type3(uint8_t op, uint32_t count, RingBuffer& rb) {
    switch (static_cast<PM4Op>(op)) {
        case PM4Op::NOP:
            for (uint32_t i = 0; i < count; ++i) fetch_dw(rb);
            break;

        case PM4Op::SET_CONTEXT_REG: {
            uint32_t offset = fetch_dw(rb); // register offset from CONTEXT_REG_BASE
            for (uint32_t i = 1; i < count; ++i) {
                uint32_t val = fetch_dw(rb);
                uint32_t reg = 0xA000 + offset + (i - 1);
                if (reg < regs_.size()) regs_[reg] = val;
            }
            break;
        }

        case PM4Op::SET_SH_REG: {
            uint32_t offset = fetch_dw(rb);
            for (uint32_t i = 1; i < count; ++i) {
                uint32_t val = fetch_dw(rb);
                uint32_t reg = 0x2C00 + offset + (i - 1);
                if (reg < regs_.size()) regs_[reg] = val;
            }
            break;
        }

        case PM4Op::INDIRECT_BUFFER: {
            fetch_dw(rb); // IB_BASE_LO
            fetch_dw(rb); // IB_BASE_HI
            fetch_dw(rb); // IB_SIZE | flags
            // TODO: recursive IB processing
            break;
        }

        default:
            // Drain unimplemented packet
            for (uint32_t i = 0; i < count; ++i) fetch_dw(rb);
            break;
    }
}

} // namespace emu::gpu
