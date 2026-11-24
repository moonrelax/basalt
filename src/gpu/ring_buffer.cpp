#include "gpu/command_processor.h"

// Compute engine (MEC) rings and SDMA ring dispatch.
// rings_[0] = GFX (handled in command_processor.cpp)
// rings_[1] = Compute ring 0
// rings_[2] = Compute ring 1
// rings_[3] = SDMA ring 0

namespace emu::gpu {

// ── MMIO offsets for MEC/Compute rings ────────────────────────────────────────
static constexpr uint32_t MMIO_MEC_RB0_BASE_LO = 0x0C40;
static constexpr uint32_t MMIO_MEC_RB0_BASE_HI  = 0x0C44;
static constexpr uint32_t MMIO_MEC_RB0_CNTL     = 0x0C48;
static constexpr uint32_t MMIO_MEC_RB0_RPTR     = 0x0C4C;
static constexpr uint32_t MMIO_MEC_RB0_WPTR     = 0x0C50;

static constexpr uint32_t MMIO_MEC_RB1_BASE_LO  = 0x0C60;
static constexpr uint32_t MMIO_MEC_RB1_BASE_HI  = 0x0C64;
static constexpr uint32_t MMIO_MEC_RB1_CNTL     = 0x0C68;
static constexpr uint32_t MMIO_MEC_RB1_RPTR     = 0x0C6C;
static constexpr uint32_t MMIO_MEC_RB1_WPTR     = 0x0C70;

// ── SDMA ring ─────────────────────────────────────────────────────────────────
static constexpr uint32_t MMIO_SDMA_RB_BASE_LO  = 0x0D00;
static constexpr uint32_t MMIO_SDMA_RB_BASE_HI  = 0x0D04;
static constexpr uint32_t MMIO_SDMA_RB_CNTL     = 0x0D08;
static constexpr uint32_t MMIO_SDMA_RB_RPTR     = 0x0D0C;
static constexpr uint32_t MMIO_SDMA_RB_WPTR     = 0x0D10;

// SDMA packet opcodes
enum class SDMAOp : uint8_t {
    NOP          = 0x00,
    COPY         = 0x01,
    FENCE        = 0x05,
    TRAP         = 0x06,
    POLL_REGMEM  = 0x08,
    TIMESTAMP    = 0x0D,
};

// ── Additional MMIO routing (called from mmio_write/mmio_read) ────────────────

bool CommandProcessor::mmio_write_ext(uint32_t offset, uint32_t val) {
    switch (offset) {
        // Compute ring 0
        case MMIO_MEC_RB0_BASE_LO:
            rings_[1].base_addr = (rings_[1].base_addr & 0xFFFFFFFF00000000ULL) | val;
            return true;
        case MMIO_MEC_RB0_BASE_HI:
            rings_[1].base_addr = (rings_[1].base_addr & 0x00000000FFFFFFFFULL) | ((uint64_t)val << 32);
            return true;
        case MMIO_MEC_RB0_CNTL:
            rings_[1].size_dw = 1u << ((val & 0x3F) + 1);
            rings_[1].enabled = !!(val & (1 << 28));
            return true;
        case MMIO_MEC_RB0_WPTR:
            rings_[1].wptr = val;
            pump_compute(1);
            return true;

        // Compute ring 1
        case MMIO_MEC_RB1_BASE_LO:
            rings_[2].base_addr = (rings_[2].base_addr & 0xFFFFFFFF00000000ULL) | val;
            return true;
        case MMIO_MEC_RB1_BASE_HI:
            rings_[2].base_addr = (rings_[2].base_addr & 0x00000000FFFFFFFFULL) | ((uint64_t)val << 32);
            return true;
        case MMIO_MEC_RB1_CNTL:
            rings_[2].size_dw = 1u << ((val & 0x3F) + 1);
            rings_[2].enabled = !!(val & (1 << 28));
            return true;
        case MMIO_MEC_RB1_WPTR:
            rings_[2].wptr = val;
            pump_compute(2);
            return true;

        // SDMA ring
        case MMIO_SDMA_RB_BASE_LO:
            rings_[3].base_addr = (rings_[3].base_addr & 0xFFFFFFFF00000000ULL) | val;
            return true;
        case MMIO_SDMA_RB_BASE_HI:
            rings_[3].base_addr = (rings_[3].base_addr & 0x00000000FFFFFFFFULL) | ((uint64_t)val << 32);
            return true;
        case MMIO_SDMA_RB_CNTL:
            rings_[3].size_dw = 1u << ((val & 0x3F) + 1);
            rings_[3].enabled = !!(val & (1 << 0));
            return true;
        case MMIO_SDMA_RB_WPTR:
            rings_[3].wptr = val;
            pump_sdma();
            return true;

        default:
            return false;
    }
}

bool CommandProcessor::mmio_read_ext(uint32_t offset, uint32_t& out) const {
    switch (offset) {
        case MMIO_MEC_RB0_RPTR: out = rings_[1].rptr; return true;
        case MMIO_MEC_RB1_RPTR: out = rings_[2].rptr; return true;
        case MMIO_SDMA_RB_RPTR: out = rings_[3].rptr; return true;
        default: return false;
    }
}

// ── Compute ring pump (PM4 packet format, same as GFX) ───────────────────────

void CommandProcessor::pump_compute(int ring_idx) {
    if (ring_idx < 1 || ring_idx > 2) return;
    RingBuffer& rb = rings_[ring_idx];
    if (!rb.enabled || !mem_read_) return;

    while (rb.rptr != rb.wptr) {
        uint32_t header = fetch_dw(rb);
        process_packet(header, rb);
    }
}

// ── SDMA ring pump ────────────────────────────────────────────────────────────

void CommandProcessor::pump_sdma() {
    RingBuffer& rb = rings_[3];
    if (!rb.enabled || !mem_read_) return;

    while (rb.rptr != rb.wptr) {
        uint32_t header = fetch_dw(rb);
        uint8_t  op     = header & 0xFF;
        uint8_t  subop  = (header >> 8) & 0xFF;
        (void)subop;

        switch (static_cast<SDMAOp>(op)) {
            case SDMAOp::NOP:
                break;

            case SDMAOp::COPY: {
                // LINEAR copy: src_addr_lo, src_addr_hi, dst_addr_lo, dst_addr_hi, count
                uint32_t count      = fetch_dw(rb); // byte count
                uint32_t src_lo     = fetch_dw(rb);
                uint32_t src_hi     = fetch_dw(rb);
                uint32_t dst_lo     = fetch_dw(rb);
                uint32_t dst_hi     = fetch_dw(rb);
                uint64_t src        = ((uint64_t)src_hi << 32) | src_lo;
                uint64_t dst        = ((uint64_t)dst_hi << 32) | dst_lo;
                (void)src; (void)dst; (void)count;
                // Actual memory-to-memory copy would call mem_write_ here;
                // stub until MemWriteFn is wired.
                break;
            }

            case SDMAOp::FENCE: {
                uint32_t addr_lo = fetch_dw(rb);
                uint32_t addr_hi = fetch_dw(rb);
                uint32_t data    = fetch_dw(rb);
                (void)addr_lo; (void)addr_hi; (void)data;
                // Write fence value to memory — stub until MemWriteFn is wired.
                break;
            }

            case SDMAOp::TRAP:
                fetch_dw(rb); // trap context
                break;

            case SDMAOp::POLL_REGMEM:
                // Poll memory location: addr_lo, addr_hi, ref, mask, poll_interval, retry_count
                for (int i = 0; i < 6; ++i) fetch_dw(rb);
                break;

            case SDMAOp::TIMESTAMP:
                fetch_dw(rb); // addr_lo
                fetch_dw(rb); // addr_hi
                break;

            default:
                // Unknown opcode — drain one word and hope to resync
                break;
        }
    }
}

} // namespace emu::gpu
