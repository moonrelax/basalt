#pragma once
#include <cstdint>
#include <array>
#include <functional>
#include <vector>

namespace emu::gpu {

// AMD RDNA 2 (Navi 2x family) — Xbox Series S variant: 20 CUs @ 1.565 GHz
// 4 TFLOPS FP32, DirectX 12 Ultimate feature level
// Command processor feeds the Graphics/Compute Engine via ring buffers.

// ── Register offsets (MMIO BAR0) ─────────────────────────────────────────────
constexpr uint32_t MMIO_CP_RB0_BASE_LO   = 0x0C00; // Ring buffer 0 base low
constexpr uint32_t MMIO_CP_RB0_BASE_HI   = 0x0C04; // Ring buffer 0 base high
constexpr uint32_t MMIO_CP_RB0_CNTL      = 0x0C08; // Ring buffer 0 control
constexpr uint32_t MMIO_CP_RB_RPTR       = 0x0C0C; // Read pointer
constexpr uint32_t MMIO_CP_RB_WPTR       = 0x0C10; // Write pointer (CPU writes)
constexpr uint32_t MMIO_CP_ME_CNTL       = 0x0E50; // Micro-engine control
constexpr uint32_t MMIO_GRBM_STATUS      = 0x8010; // GPU busy status
constexpr uint32_t MMIO_SRBM_STATUS      = 0x0E50;

// PM4 packet types
enum class PM4Type : uint8_t {
    TYPE0 = 0, // Write registers
    TYPE2 = 2, // NOP / filler
    TYPE3 = 3, // Opcode packets (most used)
};

// PM4 TYPE3 opcodes (subset)
enum class PM4Op : uint8_t {
    NOP              = 0x10,
    DRAW_INDEX_2     = 0x27,
    SET_CONTEXT_REG  = 0x69,
    SET_SH_REG       = 0x76,
    SET_UCONFIG_REG  = 0x79,
    INDIRECT_BUFFER  = 0x3F, // IB chaining
    EVENT_WRITE      = 0x46,
    RELEASE_MEM      = 0x49,
    WAIT_REG_MEM     = 0x3C,
    COPY_DATA        = 0x40,
    DMA_DATA         = 0x50,
};

struct RingBuffer {
    uint64_t base_addr = 0;
    uint32_t size_dw   = 0; // size in dwords
    uint32_t rptr      = 0; // read pointer (dword index)
    uint32_t wptr      = 0; // write pointer (dword index, CPU-driven)
    bool     enabled   = false;
};

class CommandProcessor {
public:
    CommandProcessor();

    // Called by MMIO write handler
    void mmio_write(uint32_t offset, uint32_t val);
    uint32_t mmio_read(uint32_t offset) const;

    // Advance read pointer, process packets
    void pump();

    // Set memory accessor (physical)
    using MemReadFn = std::function<uint32_t(uint64_t addr)>;
    void set_mem_read(MemReadFn fn) { mem_read_ = std::move(fn); }

private:
    std::array<RingBuffer, 4> rings_; // GFX, Compute x2, DMA
    std::array<uint32_t, 0x10000> regs_{}; // shadow MMIO registers

    MemReadFn mem_read_;

    void process_packet(uint32_t header, RingBuffer& rb);
    void process_type3(uint8_t op, uint32_t count, RingBuffer& rb);
    void pump_compute(int ring_idx);
    void pump_sdma();
    bool mmio_write_ext(uint32_t offset, uint32_t val);
    bool mmio_read_ext(uint32_t offset, uint32_t& out) const;

    uint32_t fetch_dw(RingBuffer& rb);
};

} // namespace emu::gpu
