#pragma once

#include <cstdint>

namespace emu::gpu {

inline constexpr int kVgprCount = 16;

// Runs a VOP1/VOP2/EXP subset of public RDNA2 encodings.
// v_mov_b32, v_add_f32, v_mul_f32, and EXP to MRT0.
// Returns false when the blob is empty or uses an opcode outside that set.
bool exec_rdna2(const uint8_t* code, uint32_t size, float v[kVgprCount], float exported[4]);

} // namespace emu::gpu
