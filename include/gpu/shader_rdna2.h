#pragma once

#include <cstdint>

namespace emu::gpu {

inline constexpr int kVgprCount = 64;

// One wavefront lane of a GFX10/RDNA2 program. Color is MRT0 (EXP target 0).
// Position is the POS export (EXP target 12), still in clip space.
struct RdnaOut {
    float color[4] = {0.f, 0.f, 0.f, 1.f};
    float pos[4] = {0.f, 0.f, 0.f, 1.f};
    bool color_written = false;
    bool pos_written = false;
};

// Single-lane reference executor for the public RDNA2 encodings used by
// draws: VOP1/VOP2/VOPC/VOP3, SOP1/SOP2/SOPP (including branches and
// s_endpgm), plus the 32-bit literal that follows a source of 255.
// SMEM/DS/MIMG/FLAT are skipped; they need a bound descriptor the HLE
// side does not have yet. Returns true when MRT0 was exported.
bool exec_rdna2(const uint8_t* code, uint32_t size, float v[kVgprCount], RdnaOut& out);

} // namespace emu::gpu
