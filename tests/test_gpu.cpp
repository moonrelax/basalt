#include <gtest/gtest.h>

#include "gpu/gpu.h"
#include "gpu/shader_rdna2.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using emu::gpu::CommandList;
using emu::gpu::DrawCall;
using emu::gpu::kRtHeight;
using emu::gpu::kRtWidth;
using emu::gpu::kVgprCount;

namespace {

uint32_t vop1_mov(uint32_t dst, uint32_t src9) {
    return (0x3Fu << 25) | (dst << 17) | (1u << 9) | (src9 & 0x1FFu);
}

std::vector<uint32_t> swap_rg_shader() {
    std::vector<uint32_t> code;
    code.push_back(vop1_mov(8, 256 + 3));
    code.push_back(vop1_mov(9, 256 + 2));
    code.push_back((0x3Eu << 26) | (1u << 11) | 0xFu);
    code.push_back(8u | (9u << 8) | (4u << 16) | (5u << 24));
    return code;
}

DrawCall triangle(const std::vector<uint32_t>* shader) {
    static float verts[] = {
        -0.6f, -0.6f, 1.f, 0.f, 0.f, 1.f,
         0.6f, -0.6f, 0.f, 1.f, 0.f, 1.f,
         0.0f,  0.6f, 0.f, 0.f, 1.f, 1.f,
    };
    DrawCall d;
    d.vertex_count = 3;
    d.vertices.data = reinterpret_cast<const uint8_t*>(verts);
    d.vertices.stride = 6 * sizeof(float);
    d.vertices.count = 3;
    if (shader) {
        d.rdna2.bytes = reinterpret_cast<const uint8_t*>(shader->data());
        d.rdna2.size = static_cast<uint32_t>(shader->size() * 4);
    }
    return d;
}

} // namespace

TEST(Rdna2, MovAddMulExport) {
    float v[kVgprCount] = {};
    v[1] = 0.25f;
    v[2] = 0.5f;
    const uint32_t code[] = {
        vop1_mov(0, 256 + 1),
        (1u << 25) | (3u << 17) | (2u << 9) | (256u + 0), // v_add_f32
        (5u << 25) | (4u << 17) | (3u << 9) | 242u,       // v_mul_f32 by 1.0
        (0x3Eu << 26) | (1u << 11) | 0x1u,
        4u,
    };
    emu::gpu::RdnaOut out;
    ASSERT_TRUE(emu::gpu::exec_rdna2(reinterpret_cast<const uint8_t*>(code), sizeof(code), v, out));
    EXPECT_FLOAT_EQ(v[0], 0.25f);
    EXPECT_FLOAT_EQ(v[3], 0.75f);
    EXPECT_FLOAT_EQ(v[4], 0.75f);
    EXPECT_FLOAT_EQ(out.color[0], 0.75f);
}

TEST(Rdna2, LiteralAndEndpgm) {
    float v[kVgprCount] = {};
    const uint32_t code[] = {
        (1u << 25) | (0u << 17) | (0u << 9) | 255u, // v_add_f32 v0, literal, v0
        0x3f800000u,                                 // 1.0f
        (0x17Fu << 23) | (1u << 16),                 // s_endpgm
        vop1_mov(1, 242u),
    };
    emu::gpu::RdnaOut out;
    EXPECT_FALSE(emu::gpu::exec_rdna2(reinterpret_cast<const uint8_t*>(code), sizeof(code), v, out));
    EXPECT_FLOAT_EQ(v[0], 1.f);
    EXPECT_FLOAT_EQ(v[1], 0.f);
}

TEST(Rdna2, FmaExportsPosition) {
    float v[kVgprCount] = {};
    v[0] = 2.f;
    v[1] = 3.f;
    v[2] = 0.5f;
    v[4] = 1.f;
    const uint32_t fma = (0x34u << 26) | (0x1CBu << 16) | 3u;
    const uint32_t srcs = (256u + 0) | ((256u + 1) << 9) | ((256u + 2) << 18);
    const uint32_t code[] = {
        fma, srcs,
        (0x3Eu << 26) | 0xFu | (12u << 4),
        3u | (3u << 8) | (3u << 16) | (4u << 24),
    };
    emu::gpu::RdnaOut out;
    EXPECT_FALSE(emu::gpu::exec_rdna2(reinterpret_cast<const uint8_t*>(code), sizeof(code), v, out));
    EXPECT_FLOAT_EQ(v[3], 6.5f);
    EXPECT_TRUE(out.pos_written);
    EXPECT_FLOAT_EQ(out.pos[0], 6.5f);
    EXPECT_FLOAT_EQ(out.pos[3], 1.f);
}

TEST(Raster, FlatClearIsNotPresented) {
    CommandList list;
    list.clear = true;
    list.clear_rgba[0] = 0.2f;
    list.clear_rgba[3] = 1.f;
    emu::gpu::submit(list);
    EXPECT_EQ(emu::gpu::distinct_colors(), 1u);
    EXPECT_FALSE(emu::gpu::present(0x1234));
    EXPECT_EQ(emu::gpu::last_present_va(), 0x1234u);
}

TEST(Raster, TriangleWritesVariedPixels) {
    CommandList list;
    list.clear = true;
    list.draws.push_back(triangle(nullptr));
    emu::gpu::submit(list);
    EXPECT_GE(emu::gpu::distinct_colors(), 2u);
    ASSERT_TRUE(emu::gpu::present(0));
    FILE* f = std::fopen("/tmp/basalt-present.png", "rb");
    ASSERT_NE(f, nullptr);
    uint8_t sig[8] = {};
    ASSERT_EQ(std::fread(sig, 1, 8, f), 8u);
    std::fclose(f);
    const uint8_t png[8] = {137, 80, 78, 71, 13, 10, 26, 10};
    EXPECT_EQ(std::memcmp(sig, png, 8), 0);
}

TEST(Raster, Indexed16BitTriangle) {
    static float verts[] = {
        -0.8f, -0.8f, 1.f, 0.f, 0.f, 1.f,
         0.8f, -0.8f, 0.f, 1.f, 0.f, 1.f,
         0.0f,  0.8f, 0.f, 0.f, 1.f, 1.f,
         0.2f,  0.2f, 1.f, 1.f, 0.f, 1.f,
    };
    static uint16_t idx[] = {0, 1, 2};
    DrawCall d;
    d.indexed = true;
    d.index_count = 3;
    d.index_stride = 2;
    d.index_bytes = reinterpret_cast<const uint8_t*>(idx);
    d.vertices.data = reinterpret_cast<const uint8_t*>(verts);
    d.vertices.stride = 6 * sizeof(float);
    d.vertices.count = 4;
    CommandList list;
    list.clear = true;
    list.draws.push_back(d);
    EXPECT_EQ(emu::gpu::kick(list), 3u);
    EXPECT_GE(emu::gpu::distinct_colors(), 2u);
}

TEST(Raster, ShaderSwapsRedAndGreen) {
    auto code = swap_rg_shader();
    CommandList list;
    list.clear = true;
    list.draws.push_back(triangle(&code));
    emu::gpu::submit(list);
    const int x = 294;
    const int y = 562;
    const uint8_t* p = emu::gpu::render_target() + (static_cast<uint32_t>(y) * kRtWidth + x) * 4;
    EXPECT_GT(p[1], p[0]);
    EXPECT_GT(p[1], p[2]);
    EXPECT_GE(emu::gpu::distinct_colors(), 2u);
    (void)kRtHeight;
}
