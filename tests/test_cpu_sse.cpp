#include <gtest/gtest.h>
#include <array>
#include <bit>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "cpu/cpu.h"
#include "cpu/mnemonic_names.h"

namespace {

using namespace emu::cpu;

constexpr uint64_t CODE_BASE = 0x1000;
constexpr uint64_t DATA_BASE = 0x4000;
constexpr size_t   MEM_SIZE  = 0x10000;

constexpr uint64_t FLAG_CF = 1ULL << 0;
constexpr uint64_t FLAG_PF = 1ULL << 2;
constexpr uint64_t FLAG_AF = 1ULL << 4;
constexpr uint64_t FLAG_ZF = 1ULL << 6;
constexpr uint64_t FLAG_SF = 1ULL << 7;
constexpr uint64_t FLAG_OF = 1ULL << 11;

struct MemAccess {
    uint64_t addr;
    int      size;
};

class CPUSSETest : public ::testing::Test {
protected:
    std::array<uint8_t, MEM_SIZE> mem{};
    std::vector<MemAccess>        data_reads;
    std::vector<MemAccess>        data_writes;
    CPU                           cpu;

    void SetUp() override {
        mem.fill(0);
        data_reads.clear();
        data_writes.clear();
        cpu.reset();
        cpu.set_mem_read([this](uint64_t addr, int sz) -> uint64_t {
            if (addr >= DATA_BASE) {
                data_reads.push_back({addr, sz});
            }
            if (addr + static_cast<uint64_t>(sz) > mem.size()) {
                return 0xDEADBEEFDEADBEEFULL;
            }
            uint64_t val = 0;
            std::memcpy(&val, mem.data() + addr, static_cast<size_t>(sz));
            return val;
        });
        cpu.set_mem_write([this](uint64_t addr, uint64_t val, int sz) {
            if (addr >= DATA_BASE) {
                data_writes.push_back({addr, sz});
            }
            if (addr + static_cast<uint64_t>(sz) > mem.size()) {
                return;
            }
            std::memcpy(mem.data() + addr, &val, static_cast<size_t>(sz));
        });
    }

    size_t load_code(std::initializer_list<uint8_t> bytes, uint64_t addr = CODE_BASE) {
        uint64_t a = addr;
        for (uint8_t b : bytes) {
            mem[a++] = b;
        }
        cpu.regs().rip = addr;
        return bytes.size();
    }

    void write_mem32(uint64_t addr, uint32_t v) {
        std::memcpy(mem.data() + addr, &v, sizeof(v));
    }

    void write_mem_f32(uint64_t addr, float f) {
        write_mem32(addr, std::bit_cast<uint32_t>(f));
    }

    void step_and_expect_ok(size_t expected_len, uint64_t start_rip = CODE_BASE) {
        cpu.step();
        ASSERT_EQ(cpu.fault(), 0)
            << "CPU faulted: fault=" << cpu.fault()
            << " (" << (cpu.fault() == 1 ? "undecodable" : "unimplemented") << ")"
            << " mnemonic=" << cpu.fault_mnemonic()
            << " rip=0x" << std::hex << cpu.fault_rip();
        ASSERT_FALSE(cpu.halted());
        EXPECT_EQ(cpu.regs().rip, start_rip + expected_len);
    }
};

#define STEP_EXPECT_OK(len) ASSERT_NO_FATAL_FAILURE(step_and_expect_ok(len))

// ── 1. C5 C8 57 F6 : vxorps xmm6, xmm6, xmm6 ────────────────────────────────
// Must zero both xmm6 (ymm6.lo) and the upper 128 bits (ymm6.hi).
TEST_F(CPUSSETest, VXORPS_Xmm6_ZeroesLowAndHigh) {
    auto& r = cpu.regs();
    r.ymm[6].lo.q[0] = 0x1122334455667788ULL;
    r.ymm[6].lo.q[1] = 0x99AABBCCDDEEFF00ULL;
    r.ymm[6].hi.q[0] = 0xCAFEBABEDEADBEEFULL;
    r.ymm[6].hi.q[1] = 0xFEEDFACE01234567ULL;
    // Canary in neighboring register
    r.ymm[5].lo.q[0] = 0xAAAAAAAAAAAAAAAAULL;
    r.ymm[5].hi.q[0] = 0x5555555555555555ULL;

    size_t len = load_code({0xC5, 0xC8, 0x57, 0xF6});
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.ymm[6].lo.q[0], 0ULL);
    EXPECT_EQ(r.ymm[6].lo.q[1], 0ULL);
    EXPECT_EQ(r.ymm[6].hi.q[0], 0ULL);
    EXPECT_EQ(r.ymm[6].hi.q[1], 0ULL);
    EXPECT_EQ(r.ymm[5].lo.q[0], 0xAAAAAAAAAAAAAAAAULL);
    EXPECT_EQ(r.ymm[5].hi.q[0], 0x5555555555555555ULL);
}

// ── 2. Legacy SSE bitwise: xorps, xorpd, andps, andnps, orps ────────────────
// Hand-computed patterns (a = xmm0, b = xmm1):
//   a0 = 0xF0F0F0F012345678, b0 = 0x00FF00FF87654321
//   a1 = 0xAAAA55550F0F0F0F, b1 = 0x3333CCCCFF0000FF
// Legacy SSE instructions MUST preserve ymm0.hi.
constexpr uint64_t BIT_A0  = 0xF0F0F0F012345678ULL;
constexpr uint64_t BIT_A1  = 0xAAAA55550F0F0F0FULL;
constexpr uint64_t BIT_B0  = 0x00FF00FF87654321ULL;
constexpr uint64_t BIT_B1  = 0x3333CCCCFF0000FFULL;
constexpr uint64_t BIT_HI0 = 0x123456789ABCDEF0ULL;
constexpr uint64_t BIT_HI1 = 0x0FEDCBA987654321ULL;

TEST_F(CPUSSETest, XORPS_0F57C1) {
    auto& r = cpu.regs();
    r.ymm[0].lo.q[0] = BIT_A0; r.ymm[0].lo.q[1] = BIT_A1;
    r.ymm[0].hi.q[0] = BIT_HI0; r.ymm[0].hi.q[1] = BIT_HI1;
    r.ymm[1].lo.q[0] = BIT_B0; r.ymm[1].lo.q[1] = BIT_B1;

    size_t len = load_code({0x0F, 0x57, 0xC1}); // xorps xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.ymm[0].lo.q[0], 0xF00FF00F95511559ULL);
    EXPECT_EQ(r.ymm[0].lo.q[1], 0x99999999F00F0FF0ULL);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);
    EXPECT_EQ(r.ymm[0].hi.q[1], BIT_HI1);
    EXPECT_EQ(r.ymm[1].lo.q[0], BIT_B0);
    EXPECT_EQ(r.ymm[1].lo.q[1], BIT_B1);
}

TEST_F(CPUSSETest, XORPD_660F57C1) {
    auto& r = cpu.regs();
    r.ymm[0].lo.q[0] = BIT_A0; r.ymm[0].lo.q[1] = BIT_A1;
    r.ymm[0].hi.q[0] = BIT_HI0; r.ymm[0].hi.q[1] = BIT_HI1;
    r.ymm[1].lo.q[0] = BIT_B0; r.ymm[1].lo.q[1] = BIT_B1;

    size_t len = load_code({0x66, 0x0F, 0x57, 0xC1}); // xorpd xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.ymm[0].lo.q[0], 0xF00FF00F95511559ULL);
    EXPECT_EQ(r.ymm[0].lo.q[1], 0x99999999F00F0FF0ULL);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);
    EXPECT_EQ(r.ymm[0].hi.q[1], BIT_HI1);
}

TEST_F(CPUSSETest, ANDPS_0F54C1) {
    auto& r = cpu.regs();
    r.ymm[0].lo.q[0] = BIT_A0; r.ymm[0].lo.q[1] = BIT_A1;
    r.ymm[0].hi.q[0] = BIT_HI0; r.ymm[0].hi.q[1] = BIT_HI1;
    r.ymm[1].lo.q[0] = BIT_B0; r.ymm[1].lo.q[1] = BIT_B1;

    size_t len = load_code({0x0F, 0x54, 0xC1}); // andps xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.ymm[0].lo.q[0], 0x00F000F002244220ULL);
    EXPECT_EQ(r.ymm[0].lo.q[1], 0x222244440F00000FULL);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);
    EXPECT_EQ(r.ymm[0].hi.q[1], BIT_HI1);
}

TEST_F(CPUSSETest, ANDNPS_0F55C1) {
    // ANDNPS dst, src computes (~dst) & src (asymmetric!)
    auto& r = cpu.regs();
    r.ymm[0].lo.q[0] = BIT_A0; r.ymm[0].lo.q[1] = BIT_A1;
    r.ymm[0].hi.q[0] = BIT_HI0; r.ymm[0].hi.q[1] = BIT_HI1;
    r.ymm[1].lo.q[0] = BIT_B0; r.ymm[1].lo.q[1] = BIT_B1;

    size_t len = load_code({0x0F, 0x55, 0xC1}); // andnps xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.ymm[0].lo.q[0], 0x000F000F85410101ULL);
    EXPECT_EQ(r.ymm[0].lo.q[1], 0x11118888F00000F0ULL);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);
    EXPECT_EQ(r.ymm[0].hi.q[1], BIT_HI1);
}

TEST_F(CPUSSETest, ORPS_0F56C1) {
    auto& r = cpu.regs();
    r.ymm[0].lo.q[0] = BIT_A0; r.ymm[0].lo.q[1] = BIT_A1;
    r.ymm[0].hi.q[0] = BIT_HI0; r.ymm[0].hi.q[1] = BIT_HI1;
    r.ymm[1].lo.q[0] = BIT_B0; r.ymm[1].lo.q[1] = BIT_B1;

    size_t len = load_code({0x0F, 0x56, 0xC1}); // orps xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.ymm[0].lo.q[0], 0xF0FFF0FF97755779ULL);
    EXPECT_EQ(r.ymm[0].lo.q[1], 0xBBBBDDDDFF0F0FFFULL);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);
    EXPECT_EQ(r.ymm[0].hi.q[1], BIT_HI1);
}

// ── 3. Scalar FP: addss, mulsd, minss, maxss, sqrtsd ────────────────────────
TEST_F(CPUSSETest, ADDSS_Reg_F30F58C1) {
    auto& r = cpu.regs();
    r.ymm[0].lo.f[0] = 1.5f;  r.ymm[0].lo.f[1] = 10.0f;
    r.ymm[0].lo.f[2] = 20.0f; r.ymm[0].lo.f[3] = 30.0f;
    r.ymm[0].hi.q[0] = BIT_HI0; r.ymm[0].hi.q[1] = BIT_HI1;
    r.ymm[1].lo.f[0] = 2.25f; r.ymm[1].lo.f[1] = 99.0f;
    r.ymm[1].lo.f[2] = 88.0f; r.ymm[1].lo.f[3] = 77.0f;

    size_t len = load_code({0xF3, 0x0F, 0x58, 0xC1}); // addss xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 3.75f);
    // Upper scalar lanes and YMM high half must be preserved
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[1], 10.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[2], 20.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[3], 30.0f);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);
    EXPECT_EQ(r.ymm[0].hi.q[1], BIT_HI1);
}

TEST_F(CPUSSETest, MULSD_Reg_F20F59C1) {
    auto& r = cpu.regs();
    r.ymm[0].lo.df[0] = -3.5; r.ymm[0].lo.df[1] = 42.0;
    r.ymm[0].hi.q[0]  = BIT_HI0; r.ymm[0].hi.q[1] = BIT_HI1;
    r.ymm[1].lo.df[0] = 2.5;  r.ymm[1].lo.df[1] = 99.0;

    size_t len = load_code({0xF2, 0x0F, 0x59, 0xC1}); // mulsd xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_DOUBLE_EQ(r.ymm[0].lo.df[0], -8.75);
    EXPECT_DOUBLE_EQ(r.ymm[0].lo.df[1], 42.0);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);
    EXPECT_EQ(r.ymm[0].hi.q[1], BIT_HI1);
}

TEST_F(CPUSSETest, MINSS_Reg_F30F5DC1) {
    auto& r = cpu.regs();
    // Case 1: src < dst
    r.ymm[0].lo.f[0] = 5.5f;  r.ymm[0].lo.f[1] = 11.0f;
    r.ymm[0].lo.f[2] = 22.0f; r.ymm[0].lo.f[3] = 33.0f;
    r.ymm[0].hi.q[0] = BIT_HI0;
    r.ymm[1].lo.f[0] = -2.25f;

    size_t len = load_code({0xF3, 0x0F, 0x5D, 0xC1}); // minss xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], -2.25f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[1], 11.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[2], 22.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[3], 33.0f);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);

    // Case 2: dst < src
    r.ymm[0].lo.f[0] = -4.0f;
    r.ymm[1].lo.f[0] = 3.0f;
    r.rip = CODE_BASE;
    STEP_EXPECT_OK(len);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], -4.0f);
}

TEST_F(CPUSSETest, MAXSS_Reg_F30F5FC1) {
    auto& r = cpu.regs();
    // Case 1: src > dst
    r.ymm[0].lo.f[0] = -2.25f; r.ymm[0].lo.f[1] = 11.0f;
    r.ymm[0].lo.f[2] = 22.0f;  r.ymm[0].lo.f[3] = 33.0f;
    r.ymm[0].hi.q[0] = BIT_HI0;
    r.ymm[1].lo.f[0] = 5.5f;

    size_t len = load_code({0xF3, 0x0F, 0x5F, 0xC1}); // maxss xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 5.5f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[1], 11.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[2], 22.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[3], 33.0f);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);

    // Case 2: dst > src
    r.ymm[0].lo.f[0] = 7.25f;
    r.ymm[1].lo.f[0] = 3.0f;
    r.rip = CODE_BASE;
    STEP_EXPECT_OK(len);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 7.25f);
}

TEST_F(CPUSSETest, SQRTSD_Reg_F20F51C1) {
    auto& r = cpu.regs();
    r.ymm[0].lo.df[0] = 999.0; r.ymm[0].lo.df[1] = 123.5;
    r.ymm[0].hi.q[0]  = BIT_HI0; r.ymm[0].hi.q[1] = BIT_HI1;
    r.ymm[1].lo.df[0] = 6.25;  r.ymm[1].lo.df[1] = 400.0;

    size_t len = load_code({0xF2, 0x0F, 0x51, 0xC1}); // sqrtsd xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_DOUBLE_EQ(r.ymm[0].lo.df[0], 2.5);
    EXPECT_DOUBLE_EQ(r.ymm[0].lo.df[1], 123.5);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);
    EXPECT_EQ(r.ymm[0].hi.q[1], BIT_HI1);
}

// ── 4. F3 0F 58 01 : addss xmm0, dword ptr [rcx] (4 bytes read, not 16) ────
TEST_F(CPUSSETest, ADDSS_Mem_F30F5801_ReadsOnly4Bytes) {
    auto& r = cpu.regs();
    r.rcx            = DATA_BASE;
    r.ymm[0].lo.f[0] = 1.25f;
    r.ymm[0].lo.f[1] = 11.0f;
    r.ymm[0].lo.f[2] = 22.0f;
    r.ymm[0].lo.f[3] = 33.0f;
    r.ymm[0].hi.q[0] = BIT_HI0;

    write_mem_f32(DATA_BASE, 2.5f);
    // Poison bytes 4..15 to detect accidental 16-byte loads
    for (uint64_t off = 4; off < 16; ++off) {
        mem[DATA_BASE + off] = 0xCC;
    }

    size_t len = load_code({0xF3, 0x0F, 0x58, 0x01}); // addss xmm0, [rcx]
    STEP_EXPECT_OK(len);

    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 3.75f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[1], 11.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[2], 22.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[3], 33.0f);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);

    // Verify memory read width: strictly 4 bytes at [DATA_BASE, DATA_BASE + 4)
    ASSERT_FALSE(data_reads.empty()) << "Expected a memory read from [rcx]";
    int      total_bytes = 0;
    uint64_t min_addr    = UINT64_MAX;
    uint64_t max_end     = 0;
    for (const auto& acc : data_reads) {
        total_bytes += acc.size;
        if (acc.addr < min_addr) min_addr = acc.addr;
        if (acc.addr + static_cast<uint64_t>(acc.size) > max_end) {
            max_end = acc.addr + static_cast<uint64_t>(acc.size);
        }
    }
    EXPECT_EQ(total_bytes, 4) << "addss [rcx] must read 4 bytes, not 16";
    EXPECT_EQ(min_addr, DATA_BASE);
    EXPECT_LE(max_end, DATA_BASE + 4) << "addss [rcx] touched bytes past offset +4";
}

// ── 5. 0F 2E C1 : ucomiss xmm0, xmm1 (equal, less, greater, NaN) ────────────
TEST_F(CPUSSETest, UCOMISS_Equal) {
    auto& r = cpu.regs();
    r.ymm[0].lo.f[0] = 3.5f;
    r.ymm[1].lo.f[0] = 3.5f;
    // Pre-set flags to opposite/dirty state to ensure UCOMISS writes all 6
    r.rflags = 0x2 | FLAG_CF | FLAG_PF | FLAG_AF | FLAG_SF | FLAG_OF;

    size_t len = load_code({0x0F, 0x2E, 0xC1}); // ucomiss xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_NE(r.rflags & FLAG_ZF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_PF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_CF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_OF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_SF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_AF, 0ULL);
}

TEST_F(CPUSSETest, UCOMISS_Less) {
    auto& r = cpu.regs();
    r.ymm[0].lo.f[0] = 1.0f;
    r.ymm[1].lo.f[0] = 2.0f;
    r.rflags = 0x2 | FLAG_ZF | FLAG_PF | FLAG_AF | FLAG_SF | FLAG_OF;

    size_t len = load_code({0x0F, 0x2E, 0xC1});
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.rflags & FLAG_ZF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_PF, 0ULL);
    EXPECT_NE(r.rflags & FLAG_CF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_OF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_SF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_AF, 0ULL);
}

TEST_F(CPUSSETest, UCOMISS_Greater) {
    auto& r = cpu.regs();
    r.ymm[0].lo.f[0] = 5.0f;
    r.ymm[1].lo.f[0] = 2.0f;
    r.rflags = 0x2 | FLAG_CF | FLAG_ZF | FLAG_PF | FLAG_AF | FLAG_SF | FLAG_OF;

    size_t len = load_code({0x0F, 0x2E, 0xC1});
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.rflags & FLAG_ZF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_PF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_CF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_OF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_SF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_AF, 0ULL);
}

TEST_F(CPUSSETest, UCOMISS_NaN) {
    auto& r = cpu.regs();
    r.ymm[0].lo.f[0] = std::numeric_limits<float>::quiet_NaN();
    r.ymm[1].lo.f[0] = 1.0f;
    r.rflags = 0x2 | FLAG_AF | FLAG_SF | FLAG_OF;

    size_t len = load_code({0x0F, 0x2E, 0xC1});
    STEP_EXPECT_OK(len);

    EXPECT_NE(r.rflags & FLAG_ZF, 0ULL);
    EXPECT_NE(r.rflags & FLAG_PF, 0ULL);
    EXPECT_NE(r.rflags & FLAG_CF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_OF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_SF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_AF, 0ULL);
}

// ── 6. Conversions: cvttss2si, cvtdq2ps, cvtps2dq ───────────────────────────
TEST_F(CPUSSETest, CVTTSS2SI_F30F2CC1) {
    auto& r = cpu.regs();
    // Positive fractional: 42.9f truncates toward zero to 42; 32-bit dest zero-extends rax
    r.rax            = 0xFFFFFFFF12345678ULL;
    r.ymm[1].lo.f[0] = 42.9f;

    size_t len = load_code({0xF3, 0x0F, 0x2C, 0xC1}); // cvttss2si eax, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.rax, 42ULL);

    // Negative fractional: -7.9f truncates toward zero to -7 (0xFFFFFFF9 zero-extended)
    r.rax            = 0x1234567800000000ULL;
    r.ymm[1].lo.f[0] = -7.9f;
    r.rip            = CODE_BASE;
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.rax, 0x00000000FFFFFFF9ULL);
}

TEST_F(CPUSSETest, CVTDQ2PS_0F5BC1) {
    auto& r = cpu.regs();
    r.ymm[0].hi.q[0] = BIT_HI0;
    r.ymm[0].hi.q[1] = BIT_HI1;
    r.ymm[1].lo.d[0] = 0u;
    r.ymm[1].lo.d[1] = 1u;
    r.ymm[1].lo.d[2] = static_cast<uint32_t>(-42);
    r.ymm[1].lo.d[3] = 1000u;

    size_t len = load_code({0x0F, 0x5B, 0xC1}); // cvtdq2ps xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 0.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[1], 1.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[2], -42.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[3], 1000.0f);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);
    EXPECT_EQ(r.ymm[0].hi.q[1], BIT_HI1);
}

TEST_F(CPUSSETest, CVTPS2DQ_660F5BC1) {
    auto& r = cpu.regs();
    r.ymm[0].hi.q[0] = BIT_HI0;
    r.ymm[0].hi.q[1] = BIT_HI1;
    // Default MXCSR rounding is round-to-nearest-even:
    //   1.25 -> 1, 2.5 -> 2 (even), 3.5 -> 4 (even), -4.75 -> -5
    r.ymm[1].lo.f[0] = 1.25f;
    r.ymm[1].lo.f[1] = 2.5f;
    r.ymm[1].lo.f[2] = 3.5f;
    r.ymm[1].lo.f[3] = -4.75f;

    size_t len = load_code({0x66, 0x0F, 0x5B, 0xC1}); // cvtps2dq xmm0, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_EQ(static_cast<int32_t>(r.ymm[0].lo.d[0]), 1);
    EXPECT_EQ(static_cast<int32_t>(r.ymm[0].lo.d[1]), 2);
    EXPECT_EQ(static_cast<int32_t>(r.ymm[0].lo.d[2]), 4);
    EXPECT_EQ(static_cast<int32_t>(r.ymm[0].lo.d[3]), -5);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);
    EXPECT_EQ(r.ymm[0].hi.q[1], BIT_HI1);
}

// ── 7. 0F C6 C1 1B shufps, 0F 50 C1 movmskps ────────────────────────────────
TEST_F(CPUSSETest, SHUFPS_0FC6C11B) {
    // imm8 = 0x1B = 0b00_01_10_11:
    //   dst[0] = src1[3], dst[1] = src1[2], dst[2] = src2[1], dst[3] = src2[0]
    auto& r = cpu.regs();
    r.ymm[0].lo.f[0] = 10.0f;  r.ymm[0].lo.f[1] = 20.0f;
    r.ymm[0].lo.f[2] = 30.0f;  r.ymm[0].lo.f[3] = 40.0f;
    r.ymm[0].hi.q[0] = BIT_HI0; r.ymm[0].hi.q[1] = BIT_HI1;
    r.ymm[1].lo.f[0] = 100.0f; r.ymm[1].lo.f[1] = 200.0f;
    r.ymm[1].lo.f[2] = 300.0f; r.ymm[1].lo.f[3] = 400.0f;

    size_t len = load_code({0x0F, 0xC6, 0xC1, 0x1B}); // shufps xmm0, xmm1, 0x1B
    STEP_EXPECT_OK(len);

    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 40.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[1], 30.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[2], 200.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[3], 100.0f);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);
    EXPECT_EQ(r.ymm[0].hi.q[1], BIT_HI1);
}

TEST_F(CPUSSETest, MOVMSKPS_0F50C1) {
    // Extracts sign bit (bit 31) of each float lane in xmm1 into bits 3:0 of eax (zero-extended)
    auto& r = cpu.regs();
    r.rax            = 0xFFFFFFFFFFFFFFFFULL;
    r.ymm[1].lo.d[0] = 0xBF800000u; // -1.0f (sign = 1) -> bit 0
    r.ymm[1].lo.d[1] = 0x40000000u; // +2.0f (sign = 0) -> bit 1
    r.ymm[1].lo.d[2] = 0x80000000u; // -0.0f (sign = 1) -> bit 2
    r.ymm[1].lo.d[3] = 0x00000000u; // +0.0f (sign = 0) -> bit 3

    size_t len = load_code({0x0F, 0x50, 0xC1}); // movmskps eax, xmm1
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.rax, 0x5ULL); // 0b0101
}

// ── 8. C5 FC 77 vzeroall, C5 F8 77 vzeroupper ───────────────────────────────
TEST_F(CPUSSETest, VZEROALL_C5FC77) {
    auto& r = cpu.regs();
    for (int i = 0; i < 16; ++i) {
        r.ymm[i].lo.q[0] = 0x1000ULL + static_cast<uint64_t>(i);
        r.ymm[i].lo.q[1] = 0x2000ULL + static_cast<uint64_t>(i);
        r.ymm[i].hi.q[0] = 0x3000ULL + static_cast<uint64_t>(i);
        r.ymm[i].hi.q[1] = 0x4000ULL + static_cast<uint64_t>(i);
    }

    size_t len = load_code({0xC5, 0xFC, 0x77}); // vzeroall
    STEP_EXPECT_OK(len);

    for (int i = 0; i < 16; ++i) {
        EXPECT_EQ(r.ymm[i].lo.q[0], 0ULL) << "ymm" << i << ".lo.q[0]";
        EXPECT_EQ(r.ymm[i].lo.q[1], 0ULL) << "ymm" << i << ".lo.q[1]";
        EXPECT_EQ(r.ymm[i].hi.q[0], 0ULL) << "ymm" << i << ".hi.q[0]";
        EXPECT_EQ(r.ymm[i].hi.q[1], 0ULL) << "ymm" << i << ".hi.q[1]";
    }
}

TEST_F(CPUSSETest, VZEROUPPER_C5F877) {
    auto& r = cpu.regs();
    for (int i = 0; i < 16; ++i) {
        r.ymm[i].lo.q[0] = 0x1000ULL + static_cast<uint64_t>(i);
        r.ymm[i].lo.q[1] = 0x2000ULL + static_cast<uint64_t>(i);
        r.ymm[i].hi.q[0] = 0x3000ULL + static_cast<uint64_t>(i);
        r.ymm[i].hi.q[1] = 0x4000ULL + static_cast<uint64_t>(i);
    }

    size_t len = load_code({0xC5, 0xF8, 0x77}); // vzeroupper
    STEP_EXPECT_OK(len);

    for (int i = 0; i < 16; ++i) {
        EXPECT_EQ(r.ymm[i].lo.q[0], 0x1000ULL + static_cast<uint64_t>(i)) << "ymm" << i << ".lo.q[0]";
        EXPECT_EQ(r.ymm[i].lo.q[1], 0x2000ULL + static_cast<uint64_t>(i)) << "ymm" << i << ".lo.q[1]";
        EXPECT_EQ(r.ymm[i].hi.q[0], 0ULL) << "ymm" << i << ".hi.q[0]";
        EXPECT_EQ(r.ymm[i].hi.q[1], 0ULL) << "ymm" << i << ".hi.q[1]";
    }
}

TEST_F(CPUSSETest, VSTMXCSR_VLDMXCSR_RoundTrip) {
    auto& r = cpu.regs();
    r.rax = DATA_BASE;
    write_mem32(DATA_BASE, 0xDEADBEEF);
    size_t len = load_code({0xC5, 0xF8, 0xAE, 0x18}); // vstmxcsr [rax]
    STEP_EXPECT_OK(len);
    uint32_t v; std::memcpy(&v, mem.data() + DATA_BASE, 4);
    EXPECT_EQ(v, 0x1F80u);

    write_mem32(DATA_BASE + 4, 0x9F80);
    len = load_code({0x0F, 0xAE, 0x50, 0x04}); // ldmxcsr [rax+4]
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.mxcsr, 0x9F80u);
}

// ── 9. C5 F0 58 C2 : vaddps xmm0, xmm1, xmm2 (3-op 128-bit) ─────────────────
TEST_F(CPUSSETest, VADDPS_Xmm_3Op_C5F058C2) {
    auto& r = cpu.regs();
    r.ymm[0].lo.f[0] = 99.0f; r.ymm[0].lo.f[1] = 99.0f;
    r.ymm[0].lo.f[2] = 99.0f; r.ymm[0].lo.f[3] = 99.0f;
    r.ymm[0].hi.q[0] = 0xDEADBEEFULL;
    r.ymm[0].hi.q[1] = 0xCAFEBABEULL;

    r.ymm[1].lo.f[0] = 1.0f;  r.ymm[1].lo.f[1] = 2.5f;
    r.ymm[1].lo.f[2] = -3.0f; r.ymm[1].lo.f[3] = 4.25f;
    r.ymm[1].hi.q[0] = 0x1111ULL; r.ymm[1].hi.q[1] = 0x2222ULL;

    r.ymm[2].lo.f[0] = 10.0f; r.ymm[2].lo.f[1] = -0.5f;
    r.ymm[2].lo.f[2] = 3.0f;  r.ymm[2].lo.f[3] = 0.75f;
    r.ymm[2].hi.q[0] = 0x3333ULL; r.ymm[2].hi.q[1] = 0x4444ULL;

    size_t len = load_code({0xC5, 0xF0, 0x58, 0xC2}); // vaddps xmm0, xmm1, xmm2
    STEP_EXPECT_OK(len);

    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 11.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[1], 2.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[2], 0.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[3], 5.0f);
    // VEX-128 zeroes upper 128 bits of destination
    EXPECT_EQ(r.ymm[0].hi.q[0], 0ULL);
    EXPECT_EQ(r.ymm[0].hi.q[1], 0ULL);
    // Source operands xmm1 and xmm2 must be unchanged
    EXPECT_FLOAT_EQ(r.ymm[1].lo.f[0], 1.0f);
    EXPECT_FLOAT_EQ(r.ymm[1].lo.f[1], 2.5f);
    EXPECT_FLOAT_EQ(r.ymm[1].lo.f[2], -3.0f);
    EXPECT_FLOAT_EQ(r.ymm[1].lo.f[3], 4.25f);
    EXPECT_EQ(r.ymm[1].hi.q[0], 0x1111ULL);
    EXPECT_EQ(r.ymm[1].hi.q[1], 0x2222ULL);
    EXPECT_FLOAT_EQ(r.ymm[2].lo.f[0], 10.0f);
    EXPECT_EQ(r.ymm[2].hi.q[0], 0x3333ULL);
}

// ── 10. C5 F4 58 C2 : vaddps ymm0, ymm1, ymm2 (256-bit, both halves) ───────
TEST_F(CPUSSETest, VADDPS_Ymm_256Bit_C5F458C2) {
    auto& r = cpu.regs();
    r.ymm[1].lo.f[0] = 1.0f;  r.ymm[1].lo.f[1] = 2.0f;
    r.ymm[1].lo.f[2] = 3.0f;  r.ymm[1].lo.f[3] = 4.0f;
    r.ymm[1].hi.f[0] = 5.0f;  r.ymm[1].hi.f[1] = 6.0f;
    r.ymm[1].hi.f[2] = 7.0f;  r.ymm[1].hi.f[3] = 8.0f;

    r.ymm[2].lo.f[0] = 10.0f; r.ymm[2].lo.f[1] = 20.0f;
    r.ymm[2].lo.f[2] = 30.0f; r.ymm[2].lo.f[3] = 40.0f;
    r.ymm[2].hi.f[0] = -1.0f; r.ymm[2].hi.f[1] = -2.5f;
    r.ymm[2].hi.f[2] = 0.25f; r.ymm[2].hi.f[3] = 100.0f;

    size_t len = load_code({0xC5, 0xF4, 0x58, 0xC2}); // vaddps ymm0, ymm1, ymm2
    STEP_EXPECT_OK(len);

    // Lower 128 bits
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 11.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[1], 22.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[2], 33.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[3], 44.0f);
    // Upper 128 bits
    EXPECT_FLOAT_EQ(r.ymm[0].hi.f[0], 4.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].hi.f[1], 3.5f);
    EXPECT_FLOAT_EQ(r.ymm[0].hi.f[2], 7.25f);
    EXPECT_FLOAT_EQ(r.ymm[0].hi.f[3], 108.0f);
    // Sources unchanged
    EXPECT_FLOAT_EQ(r.ymm[1].lo.f[0], 1.0f);
    EXPECT_FLOAT_EQ(r.ymm[1].hi.f[3], 8.0f);
    EXPECT_FLOAT_EQ(r.ymm[2].hi.f[3], 100.0f);
}

// ── 11. 0F 1F 44 00 00 long NOP, 0F 18 08 prefetch ──────────────────────────
TEST_F(CPUSSETest, NOP_Long_0F1F440000) {
    auto& r = cpu.regs();
    r.rax    = 0x1122334455667788ULL;
    r.rflags = 0x2 | FLAG_CF | FLAG_ZF;

    size_t len = load_code({0x0F, 0x1F, 0x44, 0x00, 0x00}); // nop dword ptr [rax+rax*1+0]
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.rax, 0x1122334455667788ULL);
    EXPECT_EQ(r.rflags, 0x2 | FLAG_CF | FLAG_ZF);
}

TEST_F(CPUSSETest, PREFETCH_0F1808) {
    auto& r = cpu.regs();
    r.rax    = DATA_BASE;
    r.rflags = 0x2 | FLAG_SF | FLAG_OF;

    size_t len = load_code({0x0F, 0x18, 0x08}); // prefetcht0 [rax]
    STEP_EXPECT_OK(len);

    EXPECT_EQ(r.rax, DATA_BASE);
    EXPECT_EQ(r.rflags, 0x2 | FLAG_SF | FLAG_OF);
}

// ── 12. All 16 SETcc (0F 90..9F) and all 16 CMOVcc (0F 40..4F) ──────────────
struct CondCodeInfo {
    uint8_t     cc;
    const char* name;
};

void PrintTo(const CondCodeInfo& info, std::ostream* os) {
    *os << info.name << " (cc=0x" << std::hex << static_cast<int>(info.cc) << std::dec << ")";
}

constexpr std::array<CondCodeInfo, 16> ALL_CC = {{
    {0x0, "O"},   {0x1, "NO"},  {0x2, "B"},   {0x3, "AE"},
    {0x4, "E"},   {0x5, "NE"},  {0x6, "BE"},  {0x7, "A"},
    {0x8, "S"},   {0x9, "NS"},  {0xA, "P"},   {0xB, "NP"},
    {0xC, "L"},   {0xD, "GE"},  {0xE, "LE"},  {0xF, "G"},
}};

bool eval_cc(uint8_t cc, bool cf, bool pf, bool zf, bool sf, bool of) {
    switch (cc) {
        case 0x0: return of;                    // O
        case 0x1: return !of;                   // NO
        case 0x2: return cf;                    // B / NAE / C
        case 0x3: return !cf;                   // AE / NB / NC
        case 0x4: return zf;                    // E / Z
        case 0x5: return !zf;                   // NE / NZ
        case 0x6: return cf || zf;              // BE / NA
        case 0x7: return !cf && !zf;            // A / NBE
        case 0x8: return sf;                    // S
        case 0x9: return !sf;                   // NS
        case 0xA: return pf;                    // P / PE
        case 0xB: return !pf;                   // NP / PO
        case 0xC: return sf != of;              // L / NGE
        case 0xD: return sf == of;              // GE / NL
        case 0xE: return zf || (sf != of);      // LE / NG
        case 0xF: return !zf && (sf == of);     // G / NLE
        default:  return false;
    }
}

uint64_t make_rflags(bool cf, bool pf, bool zf, bool sf, bool of) {
    uint64_t f = 0x2; // reserved bit 1
    if (cf) f |= FLAG_CF;
    if (pf) f |= FLAG_PF;
    if (zf) f |= FLAG_ZF;
    if (sf) f |= FLAG_SF;
    if (of) f |= FLAG_OF;
    return f;
}

class SETccTest : public CPUSSETest, public ::testing::WithParamInterface<CondCodeInfo> {};

TEST_P(SETccTest, All32FlagCombinations) {
    const auto info   = GetParam();
    const uint8_t op2 = static_cast<uint8_t>(0x90u + info.cc);

    // SETcc al : 0F (90+cc) C0
    for (int mask = 0; mask < 32; ++mask) {
        const bool cf = (mask & 1) != 0;
        const bool pf = (mask & 2) != 0;
        const bool zf = (mask & 4) != 0;
        const bool sf = (mask & 8) != 0;
        const bool of = (mask & 16) != 0;
        const bool expected = eval_cc(info.cc, cf, pf, zf, sf, of);

        cpu.clear_fault();
        auto& r  = cpu.regs();
        r.rax    = 0x11223344556677AAULL;
        r.rflags = make_rflags(cf, pf, zf, sf, of);

        size_t len = load_code({0x0F, op2, 0xC0});
        STEP_EXPECT_OK(len);

        const uint64_t expected_rax = 0x1122334455667700ULL | (expected ? 1ULL : 0ULL);
        EXPECT_EQ(r.rax, expected_rax)
            << "SET" << info.name << " (0F " << std::hex << static_cast<int>(op2) << ")"
            << " CF=" << cf << " PF=" << pf << " ZF=" << zf << " SF=" << sf << " OF=" << of;
    }
}

INSTANTIATE_TEST_SUITE_P(
    AllSETcc,
    SETccTest,
    ::testing::ValuesIn(ALL_CC),
    [](const ::testing::TestParamInfo<CondCodeInfo>& p) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "SET%s_0F%02X", p.param.name, 0x90u + p.param.cc);
        return std::string(buf);
    });

class CMOVccTest : public CPUSSETest, public ::testing::WithParamInterface<CondCodeInfo> {};

TEST_P(CMOVccTest, All32FlagCombinations_32And64Bit) {
    const auto info   = GetParam();
    const uint8_t op2 = static_cast<uint8_t>(0x40u + info.cc);

    for (int mask = 0; mask < 32; ++mask) {
        const bool cf = (mask & 1) != 0;
        const bool pf = (mask & 2) != 0;
        const bool zf = (mask & 4) != 0;
        const bool sf = (mask & 8) != 0;
        const bool of = (mask & 16) != 0;
        const bool expected = eval_cc(info.cc, cf, pf, zf, sf, of);

        // 32-bit form: 0F (40+cc) C1 -> cmovcc eax, ecx
        {
            cpu.clear_fault();
            auto& r  = cpu.regs();
            r.rax    = 0x0000000011223344ULL;
            r.rcx    = 0x99887766AABBCCDDULL;
            r.rflags = make_rflags(cf, pf, zf, sf, of);

            size_t len = load_code({0x0F, op2, 0xC1});
            STEP_EXPECT_OK(len);

            const uint64_t expected_rax = expected ? 0x00000000AABBCCDDULL : 0x0000000011223344ULL;
            EXPECT_EQ(r.rax, expected_rax)
                << "CMOV" << info.name << "32 (0F " << std::hex << static_cast<int>(op2) << ")"
                << " CF=" << cf << " PF=" << pf << " ZF=" << zf << " SF=" << sf << " OF=" << of;
        }

        // 64-bit form: 48 0F (40+cc) C1 -> cmovcc rax, rcx
        {
            cpu.clear_fault();
            auto& r  = cpu.regs();
            r.rax    = 0x1122334455667788ULL;
            r.rcx    = 0xCAFEBABEDEADBEEFULL;
            r.rflags = make_rflags(cf, pf, zf, sf, of);

            size_t len = load_code({0x48, 0x0F, op2, 0xC1});
            STEP_EXPECT_OK(len);

            const uint64_t expected_rax = expected ? 0xCAFEBABEDEADBEEFULL : 0x1122334455667788ULL;
            EXPECT_EQ(r.rax, expected_rax)
                << "CMOV" << info.name << "64 (48 0F " << std::hex << static_cast<int>(op2) << ")"
                << " CF=" << cf << " PF=" << pf << " ZF=" << zf << " SF=" << sf << " OF=" << of;
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    AllCMOVcc,
    CMOVccTest,
    ::testing::ValuesIn(ALL_CC),
    [](const ::testing::TestParamInfo<CondCodeInfo>& p) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "CMOV%s_0F%02X", p.param.name, 0x40u + p.param.cc);
        return std::string(buf);
    });

// ── 13. Regression tests for each fixed bug & Etape B edge cases ────────────

// Bug 1a: VEX2 pp==2 (F3) scalar vaddss 3-op preserves vvvv upper lanes & zeroes hi
TEST_F(CPUSSETest, VEX2_VADDSS_PP2_3Op) {
    auto& r = cpu.regs();
    r.ymm[0].hi.q[0] = BIT_HI0;
    r.ymm[1].lo.f[0] = 2.0f; r.ymm[1].lo.f[1] = 11.0f; r.ymm[1].lo.f[2] = 22.0f; r.ymm[1].lo.f[3] = 33.0f;
    r.ymm[2].lo.f[0] = 3.5f; r.ymm[2].lo.f[1] = 99.0f;
    // C5 F2 58 C2 : vaddss xmm0, xmm1, xmm2 (R=1, vvvv=1, L=0, pp=2(F3))
    size_t len = load_code({0xC5, 0xF2, 0x58, 0xC2});
    STEP_EXPECT_OK(len);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 5.5f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[1], 11.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[2], 22.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[3], 33.0f);
    EXPECT_EQ(r.ymm[0].hi.q[0], 0ULL);
    EXPECT_EQ(r.ymm[0].hi.q[1], 0ULL);
}

// Bug 1b: VEX2 pp==3 (F2) vmovsd reg-reg 3-op
TEST_F(CPUSSETest, VEX2_VMOVSD_PP3_3Op) {
    auto& r = cpu.regs();
    r.ymm[0].hi.q[0] = BIT_HI0;
    r.ymm[1].lo.df[0] = 1.0; r.ymm[1].lo.df[1] = 77.5;
    r.ymm[2].lo.df[0] = -4.25; r.ymm[2].lo.df[1] = 88.5;
    // C5 F3 10 C2 : vmovsd xmm0, xmm1, xmm2 (pp=3(F2))
    size_t len = load_code({0xC5, 0xF3, 0x10, 0xC2});
    STEP_EXPECT_OK(len);
    EXPECT_DOUBLE_EQ(r.ymm[0].lo.df[0], -4.25);
    EXPECT_DOUBLE_EQ(r.ymm[0].lo.df[1], 77.5);
    EXPECT_EQ(r.ymm[0].hi.q[0], 0ULL);
}

// Bug 1c: VEX3 W=1 (rex_w) + pp=3 (F2) vcvttsd2si r64, xmm
TEST_F(CPUSSETest, VEX3_VCVTTSD2SI_W1_64Bit) {
    auto& r = cpu.regs();
    r.ymm[1].lo.df[0] = 5000000000.75; // > INT32_MAX, fits in int64
    // C4 E1 FB 2C C1 : vcvttsd2si rax, xmm1 (map=1, W=1, vvvv=0, L=0, pp=3(F2))
    size_t len = load_code({0xC4, 0xE1, 0xFB, 0x2C, 0xC1});
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rax, 5000000000ULL);
}

// Bug 4: 0F 3A 00 must NOT decode as PSHUFD
TEST_F(CPUSSETest, ThreeByte_0F3A00_NotPSHUFD) {
    load_code({0x66, 0x0F, 0x3A, 0x00, 0xC1, 0x00});
    cpu.step();
    EXPECT_EQ(cpu.fault(), 1); // undecodable
}

// Bug 5: ADDSD/SUBSD/MULSD/DIVSD memory operand reads strictly 8 bytes
TEST_F(CPUSSETest, DIVSD_Mem_ReadsOnly8Bytes) {
    auto& r = cpu.regs();
    r.rcx = DATA_BASE;
    r.ymm[0].lo.df[0] = 15.0;
    r.ymm[0].lo.df[1] = 99.0;
    r.ymm[0].hi.q[0]  = BIT_HI0;
    double rhs = 2.5;
    std::memcpy(mem.data() + DATA_BASE, &rhs, sizeof(rhs));
    // F2 0F 5E 01 : divsd xmm0, qword ptr [rcx]
    size_t len = load_code({0xF2, 0x0F, 0x5E, 0x01});
    STEP_EXPECT_OK(len);
    EXPECT_DOUBLE_EQ(r.ymm[0].lo.df[0], 6.0);
    EXPECT_DOUBLE_EQ(r.ymm[0].lo.df[1], 99.0);
    EXPECT_EQ(r.ymm[0].hi.q[0], BIT_HI0);
    int total_bytes = 0;
    for (const auto& acc : data_reads) total_bytes += acc.size;
    EXPECT_EQ(total_bytes, 8);
}

// Bug 6: VEX-256 memory load reads hi half at +16 and handles dst==src1 aliasing
TEST_F(CPUSSETest, VADDPS_Ymm_256Bit_Mem) {
    auto& r = cpu.regs();
    r.rcx = DATA_BASE;
    for (int i = 0; i < 4; ++i) {
        r.ymm[1].lo.f[i] = static_cast<float>(i + 1);
        r.ymm[1].hi.f[i] = static_cast<float>(i + 5);
        write_mem_f32(DATA_BASE + i * 4, 10.0f * (i + 1));
        write_mem_f32(DATA_BASE + 16 + i * 4, 100.0f * (i + 1));
    }
    // C5 F4 58 09 : vaddps ymm1, ymm1, ymmword ptr [rcx]
    size_t len = load_code({0xC5, 0xF4, 0x58, 0x09});
    STEP_EXPECT_OK(len);
    EXPECT_FLOAT_EQ(r.ymm[1].lo.f[0], 11.0f);
    EXPECT_FLOAT_EQ(r.ymm[1].lo.f[3], 44.0f);
    EXPECT_FLOAT_EQ(r.ymm[1].hi.f[0], 105.0f);
    EXPECT_FLOAT_EQ(r.ymm[1].hi.f[3], 408.0f);
}

// Edge cases: MINSS/MAXSS NaN and +/-0.0 return src (x86 semantics)
TEST_F(CPUSSETest, MINSS_MAXSS_NaN_And_SignedZero) {
    auto& r = cpu.regs();
    const float nan = std::numeric_limits<float>::quiet_NaN();
    // minss(NaN, 3.0) -> 3.0 (src)
    r.ymm[0].lo.f[0] = nan; r.ymm[1].lo.f[0] = 3.0f;
    size_t len = load_code({0xF3, 0x0F, 0x5D, 0xC1});
    STEP_EXPECT_OK(len);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 3.0f);

    // minss(+0.0, -0.0) -> -0.0 (src)
    r.ymm[0].lo.f[0] = +0.0f; r.ymm[1].lo.f[0] = -0.0f; r.rip = CODE_BASE;
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.ymm[0].lo.d[0], 0x80000000u);

    // maxss(3.0, NaN) -> NaN (src)
    r.ymm[0].lo.f[0] = 3.0f; r.ymm[1].lo.f[0] = nan;
    len = load_code({0xF3, 0x0F, 0x5F, 0xC1});
    STEP_EXPECT_OK(len);
    EXPECT_TRUE(std::isnan(r.ymm[0].lo.f[0]));
}

// Edge cases: CVTTSS2SI / CVTTSD2SI overflow & NaN -> 0x80000000 / 0x8000000000000000
TEST_F(CPUSSETest, CVTT_Overflow_And_NaN) {
    auto& r = cpu.regs();
    r.ymm[1].lo.f[0] = 1e20f;
    size_t len = load_code({0xF3, 0x0F, 0x2C, 0xC1}); // cvttss2si eax, xmm1
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rax, 0x0000000080000000ULL);

    r.ymm[1].lo.df[0] = std::numeric_limits<double>::quiet_NaN();
    len = load_code({0xF2, 0x48, 0x0F, 0x2C, 0xC1}); // cvttsd2si rax, xmm1
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rax, 0x8000000000000000ULL);
}

// Edge case: CVTSI2SS sign-extends 32-bit negative int
TEST_F(CPUSSETest, CVTSI2SS_Negative32Bit) {
    auto& r = cpu.regs();
    r.rcx = 0x00000000FFFFFFFBULL; // -5 in ecx
    r.ymm[0].lo.f[1] = 12.0f;
    size_t len = load_code({0xF3, 0x0F, 0x2A, 0xC1}); // cvtsi2ss xmm0, ecx
    STEP_EXPECT_OK(len);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], -5.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[1], 12.0f);
}

// Sanity check: mnemonic_names.h stays aligned with Mnemonic enum
TEST_F(CPUSSETest, MnemonicNameTableAlignment) {
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::MOVLPS)), "MOVLPS");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::VZEROUPPER)), "VZEROUPPER");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::VZEROALL)), "VZEROALL");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::CVTDQ2PD)), "CVTDQ2PD");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::CDQE)), "CDQE");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::CQO)), "CQO");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::BLSI)), "BLSI");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::PEXTRQ)), "PEXTRQ");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::VEXTRACTF128)), "VEXTRACTF128");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::HADDPS)), "HADDPS");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::PSLLDQ)), "PSLLDQ");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::FMA3)), "FMA3");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::PACKSSDW)), "PACKSSDW");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::PSLLQ_R)), "PSLLQ_R");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::PSIGNB)), "PSIGNB");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::VPSLLV)), "VPSLLV");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::VMASKMOVD)), "VMASKMOVD");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::VMASKMOVQ)), "VMASKMOVQ");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::VCVTPS2PH)), "VCVTPS2PH");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::VCVTPH2PS)), "VCVTPH2PS");
    EXPECT_STREQ(mnemonic_name(static_cast<int>(Mnemonic::PCMPISTRI)), "PCMPISTRI");
}

// Game fault regressions: CVTDQ2PD (F3 0F E6), CDQE (48 98), CDQ (99), PUSH/POP r64
TEST_F(CPUSSETest, CVTDQ2PD_F3450FE6DB) {
    auto& r = cpu.regs();
    r.ymm[11].lo.d[0] = static_cast<uint32_t>(-17);
    r.ymm[11].lo.d[1] = 42u;
    r.ymm[11].hi.q[0] = BIT_HI0;
    size_t len = load_code({0xF3, 0x45, 0x0F, 0xE6, 0xDB}); // cvtdq2pd xmm11, xmm11
    STEP_EXPECT_OK(len);
    EXPECT_DOUBLE_EQ(r.ymm[11].lo.df[0], -17.0);
    EXPECT_DOUBLE_EQ(r.ymm[11].lo.df[1], 42.0);
    EXPECT_EQ(r.ymm[11].hi.q[0], BIT_HI0);
}

TEST_F(CPUSSETest, CDQE_And_CDQ) {
    auto& r = cpu.regs();
    r.rax = 0x00000000FFFFFFF0ULL; // -16 in eax
    size_t len = load_code({0x48, 0x98}); // cdqe
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rax, 0xFFFFFFFFFFFFFFF0ULL);

    r.rax = 0x0000000080000001ULL;
    r.rdx = 0x123456789ABCDEF0ULL;
    len = load_code({0x99}); // cdq
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rdx, 0x00000000FFFFFFFFULL);
}

TEST_F(CPUSSETest, PUSH_POP_R64) {
    auto& r = cpu.regs();
    r.rsp = DATA_BASE + 0x100;
    r.rdi = 0xCAFEBABEDEADBEEFULL;
    size_t len = load_code({0x57, 0x5E}); // push rdi; pop rsi
    step_and_expect_ok(1, CODE_BASE);
    step_and_expect_ok(1, CODE_BASE + 1);
    EXPECT_EQ(r.rsi, 0xCAFEBABEDEADBEEFULL);
    EXPECT_EQ(r.rsp, DATA_BASE + 0x100);
    (void)len;
}

TEST_F(CPUSSETest, BMI1_BLSI_C4E278F3DF) {
    auto& r = cpu.regs();
    r.rdi = 0x00001050ULL; // lowest set bit = 0x10
    r.rax = 0xFFFFFFFFFFFFFFFFULL;
    // c4 e2 78 f3 df : blsi eax, edi
    size_t len = load_code({0xC4, 0xE2, 0x78, 0xF3, 0xDF});
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rax, 0x10ULL);
    EXPECT_NE(r.rflags & FLAG_CF, 0ULL);
    EXPECT_EQ(r.rflags & FLAG_ZF, 0ULL);
}

TEST_F(CPUSSETest, BMI2_SHLX_SHRX_RORX) {
    auto& r = cpu.regs();
    r.rcx = 0x12345678ULL;
    r.rdx = 4;
    // c4 e2 69 f7 c1 : shlx eax, ecx, edx (map=2, W=0, vvvv=2(edx), L=0, pp=1)
    size_t len = load_code({0xC4, 0xE2, 0x69, 0xF7, 0xC1});
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rax, 0x23456780ULL);

    // c4 e3 7b f0 c1 04 : rorx eax, ecx, 4 (map=3, W=0, vvvv=0, L=0, pp=3)
    len = load_code({0xC4, 0xE3, 0x7B, 0xF0, 0xC1, 0x04});
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rax, 0x81234567ULL);
}

TEST_F(CPUSSETest, VPEXTRQ_C4E3F916C101) {
    auto& r = cpu.regs();
    r.ymm[0].lo.q[0] = 0x1111222233334444ULL;
    r.ymm[0].lo.q[1] = 0xAABBCCDDEEFF0011ULL;
    r.rcx = 0;
    // c4 e3 f9 16 c1 01 : vpextrq rcx, xmm0, 1
    size_t len = load_code({0xC4, 0xE3, 0xF9, 0x16, 0xC1, 0x01});
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rcx, 0xAABBCCDDEEFF0011ULL);
}

TEST_F(CPUSSETest, VBROADCASTSS_And_PTEST) {
    auto& r = cpu.regs();
    r.ymm[1].lo.f[0] = 3.25f;
    // c4 e2 7d 18 c1 : vbroadcastss ymm0, xmm1 (map=2, W=0, vvvv=0, L=1, pp=1)
    size_t len = load_code({0xC4, 0xE2, 0x7D, 0x18, 0xC1});
    STEP_EXPECT_OK(len);
    for (int i = 0; i < 4; ++i) {
        EXPECT_FLOAT_EQ(r.ymm[0].lo.f[i], 3.25f);
        EXPECT_FLOAT_EQ(r.ymm[0].hi.f[i], 3.25f);
    }

    // 66 0f 38 17 c0 : ptest xmm0, xmm0 -> non-zero so ZF=0, CF=1
    len = load_code({0x66, 0x0F, 0x38, 0x17, 0xC0});
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rflags & FLAG_ZF, 0ULL);
    EXPECT_NE(r.rflags & FLAG_CF, 0ULL);
}

TEST_F(CPUSSETest, VHADDPS_C4C13B7CC0) {
    auto& r = cpu.regs();
    r.ymm[8].lo.f[0] = 1.0f; r.ymm[8].lo.f[1] = 2.0f;
    r.ymm[8].lo.f[2] = 3.0f; r.ymm[8].lo.f[3] = 4.0f;
    r.ymm[0].hi.q[0] = BIT_HI0;
    // c4 c1 3b 7c c0 : vhaddps xmm0, xmm8, xmm8
    size_t len = load_code({0xC4, 0xC1, 0x3B, 0x7C, 0xC0});
    STEP_EXPECT_OK(len);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 3.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[1], 7.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[2], 3.0f);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[3], 7.0f);
    EXPECT_EQ(r.ymm[0].hi.q[0], 0ULL);
}

TEST_F(CPUSSETest, FMA3_VFMSUB213PS_And_VFMADD132PS) {
    auto& r = cpu.regs();
    // c4 e2 69 aa c2 : vfmsub213ps xmm0, xmm2, xmm2 -> xmm0 = xmm2 * xmm0 - xmm2
    r.ymm[0].lo.f[0] = 3.0f; r.ymm[0].lo.f[1] = 4.0f; r.ymm[0].lo.f[2] = 5.0f; r.ymm[0].lo.f[3] = 6.0f;
    r.ymm[2].lo.f[0] = 2.0f; r.ymm[2].lo.f[1] = 2.0f; r.ymm[2].lo.f[2] = 2.0f; r.ymm[2].lo.f[3] = 2.0f;
    r.ymm[0].hi.q[0] = BIT_HI0;
    size_t len = load_code({0xC4, 0xE2, 0x69, 0xAA, 0xC2});
    STEP_EXPECT_OK(len);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 4.0f);  // 2*3 - 2
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[1], 6.0f);  // 2*4 - 2
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[2], 8.0f);  // 2*5 - 2
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[3], 10.0f); // 2*6 - 2
    EXPECT_EQ(r.ymm[0].hi.q[0], 0ULL);

    // c4 e2 71 98 c1 : vfmadd132ps xmm0, xmm1, xmm1 -> xmm0 = xmm0 * xmm1 + xmm1
    r.ymm[1].lo.f[0] = 0.5f; r.ymm[1].lo.f[1] = 0.5f; r.ymm[1].lo.f[2] = 0.5f; r.ymm[1].lo.f[3] = 0.5f;
    len = load_code({0xC4, 0xE2, 0x71, 0x98, 0xC1});
    STEP_EXPECT_OK(len);
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[0], 2.5f); // 4*0.5 + 0.5
    EXPECT_FLOAT_EQ(r.ymm[0].lo.f[3], 5.5f); // 10*0.5 + 0.5
}

TEST_F(CPUSSETest, VPACKSSDW_C5F96BC0) {
    auto& r = cpu.regs();
    r.ymm[0].lo.d[0] = static_cast<uint32_t>(100);
    r.ymm[0].lo.d[1] = static_cast<uint32_t>(50000);   // saturates to 32767
    r.ymm[0].lo.d[2] = static_cast<uint32_t>(-50000);  // saturates to -32768
    r.ymm[0].lo.d[3] = static_cast<uint32_t>(-42);
    r.ymm[0].hi.q[0] = BIT_HI0;
    // c5 f9 6b c0 : vpackssdw xmm0, xmm0, xmm0
    size_t len = load_code({0xC5, 0xF9, 0x6B, 0xC0});
    STEP_EXPECT_OK(len);
    EXPECT_EQ(static_cast<int16_t>(r.ymm[0].lo.w[0]), 100);
    EXPECT_EQ(static_cast<int16_t>(r.ymm[0].lo.w[1]), 32767);
    EXPECT_EQ(static_cast<int16_t>(r.ymm[0].lo.w[2]), -32768);
    EXPECT_EQ(static_cast<int16_t>(r.ymm[0].lo.w[3]), -42);
    EXPECT_EQ(static_cast<int16_t>(r.ymm[0].lo.w[4]), 100);
    EXPECT_EQ(static_cast<int16_t>(r.ymm[0].lo.w[5]), 32767);
    EXPECT_EQ(r.ymm[0].hi.q[0], 0ULL);
}

TEST_F(CPUSSETest, BSWAP_0FCF_And_SHLD_SHRD) {
    auto& r = cpu.regs();
    r.rdi = 0x11223344AABBCCDDULL;
    size_t len = load_code({0x0F, 0xCF}); // bswap edi (32-bit zero-extends rdi)
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rdi, 0x00000000DDCCBBAAULL);

    r.rdi = 0x0102030405060708ULL;
    len = load_code({0x48, 0x0F, 0xCF}); // bswap rdi
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rdi, 0x0807060504030201ULL);

    r.rax = 0x12345678ULL;
    r.rcx = 0x9ABCDEF0ULL;
    len = load_code({0x0F, 0xA4, 0xC8, 0x04}); // shld eax, ecx, 4
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rax, 0x23456789ULL);
}

TEST_F(CPUSSETest, VPSIGNB_C4E27908C0) {
    auto& r = cpu.regs();
    r.ymm[0].lo.b[0] = static_cast<uint8_t>(-5);
    r.ymm[0].lo.b[1] = 0;
    r.ymm[0].lo.b[2] = 7;
    r.ymm[0].hi.q[0] = BIT_HI0;
    // c4 e2 79 08 c0 : vpsignb xmm0, xmm0, xmm0 (computes abs of signed bytes)
    size_t len = load_code({0xC4, 0xE2, 0x79, 0x08, 0xC0});
    STEP_EXPECT_OK(len);
    EXPECT_EQ(static_cast<int8_t>(r.ymm[0].lo.b[0]), 5);
    EXPECT_EQ(static_cast<int8_t>(r.ymm[0].lo.b[1]), 0);
    EXPECT_EQ(static_cast<int8_t>(r.ymm[0].lo.b[2]), 7);
    EXPECT_EQ(r.ymm[0].hi.q[0], 0ULL);
}

TEST_F(CPUSSETest, VPMASKMOVD_Store_C4E2458E048F) {
    auto& r = cpu.regs();
    r.rdi = DATA_BASE;
    r.rcx = 0;
    for (int i = 0; i < 8; ++i) write_mem32(DATA_BASE + i * 4, 0xAAAAAAAAu);
    r.ymm[0].lo.d[0] = 0x11111111u; r.ymm[0].lo.d[1] = 0x22222222u;
    r.ymm[0].lo.d[2] = 0x33333333u; r.ymm[0].lo.d[3] = 0x44444444u;
    r.ymm[0].hi.d[0] = 0x55555555u; r.ymm[0].hi.d[1] = 0x66666666u;
    r.ymm[0].hi.d[2] = 0x77777777u; r.ymm[0].hi.d[3] = 0x88888888u;
    r.ymm[7].lo.d[0] = 0x80000000u; r.ymm[7].lo.d[1] = 0x00000000u;
    r.ymm[7].lo.d[2] = 0x80000000u; r.ymm[7].lo.d[3] = 0x00000000u;
    r.ymm[7].hi.d[0] = 0x00000000u; r.ymm[7].hi.d[1] = 0xFFFFFFFFu;
    r.ymm[7].hi.d[2] = 0x00000000u; r.ymm[7].hi.d[3] = 0x80000000u;
    // c4 e2 45 8e 04 8f : vpmaskmovd ymmword ptr [rdi+rcx*4], ymm7, ymm0
    size_t len = load_code({0xC4, 0xE2, 0x45, 0x8E, 0x04, 0x8F});
    STEP_EXPECT_OK(len);
    uint32_t got[8];
    std::memcpy(got, mem.data() + DATA_BASE, sizeof(got));
    EXPECT_EQ(got[0], 0x11111111u);
    EXPECT_EQ(got[1], 0xAAAAAAAAu);
    EXPECT_EQ(got[2], 0x33333333u);
    EXPECT_EQ(got[3], 0xAAAAAAAAu);
    EXPECT_EQ(got[4], 0xAAAAAAAAu);
    EXPECT_EQ(got[5], 0x66666666u);
    EXPECT_EQ(got[6], 0xAAAAAAAAu);
    EXPECT_EQ(got[7], 0x88888888u);
}

TEST_F(CPUSSETest, F16C_VCVTPS2PH_And_VCVTPH2PS) {
    auto& r = cpu.regs();
    r.ymm[6].lo.f[0] = 1.0f;
    r.ymm[6].lo.f[1] = -2.5f;
    r.ymm[6].lo.f[2] = 0.0f;
    r.ymm[6].lo.f[3] = 65504.0f;
    r.ymm[0].hi.q[0] = BIT_HI0;
    // c4 e3 79 1d f0 03 : vcvtps2ph xmm0, xmm6, 3 (trunc)
    size_t len = load_code({0xC4, 0xE3, 0x79, 0x1D, 0xF0, 0x03});
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.ymm[0].lo.w[0], 0x3C00u); // 1.0
    EXPECT_EQ(r.ymm[0].lo.w[1], 0xC100u); // -2.5
    EXPECT_EQ(r.ymm[0].lo.w[2], 0x0000u); // 0.0
    EXPECT_EQ(r.ymm[0].lo.w[3], 0x7BFFu); // 65504.0
    EXPECT_EQ(r.ymm[0].lo.q[1], 0ULL);
    EXPECT_EQ(r.ymm[0].hi.q[0], 0ULL);

    // c4 e2 79 13 c8 : vcvtph2ps xmm1, xmm0
    len = load_code({0xC4, 0xE2, 0x79, 0x13, 0xC8});
    STEP_EXPECT_OK(len);
    EXPECT_FLOAT_EQ(r.ymm[1].lo.f[0], 1.0f);
    EXPECT_FLOAT_EQ(r.ymm[1].lo.f[1], -2.5f);
    EXPECT_FLOAT_EQ(r.ymm[1].lo.f[2], 0.0f);
    EXPECT_FLOAT_EQ(r.ymm[1].lo.f[3], 65504.0f);
}

TEST_F(CPUSSETest, PCMPISTRI_660F3A63C841_Wcsrchr) {
    auto& r = cpu.regs();
    // xmm1 = L"\\" (set of 1 wide char '\\' = 0x5C, null-terminated)
    r.ymm[1].lo = {};
    r.ymm[1].lo.w[0] = '\\';
    // xmm0 = L"a\\b\\c\0" -> '\\' at indices 1 and 3; imm8=0x41 picks MSB -> index 3!
    r.ymm[0].lo = {};
    r.ymm[0].lo.w[0] = 'a';
    r.ymm[0].lo.w[1] = '\\';
    r.ymm[0].lo.w[2] = 'b';
    r.ymm[0].lo.w[3] = '\\';
    r.ymm[0].lo.w[4] = 'c';
    r.ymm[0].lo.w[5] = 0;

    // 66 0f 3a 63 c8 41 : pcmpistri xmm1, xmm0, 0x41
    size_t len = load_code({0x66, 0x0F, 0x3A, 0x63, 0xC8, 0x41});
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.rcx, 3ULL);
    EXPECT_NE(r.rflags & FLAG_CF, 0ULL); // match found
    EXPECT_NE(r.rflags & FLAG_ZF, 0ULL); // null in xmm0
    EXPECT_NE(r.rflags & FLAG_SF, 0ULL); // null in xmm1
}

} // namespace

// vpblendd xmm0, xmm1, xmm0, 0x08 : dword3 from xmm0, rest from xmm1
TEST_F(CPUSSETest, VPBLENDD_Xmm) {
    auto& r = cpu.regs();
    for (int i = 0; i < 4; i++) { r.ymm[0].lo.d[i] = 0xA0 + i; r.ymm[1].lo.d[i] = 0xB0 + i; }
    size_t len = load_code({0xC4, 0xE3, 0x71, 0x02, 0xC0, 0x08});
    STEP_EXPECT_OK(len);
    EXPECT_EQ(r.ymm[0].lo.d[0], 0xB0u);
    EXPECT_EQ(r.ymm[0].lo.d[2], 0xB2u);
    EXPECT_EQ(r.ymm[0].lo.d[3], 0xA3u);
}
