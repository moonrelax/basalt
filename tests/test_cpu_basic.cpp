#include <gtest/gtest.h>
#include <array>
#include <cstring>
#include "cpu/cpu.h"

using namespace emu::cpu;

class CPUTest : public ::testing::Test {
protected:
    std::array<uint8_t, 0x10000> mem{};
    CPU                          cpu;

    void SetUp() override {
        mem.fill(0);
        cpu.reset();
        cpu.set_mem_read([&](uint64_t addr, int sz) -> uint64_t {
            if (addr + static_cast<uint64_t>(sz) > mem.size()) return 0;
            uint64_t val = 0;
            std::memcpy(&val, mem.data() + addr, static_cast<size_t>(sz));
            return val;
        });
        cpu.set_mem_write([&](uint64_t addr, uint64_t val, int sz) {
            if (addr + static_cast<uint64_t>(sz) > mem.size()) return;
            std::memcpy(mem.data() + addr, &val, static_cast<size_t>(sz));
        });
    }

    void load_code(uint64_t addr, std::initializer_list<uint8_t> bytes) {
        uint64_t a = addr;
        for (uint8_t b : bytes) mem[a++] = b;
        cpu.regs().rip = addr;
    }
};

TEST_F(CPUTest, NOP) {
    load_code(0x1000, {0x90}); // NOP
    uint64_t rip_before = cpu.regs().rip;
    cpu.step();
    EXPECT_EQ(cpu.regs().rip, rip_before + 1);
}

TEST_F(CPUTest, HLT) {
    load_code(0x1000, {0xF4}); // HLT
    cpu.step();
    EXPECT_TRUE(cpu.halted());
}

TEST_F(CPUTest, CLI_STI) {
    load_code(0x1000, {0xFA, 0xFB}); // CLI then STI
    cpu.regs().rflags |= (1 << 9); // IF=1
    cpu.step(); // CLI
    EXPECT_EQ(cpu.regs().rflags & (1 << 9), 0u);
    cpu.step(); // STI
    EXPECT_NE(cpu.regs().rflags & (1 << 9), 0u);
}

TEST_F(CPUTest, AddRaxMinus1_CF1) {
    // add rax, -1 (48 83 C0 FF) with rax=2 -> rax=1, CF=1
    load_code(0x1000, {0x48, 0x83, 0xC0, 0xFF});
    cpu.regs().rax = 2;
    cpu.regs().rflags = 0;
    cpu.step();
    EXPECT_EQ(cpu.regs().rax, 1u);
    EXPECT_NE(cpu.regs().rflags & 1u, 0u); // CF=1
    EXPECT_EQ(cpu.regs().rflags & (1u << 6), 0u); // ZF=0
}

TEST_F(CPUTest, AddRax1_Max64_CF1_ZF1) {
    // add rax, 1 (48 83 C0 01) with rax=UINT64_MAX -> rax=0, CF=1, ZF=1
    load_code(0x1000, {0x48, 0x83, 0xC0, 0x01});
    cpu.regs().rax = ~0ULL;
    cpu.regs().rflags = 0;
    cpu.step();
    EXPECT_EQ(cpu.regs().rax, 0u);
    EXPECT_NE(cpu.regs().rflags & 1u, 0u); // CF=1
    EXPECT_NE(cpu.regs().rflags & (1u << 6), 0u); // ZF=1
}

TEST_F(CPUTest, AdcRaxMax64_CF1) {
    // adc rax, -1 (48 83 D0 FF) with CF=1 -> result unchanged, CF=1
    load_code(0x1000, {0x48, 0x83, 0xD0, 0xFF});
    cpu.regs().rax = 0x123456789ABCDEF0ULL;
    cpu.regs().rflags = 1u; // CF=1
    cpu.step();
    EXPECT_EQ(cpu.regs().rax, 0x123456789ABCDEF0ULL);
    EXPECT_NE(cpu.regs().rflags & 1u, 0u); // CF=1
    EXPECT_EQ(cpu.regs().rflags & (1u << 11), 0u); // OF=0
}

TEST_F(CPUTest, SbbRaxMax64_CF1) {
    // sbb rax, -1 (48 83 D8 FF) with CF=1 -> subtracting UINT64_MAX+1=2^64 leaves rax unchanged, CF=1
    load_code(0x1000, {0x48, 0x83, 0xD8, 0xFF});
    cpu.regs().rax = 0x42ULL;
    cpu.regs().rflags = 1u; // CF=1
    cpu.step();
    EXPECT_EQ(cpu.regs().rax, 0x42ULL);
    EXPECT_NE(cpu.regs().rflags & 1u, 0u); // CF=1
    EXPECT_EQ(cpu.regs().rflags & (1u << 11), 0u); // OF=0
}

TEST_F(CPUTest, SubSizes8_16_32_64) {
    // sub al, 5 (2C 05); sub ax, 5 (66 83 E8 05); sub eax, 5 (83 E8 05); sub rax, 5 (48 83 E8 05)
    load_code(0x1000, {
        0x2C, 0x05,
        0x66, 0x83, 0xE8, 0x05,
        0x83, 0xE8, 0x05,
        0x48, 0x83, 0xE8, 0x05
    });
    cpu.regs().rax = 3;
    cpu.step(); // 8-bit: 3 - 5 = 0xFE, CF=1
    EXPECT_EQ(cpu.regs().rax & 0xFF, 0xFEu);
    EXPECT_NE(cpu.regs().rflags & 1u, 0u);

    cpu.regs().rax = 3;
    cpu.step(); // 16-bit: 3 - 5 = 0xFFFE, CF=1
    EXPECT_EQ(cpu.regs().rax & 0xFFFF, 0xFFFEu);
    EXPECT_NE(cpu.regs().rflags & 1u, 0u);

    cpu.regs().rax = 3;
    cpu.step(); // 32-bit: 3 - 5 = 0xFFFFFFFE, CF=1
    EXPECT_EQ(cpu.regs().rax, 0xFFFFFFFEULL);
    EXPECT_NE(cpu.regs().rflags & 1u, 0u);

    cpu.regs().rax = 3;
    cpu.step(); // 64-bit: 3 - 5 = 0xFFFFFFFFFFFFFFFE, CF=1
    EXPECT_EQ(cpu.regs().rax, 0xFFFFFFFFFFFFFFFEULL);
    EXPECT_NE(cpu.regs().rflags & 1u, 0u);
}

TEST_F(CPUTest, NegZero_CF0) {
    // neg rax (48 F7 D8)
    load_code(0x1000, {0x48, 0xF7, 0xD8, 0x48, 0xF7, 0xD8});
    cpu.regs().rax = 0;
    cpu.regs().rflags = 1u; // pre-set CF=1
    cpu.step();
    EXPECT_EQ(cpu.regs().rax, 0u);
    EXPECT_EQ(cpu.regs().rflags & 1u, 0u); // CF=0 for neg 0
    EXPECT_NE(cpu.regs().rflags & (1u << 6), 0u); // ZF=1

    cpu.regs().rax = 5;
    cpu.step();
    EXPECT_EQ(cpu.regs().rax, static_cast<uint64_t>(-5LL));
    EXPECT_NE(cpu.regs().rflags & 1u, 0u); // CF=1 for neg non-zero
}

TEST_F(CPUTest, IncPreservesCF) {
    // inc rax (48 FF C0)
    load_code(0x1000, {0x48, 0xFF, 0xC0, 0x48, 0xFF, 0xC0});
    cpu.regs().rax = ~0ULL;
    cpu.regs().rflags = 0; // CF=0
    cpu.step();
    EXPECT_EQ(cpu.regs().rax, 0u);
    EXPECT_EQ(cpu.regs().rflags & 1u, 0u); // CF=0 preserved even on wrap
    EXPECT_NE(cpu.regs().rflags & (1u << 6), 0u); // ZF=1

    cpu.regs().rax = 10;
    cpu.regs().rflags = 1u; // CF=1
    cpu.step();
    EXPECT_EQ(cpu.regs().rax, 11u);
    EXPECT_NE(cpu.regs().rflags & 1u, 0u); // CF=1 preserved
}

TEST_F(CPUTest, ShlCountZeroPreservesFlags) {
    // shl rax, cl (48 D3 E0)
    load_code(0x1000, {0x48, 0xD3, 0xE0});
    cpu.regs().rax = 0x8000000000000001ULL;
    cpu.regs().rcx = 0;
    uint64_t initial_flags = (1u << 0) | (1u << 6) | (1u << 11);
    cpu.regs().rflags = initial_flags;
    cpu.step();
    EXPECT_EQ(cpu.regs().rax, 0x8000000000000001ULL);
    EXPECT_EQ(cpu.regs().rflags, initial_flags);
}

TEST_F(CPUTest, ImulOverflowFlags) {
    // imul rax, rcx (48 0F AF C1)
    load_code(0x1000, {0x48, 0x0F, 0xAF, 0xC1, 0x48, 0x0F, 0xAF, 0xC1});
    cpu.regs().rax = 0x4000000000000000ULL;
    cpu.regs().rcx = 4; // overflows signed 64-bit
    cpu.regs().rflags = 0;
    cpu.step();
    EXPECT_NE(cpu.regs().rflags & 1u, 0u); // CF=1
    EXPECT_NE(cpu.regs().rflags & (1u << 11), 0u); // OF=1

    cpu.regs().rax = 7;
    cpu.regs().rcx = -3ULL; // -21 fits in signed 64-bit
    cpu.step();
    EXPECT_EQ(cpu.regs().rax, static_cast<uint64_t>(-21LL));
    EXPECT_EQ(cpu.regs().rflags & 1u, 0u); // CF=0
    EXPECT_EQ(cpu.regs().rflags & (1u << 11), 0u); // OF=0
}

TEST_F(CPUTest, LoopAddMinus1JbExits) {
    // Exact pattern from a real title:
    // 0x1000: 48 83 C7 FF (add rdi, -1)
    // 0x1004: 72 FA       (jb 0x1000)
    // 0x1006: F4          (hlt)
    load_code(0x1000, {0x48, 0x83, 0xC7, 0xFF, 0x72, 0xFA, 0xF4});
    cpu.regs().rdi = 3;
    int steps = 0;
    while (!cpu.halted() && steps < 20) {
        cpu.step();
        ++steps;
    }
    EXPECT_TRUE(cpu.halted());
    EXPECT_EQ(cpu.regs().rdi, ~0ULL); // 3 -> 2 -> 1 -> 0 -> -1 (CF=0, exits loop)
    EXPECT_EQ(steps, 9); // 4 iterations * 2 insns + 1 HLT
}

TEST_F(CPUTest, AdcxAdoxSeparateCarryChains) {
    // exact bytes from a real title: adcx r12, r9 ; adox r11, r10
    load_code(0x1000, {0x66, 0x4D, 0x0F, 0x38, 0xF6, 0xE1,
                       0xF3, 0x4D, 0x0F, 0x38, 0xF6, 0xDA});
    cpu.regs().r12 = ~0ULL; cpu.regs().r9 = 1;      // carry out on CF chain
    cpu.regs().r11 = 5;     cpu.regs().r10 = 6;     // OF chain, OF in = 1
    cpu.regs().rflags = (1u << 11) | (1u << 6);     // OF=1, ZF=1, CF=0
    cpu.step();
    EXPECT_EQ(cpu.regs().r12, 0ULL);
    EXPECT_NE(cpu.regs().rflags & 1u, 0u);          // CF=1
    EXPECT_NE(cpu.regs().rflags & (1u << 11), 0u);  // OF untouched
    EXPECT_NE(cpu.regs().rflags & (1u << 6), 0u);   // ZF untouched
    cpu.step();
    EXPECT_EQ(cpu.regs().r11, 12ULL);               // 5 + 6 + OF
    EXPECT_EQ(cpu.regs().rflags & (1u << 11), 0u);  // OF=0 (no carry out)
    EXPECT_NE(cpu.regs().rflags & 1u, 0u);          // CF untouched
}

TEST_F(CPUTest, AdcAlImm8) {
    load_code(0x1000, {0x14, 0x01}); // adc al, 1
    cpu.regs().rax = 0x10; cpu.regs().rflags = 1; // CF=1
    cpu.step();
    EXPECT_EQ(cpu.regs().rax & 0xFF, 0x12ULL);
}
