#include <gtest/gtest.h>
#include "memory/memory_map.h"

using namespace emu::memory;

TEST(MemoryMap, BasicReadWrite) {
    MemoryMap mm;
    mm.write32(0x1000, 0xDEADBEEF);
    EXPECT_EQ(mm.read32(0x1000), 0xDEADBEEF);
}

TEST(MemoryMap, ByteOrder) {
    MemoryMap mm;
    mm.write32(0x2000, 0x01020304);
    EXPECT_EQ(mm.read8(0x2000), 0x04); // little-endian
    EXPECT_EQ(mm.read8(0x2003), 0x01);
}

TEST(MemoryMap, MMIO_Callback) {
    MemoryMap mm;
    uint32_t captured = 0;

    MemoryRegion r{};
    r.base = 0xFC000000;
    r.size = 0x1000;
    r.type = RegionType::MMIO;
    r.write_cb = [&](uint64_t, uint64_t val, int) { captured = val; };
    r.read_cb  = [&](uint64_t, int) -> uint64_t   { return 0xCAFE; };
    mm.add_region(std::move(r));

    mm.write32(0xFC000010, 0x1234);
    EXPECT_EQ(captured, 0x1234u);
    EXPECT_EQ(mm.read32(0xFC000010), 0xCAFEu);
}
