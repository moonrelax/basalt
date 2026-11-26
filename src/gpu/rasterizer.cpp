#include "gpu/gpu.h"
#include "gpu/shader_rdna2.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <unordered_set>
#include <vector>

namespace emu::gpu {
namespace {

uint8_t g_rt[kRtWidth * kRtHeight * 4];
uint64_t g_present_va = 0;

struct Vtx {
    float x, y, r, g, b, a;
};

uint8_t chan(float c) {
    if (c < 0.f) c = 0.f;
    if (c > 1.f) c = 1.f;
    return static_cast<uint8_t>(c * 255.f + 0.5f);
}

uint32_t read_index(const DrawCall& d, uint32_t slot) {
    const uint32_t at = d.start_index + slot;
    if (!d.index_bytes || at >= d.index_count) return 0xffffffffu;
    const uint8_t* p = d.index_bytes + static_cast<uint64_t>(at) * d.index_stride;
    if (d.index_stride == 2) {
        uint16_t x = 0;
        std::memcpy(&x, p, 2);
        return x == 0xffffu ? 0xffffffffu : x;
    }
    uint32_t x = 0;
    std::memcpy(&x, p, 4);
    return x;
}

bool fetch(const DrawCall& d, uint32_t slot, Vtx& out) {
    uint32_t index = d.start_vertex + slot;
    if (d.indexed) {
        index = read_index(d, slot);
        if (index == 0xffffffffu) return false;
        index += d.start_vertex;
    }
    if (!d.vertices.data || index >= d.vertices.count) return false;
    if (d.vertices.stride < 2 * sizeof(float)) return false;
    const uint32_t nf = d.vertices.stride / sizeof(float);
    const auto* p = reinterpret_cast<const float*>(d.vertices.data + index * d.vertices.stride);
    float regs[kVgprCount] = {};
    for (uint32_t i = 0; i < nf && i < static_cast<uint32_t>(kVgprCount); ++i)
        regs[i] = p[i];
    RdnaOut io;
    io.color[0] = nf > 2 ? regs[2] : 1.f;
    io.color[1] = nf > 3 ? regs[3] : 1.f;
    io.color[2] = nf > 4 ? regs[4] : 1.f;
    io.color[3] = nf > 5 ? regs[5] : 1.f;
    if (d.rdna2.bytes && d.rdna2.size)
        exec_rdna2(d.rdna2.bytes, d.rdna2.size, regs, io);
    float x = regs[0];
    float y = regs[1];
    if (io.pos_written && io.pos[3] != 0.f) {
        x = io.pos[0] / io.pos[3];
        y = io.pos[1] / io.pos[3];
    }
    out = {x, y, io.color[0], io.color[1], io.color[2], io.color[3]};
    return true;
}

void put(int x, int y, const Vtx& c) {
    if (x < 0 || y < 0 || x >= static_cast<int>(kRtWidth) || y >= static_cast<int>(kRtHeight)) return;
    uint8_t* p = g_rt + (static_cast<uint32_t>(y) * kRtWidth + static_cast<uint32_t>(x)) * 4;
    p[0] = chan(c.r);
    p[1] = chan(c.g);
    p[2] = chan(c.b);
    p[3] = chan(c.a);
}

void fill_tri(const Vtx& a, const Vtx& b, const Vtx& c) {
    auto sx = [](float x) { return (x * 0.5f + 0.5f) * static_cast<float>(kRtWidth); };
    auto sy = [](float y) { return (0.5f - y * 0.5f) * static_cast<float>(kRtHeight); };
    const float ax = sx(a.x), ay = sy(a.y);
    const float bx = sx(b.x), by = sy(b.y);
    const float cx = sx(c.x), cy = sy(c.y);
    auto edge = [](float x0, float y0, float x1, float y1, float px, float py) {
        return (px - x0) * (y1 - y0) - (py - y0) * (x1 - x0);
    };
    const float area = edge(ax, ay, bx, by, cx, cy);
    if (area == 0.f) return;
    int minx = static_cast<int>(ax < bx ? (ax < cx ? ax : cx) : (bx < cx ? bx : cx));
    int maxx = static_cast<int>(ax > bx ? (ax > cx ? ax : cx) : (bx > cx ? bx : cx));
    int miny = static_cast<int>(ay < by ? (ay < cy ? ay : cy) : (by < cy ? by : cy));
    int maxy = static_cast<int>(ay > by ? (ay > cy ? ay : cy) : (by > cy ? by : cy));
    if (minx < 0) minx = 0;
    if (miny < 0) miny = 0;
    if (maxx >= static_cast<int>(kRtWidth)) maxx = static_cast<int>(kRtWidth) - 1;
    if (maxy >= static_cast<int>(kRtHeight)) maxy = static_cast<int>(kRtHeight) - 1;
    for (int y = miny; y <= maxy; ++y) {
        for (int x = minx; x <= maxx; ++x) {
            const float px = static_cast<float>(x) + 0.5f;
            const float py = static_cast<float>(y) + 0.5f;
            const float w0 = edge(bx, by, cx, cy, px, py) / area;
            const float w1 = edge(cx, cy, ax, ay, px, py) / area;
            const float w2 = edge(ax, ay, bx, by, px, py) / area;
            if (w0 < 0.f || w1 < 0.f || w2 < 0.f) continue;
            Vtx col{
                0, 0,
                a.r * w0 + b.r * w1 + c.r * w2,
                a.g * w0 + b.g * w1 + c.g * w2,
                a.b * w0 + b.b * w1 + c.b * w2,
                a.a * w0 + b.a * w1 + c.a * w2,
            };
            put(x, y, col);
        }
    }
}

void draw_one(const DrawCall& d) {
    const uint32_t n = d.indexed ? d.index_count : d.vertex_count;
    for (uint32_t i = 0; i + 2 < n; i += 3) {
        Vtx a, b, c;
        if (!fetch(d, i, a) || !fetch(d, i + 1, b) || !fetch(d, i + 2, c)) continue;
        fill_tri(a, b, c);
    }
}

void png_chunk(std::vector<uint8_t>& out, const char tag[4], const uint8_t* data, uint32_t n) {
    out.push_back(static_cast<uint8_t>(n >> 24));
    out.push_back(static_cast<uint8_t>(n >> 16));
    out.push_back(static_cast<uint8_t>(n >> 8));
    out.push_back(static_cast<uint8_t>(n));
    out.insert(out.end(), tag, tag + 4);
    if (n && data) out.insert(out.end(), data, data + n);
    uint32_t c = 0xFFFFFFFFu;
    auto feed = [&](const uint8_t* p, size_t k) {
        for (size_t i = 0; i < k; ++i) {
            c ^= p[i];
            for (int b = 0; b < 8; ++b) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
        }
    };
    feed(reinterpret_cast<const uint8_t*>(tag), 4);
    if (n && data) feed(data, n);
    c = ~c;
    out.push_back(static_cast<uint8_t>(c >> 24));
    out.push_back(static_cast<uint8_t>(c >> 16));
    out.push_back(static_cast<uint8_t>(c >> 8));
    out.push_back(static_cast<uint8_t>(c));
}

bool write_png(const char* path) {
    std::vector<uint8_t> raw;
    raw.reserve(static_cast<size_t>(kRtHeight) * (1 + kRtWidth * 4));
    for (uint32_t y = 0; y < kRtHeight; ++y) {
        raw.push_back(0);
        const uint8_t* row = g_rt + y * kRtWidth * 4;
        raw.insert(raw.end(), row, row + kRtWidth * 4);
    }
    std::vector<uint8_t> z;
    z.push_back(0x78);
    z.push_back(0x01);
    size_t off = 0;
    while (off < raw.size()) {
        const uint16_t n = static_cast<uint16_t>(std::min<size_t>(65535, raw.size() - off));
        const bool last = off + n == raw.size();
        const uint16_t nlen = static_cast<uint16_t>(~n);
        z.push_back(last ? 1 : 0);
        z.push_back(static_cast<uint8_t>(n));
        z.push_back(static_cast<uint8_t>(n >> 8));
        z.push_back(static_cast<uint8_t>(nlen));
        z.push_back(static_cast<uint8_t>(nlen >> 8));
        z.insert(z.end(), raw.begin() + static_cast<std::ptrdiff_t>(off),
                 raw.begin() + static_cast<std::ptrdiff_t>(off + n));
        off += n;
    }
    uint32_t s1 = 1, s2 = 0;
    for (uint8_t byte : raw) {
        s1 = (s1 + byte) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    const uint32_t adler32 = (s2 << 16) | s1;
    z.push_back(static_cast<uint8_t>(adler32 >> 24));
    z.push_back(static_cast<uint8_t>(adler32 >> 16));
    z.push_back(static_cast<uint8_t>(adler32 >> 8));
    z.push_back(static_cast<uint8_t>(adler32));

    uint8_t ihdr[13] = {};
    ihdr[0] = static_cast<uint8_t>(kRtWidth >> 24);
    ihdr[1] = static_cast<uint8_t>(kRtWidth >> 16);
    ihdr[2] = static_cast<uint8_t>(kRtWidth >> 8);
    ihdr[3] = static_cast<uint8_t>(kRtWidth);
    ihdr[4] = static_cast<uint8_t>(kRtHeight >> 24);
    ihdr[5] = static_cast<uint8_t>(kRtHeight >> 16);
    ihdr[6] = static_cast<uint8_t>(kRtHeight >> 8);
    ihdr[7] = static_cast<uint8_t>(kRtHeight);
    ihdr[8] = 8;
    ihdr[9] = 6;
    std::vector<uint8_t> png = {137, 80, 78, 71, 13, 10, 26, 10};
    png_chunk(png, "IHDR", ihdr, 13);
    png_chunk(png, "IDAT", z.data(), static_cast<uint32_t>(z.size()));
    png_chunk(png, "IEND", nullptr, 0);
    FILE* f = std::fopen(path, "wb");
    if (!f) return false;
    const size_t n = std::fwrite(png.data(), 1, png.size(), f);
    std::fclose(f);
    return n == png.size();
}

} // namespace

uint32_t kick(const CommandList& cmdlist) {
    uint32_t n = 0;
    for (const DrawCall& d : cmdlist.draws)
        n += d.indexed ? d.index_count : d.vertex_count;
    submit(cmdlist);
    static int logs = 0;
    if (logs < 8 && !cmdlist.draws.empty()) {
        ++logs;
        std::fprintf(stderr, "    [gpu] kick draws=%zu verts=%u colors=%u\n",
                     cmdlist.draws.size(), n, distinct_colors());
    }
    return n;
}

void submit(const CommandList& cmdlist) {
    if (cmdlist.clear) {
        const uint8_t px[4] = {chan(cmdlist.clear_rgba[0]), chan(cmdlist.clear_rgba[1]),
                               chan(cmdlist.clear_rgba[2]), chan(cmdlist.clear_rgba[3])};
        for (uint32_t i = 0; i < kRtWidth * kRtHeight; ++i) std::memcpy(g_rt + i * 4, px, 4);
    } else {
        std::memset(g_rt, 0, sizeof(g_rt));
    }
    for (const DrawCall& d : cmdlist.draws) {
        uint32_t instances = d.instance_count == 0 ? 1 : d.instance_count;
        for (uint32_t n = 0; n < instances; ++n) draw_one(d);
    }
}

const uint8_t* render_target() { return g_rt; }

uint32_t distinct_colors() {
    std::unordered_set<uint32_t> colors;
    for (uint32_t i = 0; i < kRtWidth * kRtHeight; ++i) {
        uint32_t p = 0;
        std::memcpy(&p, g_rt + i * 4, 4);
        if ((p & 0x00FFFFFFu) == 0) continue;
        colors.insert(p & 0x00FFFFFFu);
        if (colors.size() > 8) break;
    }
    return static_cast<uint32_t>(colors.size());
}

bool present(uint64_t backbuffer_va) {
    g_present_va = backbuffer_va;
    if (distinct_colors() < 2) return false;
    return write_png("/tmp/basalt-present.png");
}

uint64_t last_present_va() { return g_present_va; }

} // namespace emu::gpu
