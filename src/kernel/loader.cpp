#include "kernel/loader.h"
#include <fstream>
#include <cstring>
#include <cctype>
#include <filesystem>

namespace emu::kernel {

Loader::Loader(memory::MemoryMap& mem) : mem_(mem) {}

bool Loader::validate_pe(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(DOSHeader)) return false;

    const auto* dos = reinterpret_cast<const DOSHeader*>(data.data());
    if (dos->e_magic != 0x5A4D) return false; // 'MZ'

    uint32_t pe_off = dos->e_lfanew;
    if (pe_off + sizeof(PEHeader) > data.size()) return false;

    const auto* pe = reinterpret_cast<const PEHeader*>(data.data() + pe_off);
    if (pe->signature != 0x00004550) return false; // 'PE\0\0'
    if (pe->machine   != 0x8664)     return false; // AMD64 only

    return true;
}

void Loader::map_sections(const std::vector<uint8_t>& data,
                          const PEHeader&             pe,
                          const PEOptionalHeader64&   opt,
                          uint64_t                    base) {
    uint32_t pe_off      = reinterpret_cast<const DOSHeader*>(data.data())->e_lfanew;
    uint32_t sec_offset  = pe_off + sizeof(PEHeader) + pe.optional_hdr_size;

    for (uint16_t i = 0; i < pe.num_sections; ++i) {
        const auto* sec = reinterpret_cast<const SectionHeader*>(
            data.data() + sec_offset + i * sizeof(SectionHeader));

        uint64_t vaddr   = base + sec->virtual_address;
        uint32_t raw_off = sec->raw_offset;
        uint32_t raw_sz  = sec->raw_size;
        uint32_t virt_sz = sec->virtual_size;

        // Copy initialized data
        uint32_t copy_sz = std::min(raw_sz, virt_sz);
        if (raw_off + copy_sz <= data.size()) {
            uint8_t* dst = mem_.raw_ptr(vaddr, copy_sz);
            if (dst) std::memcpy(dst, data.data() + raw_off, copy_sz);
        }

        // Zero BSS tail (virtual_size > raw_size)
        if (virt_sz > raw_sz) {
            uint8_t* dst = mem_.raw_ptr(vaddr + raw_sz, virt_sz - raw_sz);
            if (dst) std::memset(dst, 0, virt_sz - raw_sz);
        }
    }
}

std::optional<LoadedImage> Loader::load_pe(const std::string& path, uint64_t preferred_base) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return std::nullopt;

    std::streamsize sz = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(sz);
    if (!f.read(reinterpret_cast<char*>(data.data()), sz)) return std::nullopt;

    if (!validate_pe(data)) return std::nullopt;

    const auto* dos = reinterpret_cast<const DOSHeader*>(data.data());
    uint32_t    pe_off = dos->e_lfanew;
    const auto* pe  = reinterpret_cast<const PEHeader*>(data.data() + pe_off);
    const auto* opt = reinterpret_cast<const PEOptionalHeader64*>(
        data.data() + pe_off + sizeof(PEHeader));

    if (opt->magic != 0x020B) return std::nullopt; // must be PE32+

    uint64_t load_base = (preferred_base != 0) ? preferred_base : opt->image_base;

    if (uint8_t* h = mem_.raw_ptr(load_base, opt->headers_size))
        std::memcpy(h, data.data(), std::min<size_t>(opt->headers_size, data.size()));
    map_sections(data, *pe, *opt, load_base);

    struct DataDir { uint32_t rva, size; };
    const auto* dirs = reinterpret_cast<const DataDir*>(opt + 1);
    auto dir = [&](uint32_t i) { return i < opt->num_data_dirs ? dirs[i] : DataDir{0, 0}; };

    std::string mod = std::filesystem::path(path).filename().string();
    for (auto& c : mod) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (int64_t delta = static_cast<int64_t>(load_base - opt->image_base))
        apply_relocs(load_base, dir(5).rva, dir(5).size, delta);
    parse_exports(mod, load_base, dir(0).rva, dir(0).size);
    bind_imports(load_base, dir(1).rva);

    LoadedImage img{
        .base_vaddr  = load_base,
        .entry_point = load_base + opt->entry_point_rva,
        .image_size  = opt->image_size,
        .name        = mod,
    };
    images_.push_back(img);
    return img;
}

std::string Loader::read_cstr(uint64_t va) const {
    std::string s;
    for (uint8_t c; (c = mem_.read8(va)) != 0 && s.size() < 512; ++va) s += static_cast<char>(c);
    return s;
}

void Loader::apply_relocs(uint64_t base, uint32_t rva, uint32_t size, int64_t delta) {
    uint64_t p = base + rva, end = p + size;
    while (rva && p + 8 <= end) {
        uint32_t page  = mem_.read32(p);
        uint32_t bsize = mem_.read32(p + 4);
        if (bsize < 8) break;
        for (uint32_t i = 8; i + 2 <= bsize; i += 2) {
            uint16_t e = mem_.read16(p + i);
            uint64_t at = base + page + (e & 0xFFF);
            switch (e >> 12) {
                case 10: mem_.write64(at, mem_.read64(at) + delta); break;               // DIR64
                case 3:  mem_.write32(at, mem_.read32(at) + static_cast<uint32_t>(delta)); break; // HIGHLOW
                default: break;
            }
        }
        p += bsize;
    }
}

void Loader::parse_exports(const std::string& mod, uint64_t base, uint32_t rva, uint32_t size) {
    if (!rva) return;
    uint64_t d = base + rva;
    uint32_t n_names = mem_.read32(d + 24);
    uint32_t funcs   = mem_.read32(d + 28);
    uint32_t names   = mem_.read32(d + 32);
    uint32_t ords    = mem_.read32(d + 36);
    auto& tbl = exports_[mod];
    for (uint32_t i = 0; i < n_names; ++i) {
        std::string name = read_cstr(base + mem_.read32(base + names + i * 4));
        uint16_t ord = mem_.read16(base + ords + i * 2);
        uint32_t frva = mem_.read32(base + funcs + ord * 4);
        // Forwarders (rva inside the export dir) are left unresolved → thunk.
        if (frva >= rva && frva < rva + size) continue;
        tbl[name] = base + frva;
    }
}

void Loader::bind_imports(uint64_t base, uint32_t rva) {
    if (!rva) return;
    for (uint64_t d = base + rva;; d += 20) {
        uint32_t ilt = mem_.read32(d), name_rva = mem_.read32(d + 12), iat = mem_.read32(d + 16);
        if (!name_rva) break;
        std::string mod = read_cstr(base + name_rva);
        std::string lmod = mod;
        for (auto& c : lmod) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        auto mit = exports_.find(lmod);
        uint64_t lookup = base + (ilt ? ilt : iat);
        for (uint64_t k = 0;; ++k) {
            uint64_t ent = mem_.read64(lookup + k * 8);
            if (!ent) break;
            std::string fn = (ent >> 63) ? "#" + std::to_string(ent & 0xFFFF)
                                         : read_cstr(base + (ent & 0x7FFFFFFF) + 2);
            uint64_t target = 0;
            if (mit != exports_.end())
                if (auto f = mit->second.find(fn); f != mit->second.end()) target = f->second;
            if (!target) target = make_thunk(mod, fn);
            mem_.write64(base + iat + k * 8, target);
        }
    }
}

std::optional<uint64_t> Loader::find_export(const std::string& name) const {
    for (auto& [m, tbl] : exports_)
        if (auto f = tbl.find(name); f != tbl.end()) return f->second;
    return std::nullopt;
}

uint64_t Loader::make_thunk(const std::string& module, const std::string& name) {
    std::string key = module + "!" + name;
    if (auto it = thunk_index_.find(key); it != thunk_index_.end()) return it->second;
    if (thunks_.size() >= THUNK_MAX) return 0;
    uint64_t addr = THUNK_BASE + thunks_.size() * THUNK_STRIDE;
    thunks_.push_back({module, name});
    thunk_index_[key] = addr;
    mem_.write8(addr, 0xF4); // HLT: safety net if the run loop misses it
    return addr;
}

const Thunk* Loader::thunk_at(uint64_t addr) const {
    if (addr < THUNK_BASE || (addr - THUNK_BASE) % THUNK_STRIDE) return nullptr;
    uint64_t i = (addr - THUNK_BASE) / THUNK_STRIDE;
    return i < thunks_.size() ? &thunks_[i] : nullptr;
}

bool Loader::load_raw(const std::string& path, uint64_t load_addr) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;

    std::streamsize sz = f.tellg();
    f.seekg(0, std::ios::beg);

    uint8_t* dst = mem_.raw_ptr(load_addr, sz);
    if (!dst) return false;

    return !!f.read(reinterpret_cast<char*>(dst), sz);
}

} // namespace emu::kernel
