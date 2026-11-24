#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <map>
#include "../memory/memory_map.h"

namespace emu::kernel {

// Xbox Series S runs a custom Windows 10 (GameCore) kernel derivative.
// Executables are PE32+ (x86-64), DLLs are standard PE format.
// The bootloader chain: SoC ROM → bootloader → hypervisor → Xbox kernel.

// PE32+ structures (minimal, for loading)
#pragma pack(push, 1)
struct DOSHeader {
    uint16_t e_magic;    // MZ
    uint8_t  e_pad[58];
    uint32_t e_lfanew;   // offset to PE header
};

struct PEHeader {
    uint32_t signature;  // PE\0\0
    uint16_t machine;    // 0x8664 for AMD64
    uint16_t num_sections;
    uint32_t timestamp;
    uint32_t symbol_table_ptr;
    uint32_t num_symbols;
    uint16_t optional_hdr_size;
    uint16_t characteristics;
};

struct PEOptionalHeader64 {
    uint16_t magic;          // 0x020B for PE32+
    uint8_t  linker_ver_maj;
    uint8_t  linker_ver_min;
    uint32_t code_size;
    uint32_t init_data_size;
    uint32_t uninit_data_size;
    uint32_t entry_point_rva;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t os_ver_maj, os_ver_min;
    uint16_t image_ver_maj, image_ver_min;
    uint16_t subsystem_ver_maj, subsystem_ver_min;
    uint32_t win32_version;
    uint32_t image_size;
    uint32_t headers_size;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t stack_reserve, stack_commit;
    uint64_t heap_reserve,  heap_commit;
    uint32_t loader_flags;
    uint32_t num_data_dirs;
};

struct SectionHeader {
    char     name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t reloc_offset;
    uint32_t line_num_offset;
    uint16_t num_relocs;
    uint16_t num_line_nums;
    uint32_t characteristics;
};
#pragma pack(pop)

struct LoadedImage {
    uint64_t    base_vaddr;
    uint64_t    entry_point;
    uint64_t    image_size;
    std::string name;
};

// Unresolved import: the IAT slot points at a unique address in the thunk
// range; the run loop intercepts rip landing there and emulates the call.
struct Thunk {
    std::string module;
    std::string name;
};

class Loader {
public:
    static constexpr uint64_t THUNK_BASE   = 0x3F0000000ULL;
    static constexpr uint64_t THUNK_STRIDE = 0x10;
    static constexpr uint64_t THUNK_MAX    = 0x10000;

    explicit Loader(memory::MemoryMap& mem);

    // Load PE32+ image: map sections + headers, apply relocations, register
    // exports, bind imports (to already-loaded modules or to thunks).
    std::optional<LoadedImage> load_pe(const std::string& path, uint64_t preferred_base = 0);

    // Load raw binary (boot ROM, firmware blobs)
    bool load_raw(const std::string& path, uint64_t load_addr);

    std::optional<uint64_t> find_export(const std::string& name) const;
    uint64_t make_thunk(const std::string& module, const std::string& name);
    const Thunk* thunk_at(uint64_t addr) const;
    const std::vector<LoadedImage>& images() const { return images_; }

private:
    memory::MemoryMap& mem_;
    std::map<std::string, std::map<std::string, uint64_t>> exports_; // lowercase module → name → va
    std::map<std::string, uint64_t> thunk_index_;                    // "module!name" → addr
    std::vector<Thunk>       thunks_;
    std::vector<LoadedImage> images_;

    std::string read_cstr(uint64_t va) const;
    void apply_relocs(uint64_t base, uint32_t rva, uint32_t size, int64_t delta);
    void parse_exports(const std::string& mod, uint64_t base, uint32_t rva, uint32_t size);
    void bind_imports(uint64_t base, uint32_t rva);

    bool validate_pe(const std::vector<uint8_t>& data);
    void map_sections(const std::vector<uint8_t>& data,
                      const PEHeader&             pe,
                      const PEOptionalHeader64&   opt,
                      uint64_t                    base);
};

} // namespace emu::kernel
