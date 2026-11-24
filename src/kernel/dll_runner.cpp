#include <strings.h>
#include "kernel/dll_runner.h"
#include "kernel/xbox_gdk_stubs.h"
#include "cpu/mnemonic_names.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>

namespace emu::kernel {

namespace {
constexpr uint64_t TEB          = DllRunner::kMainTeb;
constexpr uint64_t PEB          = DllRunner::kMainPeb;
constexpr uint64_t STACK_TOP    = DllRunner::kMainStackTop;
constexpr uint64_t STACK_SIZE   = DllRunner::kMainStackSize;
constexpr uint64_t HEAP_BASE    = 0x300000000ULL;
constexpr uint64_t VALLOC_BASE  = 0x040000000ULL; // 1.0 GiB .. 12.0 GiB virtual window (11 GiB for 4-6 GiB XMem reservations)
constexpr uint64_t VALLOC_LIMIT = 0x300000000ULL;
constexpr uint64_t VALLOC_ALIGN = 0x10000ULL;
constexpr uint64_t SENTINEL     = DllRunner::kSentinel;
constexpr uint64_t DLL_BASE     = 0x180000000ULL;
constexpr uint64_t DLL_STRIDE   = 0x1000000ULL;

constexpr uint64_t INVALID_HANDLE_VAL = ~0ULL;
constexpr uint32_t WAIT_OBJECT_0      = 0x00000000u;
constexpr uint32_t WAIT_TIMEOUT       = 0x00000102u;
constexpr uint32_t WAIT_FAILED        = 0xFFFFFFFFu;
constexpr uint32_t MEM_COMMIT         = 0x00001000u;
constexpr uint32_t MEM_RESERVE        = 0x00002000u;
constexpr uint32_t MEM_RELEASE        = 0x00008000u;

const char* const LOAD_ORDER[] = {
    "vcruntime140.dll", "vcruntime140_1.dll",
    "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
    "msvcp140_atomic_wait.dll", "msvcp140_codecvt_ids.dll",
    "concrt140.dll", "vccorlib140.dll", "vcomp140.dll",
    "XCurl.dll", "libHttpClient.GDK.dll",    "amd_fidelityfx_loader_xbox.dll", "amd_fidelityfx_upscaler_xbox.dll",
    "XboxBvhBuilder.dll",
};

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

const char* stop_name(int s) {
    static const char* n[] = {"returned", "fault", "halt", "wild-jump", "budget", "aborted"};
    return n[s];
}

// ── XGameRuntime / COM fake-object state (per DllRunner instance) ────────────
struct GdkQueryRecord {
    std::string provider;
    std::string iid;
    uint32_t    hr     = 0;
    uint64_t    calls  = 0;
    std::string note;
};

struct GdkMethodKey {
    std::string iid;
    int         index = 0;
    bool operator<(const GdkMethodKey& o) const {
        if (iid != o.iid) return iid < o.iid;
        return index < o.index;
    }
};

struct GdkMethodStats {
    uint64_t    calls = 0;
    std::string stub_desc;
};

struct GdkComState {
    std::map<std::string, uint64_t>                iid_vtables; // iid -> vtable VA (64 entries)
    std::map<std::pair<std::string, std::string>, GdkQueryRecord> queries;
    std::map<GdkMethodKey, GdkMethodStats>         methods;
    uint64_t                                       init_calls   = 0;
    uint64_t                                       uninit_calls = 0;
    std::vector<std::pair<uint64_t, uint64_t>>     valloc_freed;
    int                                            valloc_log   = 0;
    int                                            alloc_log    = 0;
    uint64_t                                       argc_va      = 0;
    uint64_t                                       argv_va      = 0;
    uint64_t                                       xmem_alloc_hook = 0;
    uint64_t                                       xmem_free_hook  = 0;
    uint64_t                                       xmem_hysteresis = 0;
};

constexpr uint32_t kRegdbEClassNotReg = 0x80040154u;

bool should_deny_gdk_guid(const std::string& provider, const std::string& iid) {
    (void)provider;
    (void)iid;
    return false;
}

std::map<const DllRunner*, GdkComState> g_gdk_states;
static int g_sync_log = 0;

std::string format_guid(const memory::MemoryMap& mem, uint64_t va) {
    if (!va) return "{null}";
    uint32_t d1 = mem.read32(va + 0);
    uint16_t d2 = mem.read16(va + 4);
    uint16_t d3 = mem.read16(va + 6);
    uint8_t  d4[8];
    for (int i = 0; i < 8; ++i) d4[i] = mem.read8(va + 8 + i);
    char buf[64];
    std::snprintf(buf, sizeof(buf),
                  "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
                  d1, d2, d3,
                  d4[0], d4[1],
                  d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]);
    return buf;
}

void dump_gdk_summary(const GdkComState& st) {
    if (st.queries.empty() && st.methods.empty() && st.init_calls == 0 && st.uninit_calls == 0)
        return;
    std::fprintf(stderr, "\n  [gdk] XGameRuntime summary (init=%llu, uninit=%llu, %zu GUID pair(s), %zu method(s)):\n",
                 static_cast<unsigned long long>(st.init_calls),
                 static_cast<unsigned long long>(st.uninit_calls),
                 st.queries.size(), st.methods.size());
    for (const auto& [key, rec] : st.queries) {
        std::fprintf(stderr, "    [gdk-query] provider=%s iid=%s calls=%llu hr=0x%08x%s%s\n",
                     rec.provider.c_str(), rec.iid.c_str(),
                     static_cast<unsigned long long>(rec.calls),
                     rec.hr,
                     rec.note.empty() ? "" : " ",
                     rec.note.c_str());
    }
    for (const auto& [mkey, mst] : st.methods) {
        std::fprintf(stderr, "    [gdk-method] iid=%s m%-2d calls=%-6llu stub=%s\n",
                     mkey.iid.c_str(), mkey.index,
                     static_cast<unsigned long long>(mst.calls),
                     mst.stub_desc.c_str());
    }
}
} // namespace

DllRunner::DllRunner(memory::MemoryMap& mem, cpu::CPU& cpu)
    : mem_(mem), cpu_(cpu), loader_(mem), ring_(16, 0) {}

DllRunner::~DllRunner() {
    dump_milestones();
    if (!unknown_counts_.empty()) {
        std::vector<std::pair<std::string, uint64_t>> sorted_unk(unknown_counts_.begin(), unknown_counts_.end());
        std::sort(sorted_unk.begin(), sorted_unk.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        std::fprintf(stderr, "\n  [unknown] unresolved import call summary (%zu function(s)):\n",
                     sorted_unk.size());
        for (const auto& [name, cnt] : sorted_unk) {
            std::fprintf(stderr, "    %-48s calls=%llu\n",
                         name.c_str(), static_cast<unsigned long long>(cnt));
        }
    }
    if (auto it = g_gdk_states.find(this); it != g_gdk_states.end()) {
        dump_gdk_summary(it->second);
        g_gdk_states.erase(it);
    }
    for (auto& [h, fh] : files_) {
        if (fh.fp) {
            std::fclose(fh.fp);
            fh.fp = nullptr;
        }
    }
    files_.clear();
}

std::string DllRunner::describe_handle(uint64_t h) const {
    char buf[256];
    if (auto it = events_.find(h); it != events_.end()) {
        std::snprintf(buf, sizeof(buf), "event(0x%llx, manual=%d, sig=%d, name=\"%s\")",
                      static_cast<unsigned long long>(h),
                      it->second.manual_reset ? 1 : 0,
                      it->second.signaled ? 1 : 0,
                      it->second.name.c_str());
        return buf;
    }
    if (auto it = files_.find(h); it != files_.end()) {
        std::snprintf(buf, sizeof(buf), "file(0x%llx, \"%s\")",
                      static_cast<unsigned long long>(h),
                      it->second.guest_path.c_str());
        return buf;
    }
    if (auto it = task_queues_.find(h); it != task_queues_.end()) {
        std::snprintf(buf, sizeof(buf), "task_queue(0x%llx, items=%zu)",
                      static_cast<unsigned long long>(h),
                      it->second.items.size());
        return buf;
    }
    std::snprintf(buf, sizeof(buf), "handle(0x%llx)", static_cast<unsigned long long>(h));
    return buf;
}

void DllRunner::pump_auto_task_queues() {
    bool did_work = true;
    int guard = 0;
    while (did_work && !abort_ && guard++ < 64) {
        did_work = false;
        for (auto& [qh, q] : task_queues_) {
            for (size_t i = 0; i < q.items.size(); ) {
                uint32_t mode = (q.items[i].port == 0) ? q.work_mode : q.comp_mode;
                // XTaskQueueDispatchMode: 0 = ThreadPool, 1 = SerializedThreadPool, 3 = Immediate
                if (mode == 0 || mode == 1 || mode == 3) {
                    TaskQueueItem item = q.items[i];
                    q.items.erase(q.items.begin() + static_cast<std::ptrdiff_t>(i));
                    std::fprintf(stderr, "    [taskq] auto-dispatch queue=0x%llx port=%llu cb=0x%llx (%s) ctx=0x%llx\n",
                                 static_cast<unsigned long long>(qh),
                                 static_cast<unsigned long long>(item.port),
                                 static_cast<unsigned long long>(item.callback),
                                 where(item.callback).c_str(),
                                 static_cast<unsigned long long>(item.context));
                    call_guest(item.callback, item.context, 0);
                    did_work = true;
                    break;
                } else {
                    ++i;
                }
            }
            if (did_work || abort_) break;
        }
    }
}

void DllRunner::record_milestone(const std::string& label, uint64_t va) {
    if (!milestone_seen_.insert(va).second) return;
    milestones_.push_back(Milestone{label, va, insn_count_, current_tid_});
    std::fprintf(stderr, "  [milestone] %-36s at 0x%llx (%s) tid=%u insns=%llu\n",
                 label.c_str(),
                 static_cast<unsigned long long>(va),
                 where(va).c_str(),
                 current_tid_,
                 static_cast<unsigned long long>(insn_count_));
    std::fflush(stderr);
}

void DllRunner::dump_milestones() const {
    if (milestones_.empty()) return;
    std::fprintf(stderr, "\n  [milestone] summary (%zu reached):\n", milestones_.size());
    for (const auto& m : milestones_) {
        std::fprintf(stderr, "    insns=%-12llu tid=%-4u 0x%llx (%s) — %s\n",
                     static_cast<unsigned long long>(m.insns),
                     m.tid,
                     static_cast<unsigned long long>(m.va),
                     where(m.va).c_str(),
                     m.label.c_str());
    }
}

uint32_t DllRunner::get_last_error() const {
    if (auto it = last_errors_.find(current_tid_); it != last_errors_.end())
        return it->second;
    return 0;
}

void DllRunner::set_last_error(uint32_t err) {
    last_errors_[current_tid_] = err;
}

uint64_t DllRunner::alloc(uint64_t size, uint64_t align) {
    constexpr uint64_t kHeapCeiling = 0x3B0000000ULL; // keep clear of stacks at 0x3CE000000
    heap_top_ = (heap_top_ + align - 1) & ~(align - 1);
    uint64_t p = heap_top_;
    if (size == 0) size = 1;
    if (size > kHeapCeiling - HEAP_BASE || p + size > kHeapCeiling) {
        std::fprintf(stderr, "    [mem] alloc OOM/cap: size=0x%llx heap_top=0x%llx (insns=%llu)\n",
                     static_cast<unsigned long long>(size),
                     static_cast<unsigned long long>(heap_top_),
                     static_cast<unsigned long long>(insn_count_));
        return 0;
    }
    heap_top_ += size;
    // Bump heap only ever advances into fresh zero-backed MemoryMap pages;
    // avoid std::fill so large reservations do not fault gigabytes of host RAM.
    if (size >= (16ULL << 20)) {
        auto& st = g_gdk_states[this];
        if (st.alloc_log < 20) {
            ++st.alloc_log;
            std::fprintf(stderr, "    [mem] large alloc size=0x%llx (%llu MB) -> 0x%llx\n",
                         static_cast<unsigned long long>(size),
                         static_cast<unsigned long long>(size >> 20),
                         static_cast<unsigned long long>(p));
        }
    }
    alloc_sizes_[p] = size;
    return p;
}

uint64_t DllRunner::alloc_stack(uint64_t size) {
    if (size < STACK_SIZE) size = STACK_SIZE;
    size = (size + VALLOC_ALIGN - 1) & ~(VALLOC_ALIGN - 1);
    uint64_t top = stack_cursor_;
    uint64_t base = top - size;
    stack_cursor_ = base - VALLOC_ALIGN; // guard gap
    return top;
}

// copy every loaded image's .tls template into the thread's slot array.
// msvc thread-safe statics rely on _Init_thread_epoch starting at INT_MIN from
// this template; a zeroed slot makes every guarded static look initialized.
void DllRunner::init_tls_slots(uint64_t tls_arr) {
    uint32_t idx = 0;
    for (auto& img : loader_.images()) {
        uint64_t b   = img.base_vaddr;
        uint64_t nt  = b + mem_.read32(b + 0x3c);
        uint64_t opt = nt + 0x18;
        if (mem_.read32(nt) != 0x4550 || mem_.read16(opt) != 0x20b) continue;
        uint32_t rva = mem_.read32(opt + 0x70 + 9 * 8);
        if (!rva) continue;
        uint64_t dir   = b + rva;
        uint64_t start = mem_.read64(dir), end = mem_.read64(dir + 8);
        uint64_t pidx  = mem_.read64(dir + 16);
        uint32_t zf    = mem_.read32(dir + 32);
        uint64_t size  = (end - start) + zf;
        if (idx >= 64 || end < start || size > 0x100000) continue;
        uint64_t blk = mem_.read64(tls_arr + idx * 8);
        if (size > 0x4000) { blk = alloc(size); mem_.write64(tls_arr + idx * 8, blk); }
        for (uint64_t i = 0; i < size; ++i)
            mem_.write8(blk + i, i < end - start ? mem_.read8(start + i) : 0);
        if (pidx) mem_.write32(pidx, idx);
        static int logged = 0;
        if (logged++ < 4)
            std::fprintf(stderr, "  [tls] %s slot=%u size=0x%llx\n", img.name.c_str(), idx,
                         (unsigned long long)size);
        ++idx;
    }
}

uint64_t DllRunner::alloc_teb(uint64_t stack_top, uint64_t stack_size, uint32_t tid) {
    uint64_t teb = alloc(0x2000, 0x1000);
    uint64_t tls_arr = alloc(64 * 8);
    for (int i = 0; i < 64; ++i) mem_.write64(tls_arr + i * 8, alloc(0x4000));
    init_tls_slots(tls_arr);
    mem_.write64(teb + 0x08, stack_top);
    mem_.write64(teb + 0x10, stack_top - stack_size);
    mem_.write64(teb + 0x30, teb);
    mem_.write64(teb + 0x40, 0x4);
    mem_.write64(teb + 0x48, tid);
    mem_.write64(teb + 0x58, tls_arr);
    mem_.write64(teb + 0x60, PEB);
    mem_.write32(teb + 0x68, 0);
    return teb;
}

uint64_t DllRunner::virtual_alloc(uint64_t req_addr, uint64_t size, uint32_t alloc_type) {
    uint64_t raw_size = size ? size : VALLOC_ALIGN;

    auto& st = g_gdk_states[this];
    auto zero_reused = [&](uint64_t base, uint64_t sz) {
        if (st.valloc_freed.empty()) return;
        uint64_t end = base + sz;
        std::vector<std::pair<uint64_t, uint64_t>> next_freed;
        for (const auto& [fb, fe] : st.valloc_freed) {
            if (fe <= base || fb >= end) {
                next_freed.push_back({fb, fe});
                continue;
            }
            uint64_t ob = std::max(base, fb);
            uint64_t oe = std::min(end, fe);
            if (uint8_t* d = mem_.raw_ptr(ob, oe - ob))
                std::fill(d, d + (oe - ob), 0);
            if (fb < ob) next_freed.push_back({fb, ob});
            if (oe < fe) next_freed.push_back({oe, fe});
        }
        st.valloc_freed.swap(next_freed);
    };

    auto log_valloc = [&](uint64_t res) {
        if (raw_size >= (1ULL << 20) && st.valloc_log < 50) {
            ++st.valloc_log;
            std::fprintf(stderr, "    [mem] VirtualAlloc req=0x%llx size=0x%llx (%llu MB) type=0x%x -> 0x%llx\n",
                         static_cast<unsigned long long>(req_addr),
                         static_cast<unsigned long long>(raw_size),
                         static_cast<unsigned long long>(raw_size >> 20),
                         alloc_type,
                         static_cast<unsigned long long>(res));
        }
    };

    // If committing inside an already reserved block, preserve existing contents.
    // Also MEM_REPLACE_PLACEHOLDER (0x4000): the caller maps a view over a
    // placeholder it reserved earlier, the address must be honoured as-is.
    if (req_addr != 0 && (((alloc_type & MEM_COMMIT) && !(alloc_type & MEM_RESERVE)) ||
                          (alloc_type & 0x4000))) {
        for (const auto& [base, sz] : vallocs_) {
            if (req_addr >= base && req_addr < base + sz) {
                uint64_t r = req_addr & ~0xFFFULL;
                log_valloc(r);
                return r;
            }
        }
    }

    auto overlaps = [&](uint64_t base, uint64_t sz) -> bool {
        if (base < VALLOC_ALIGN || base + sz < base || base + sz > memory::XBSS_RAM_SIZE)
            return true;
        // Avoid low MMIO aperture [0xE0000000, 0x100000000)
        if (!(base + sz <= 0xE0000000ULL || base >= 0x100000000ULL))
            return true;
        // Keep clear of heap, stacks, TEB/PEB, and thunk area.
        if (!(base + sz <= HEAP_BASE || base >= memory::XBSS_RAM_SIZE))
            return true;
        for (const auto& img : loader_.images()) {
            uint64_t img_end = (img.base_vaddr + img.image_size + VALLOC_ALIGN - 1) & ~(VALLOC_ALIGN - 1);
            if (!(base + sz <= img.base_vaddr || base >= img_end))
                return true;
        }
        for (const auto& [ebase, esz] : vallocs_) {
            if (!(base + sz <= ebase || base >= ebase + esz))
                return true;
        }
        return false;
    };

    // Respect requested address if free (aligned down to 64 KiB).
    if (req_addr != 0) {
        uint64_t aligned_base = req_addr & ~(VALLOC_ALIGN - 1);
        uint64_t aligned_end  = (req_addr + raw_size + VALLOC_ALIGN - 1) & ~(VALLOC_ALIGN - 1);
        uint64_t aligned_sz   = aligned_end - aligned_base;
        if (!overlaps(aligned_base, aligned_sz)) {
            zero_reused(aligned_base, aligned_sz);
            vallocs_[aligned_base] = aligned_sz;
            log_valloc(aligned_base);
            return aligned_base;
        }
        // If caller explicitly passed MEM_COMMIT on an already-mapped range, let it succeed.
        if (alloc_type & MEM_COMMIT) {
            for (const auto& [base, sz] : vallocs_) {
                if (req_addr >= base && req_addr < base + sz)
                    return req_addr & ~0xFFFULL;
            }
        }
    }

    // First-fit 64 KiB aligned allocation in [VALLOC_BASE, VALLOC_LIMIT),
    // skipping loaded PE images (exe @ 0x140000000, DLLs @ 0x180000000) and existing vallocs.
    uint64_t align = VALLOC_ALIGN;
    if (alloc_type & 0x20000000u) { // MEM_LARGE_PAGES / 2 MiB or 4 MiB pages
        align = 0x400000ULL;
    }
    uint64_t aligned_sz = (raw_size + align - 1) & ~(align - 1);
    std::vector<std::pair<uint64_t, uint64_t>> intervals;
    intervals.reserve(vallocs_.size() + loader_.images().size() + 1);
    // Avoid low MMIO aperture [0xE0000000, 0x100000000)
    intervals.push_back({0xE0000000ULL, 0x20000000ULL});
    for (const auto& img : loader_.images()) {
        uint64_t img_end = (img.base_vaddr + img.image_size + VALLOC_ALIGN - 1) & ~(VALLOC_ALIGN - 1);
        intervals.push_back({img.base_vaddr, img_end - img.base_vaddr});
    }
    for (const auto& [ebase, esz] : vallocs_) {
        intervals.push_back({ebase, esz});
    }
    std::sort(intervals.begin(), intervals.end());

    uint64_t cand = (VALLOC_BASE + align - 1) & ~(align - 1);
    for (const auto& [ebase, esz] : intervals) {
        if (ebase + esz <= cand) continue;
        if (ebase >= VALLOC_LIMIT) break;
        if (cand + aligned_sz <= ebase) break;
        uint64_t next = (ebase + esz + align - 1) & ~(align - 1);
        if (next > cand) cand = next;
    }
    if (cand + aligned_sz <= VALLOC_LIMIT && !overlaps(cand, aligned_sz)) {
        zero_reused(cand, aligned_sz);
        vallocs_[cand] = aligned_sz;
        log_valloc(cand);
        return cand;
    }

    // Window exhausted / request larger than it: back the reservation with
    // lazy (MAP_NORESERVE) RAM above physical DRAM so only touched pages cost memory.
    if (aligned_sz >= 0x10000000ULL) {
        uint64_t base = (big_top_ + align - 1) & ~(align - 1);
        try {
            mem_.add_region(memory::make_lazy_ram(base, aligned_sz, "valloc-hi"));
        } catch (const std::bad_alloc&) { return 0; }
        big_top_ = base + aligned_sz + VALLOC_ALIGN;
        vallocs_[base] = aligned_sz;
        log_valloc(base);
        return base;
    }

    // Fallback to bump heap if arena is exhausted.
    uint64_t res = alloc(aligned_sz, align);
    log_valloc(res);
    return res;
}

bool DllRunner::virtual_free(uint64_t addr, uint32_t free_type) {
    if (!addr) return true;
    // MEM_PRESERVE_PLACEHOLDER (0x2): split/convert back to placeholder, the
    // reservation stays ours.
    if ((free_type & MEM_RELEASE) && !(free_type & 0x2)) {
        auto it = vallocs_.find(addr);
        if (it == vallocs_.end()) {
            // Check if addr falls within a tracked block.
            for (auto iter = vallocs_.begin(); iter != vallocs_.end(); ++iter) {
                if (addr >= iter->first && addr < iter->first + iter->second) {
                    it = iter;
                    break;
                }
            }
        }
        if (it != vallocs_.end()) {
            if (it->first >= memory::XBSS_RAM_SIZE) mem_.remove_region(it->first);
            g_gdk_states[this].valloc_freed.push_back({it->first, it->first + it->second});
            vallocs_.erase(it);
        }
    }
    return true;
}

void DllRunner::setup_teb_peb() {
    heap_top_ = HEAP_BASE;
    uint64_t tls_arr = alloc(64 * 8);
    for (int i = 0; i < 64; ++i) mem_.write64(tls_arr + i * 8, alloc(0x4000));
    mem_.write64(TEB + 0x08, STACK_TOP);
    mem_.write64(TEB + 0x10, STACK_TOP - STACK_SIZE);
    mem_.write64(TEB + 0x30, TEB);
    mem_.write64(TEB + 0x40, 0x4);
    mem_.write64(TEB + 0x48, 0x8);
    mem_.write64(TEB + 0x58, tls_arr);
    mem_.write64(TEB + 0x60, PEB);
    mem_.write32(TEB + 0x68, 0);
    mem_.write64(PEB + 0x30, 0xFEED0000); // ProcessHeap handle
    cpu_.regs().msr_gs_base = TEB;
}

uint64_t DllRunner::make_fake_com(const std::string& iid) {
    auto& st = g_gdk_states[this];
    uint64_t vtbl = 0;
    if (auto vit = st.iid_vtables.find(iid); vit != st.iid_vtables.end()) {
        vtbl = vit->second;
    } else {
        vtbl = alloc(512 * 8, 16);
        for (int i = 0; i < 512; ++i)
            mem_.write64(vtbl + static_cast<uint64_t>(i) * 8,
                         loader_.make_thunk("gdkobj", iid + "_m" + std::to_string(i)));
        st.iid_vtables[iid] = vtbl;
    }
    uint64_t obj = alloc(64, 16);
    mem_.write64(obj + 0, vtbl);
    mem_.write64(obj + 8, 1);
    return obj;
}

uint64_t DllRunner::arg(int i) {
    auto& r = cpu_.regs();
    switch (i) {
        case 0: return r.rcx;
        case 1: return r.rdx;
        case 2: return r.r8;
        case 3: return r.r9;
        default: return mem_.read64(r.rsp + 8 + i * 8); // rsp → return address on thunk entry
    }
}

std::string DllRunner::read_str(uint64_t va, bool wide) const {
    std::string s;
    if (!va) return s;
    for (int i = 0; i < 512; ++i) {
        uint16_t c = wide ? (mem_.read8(va + i * 2) | (mem_.read8(va + i * 2 + 1) << 8)) : mem_.read8(va + i);
        if (!c) break;
        s += static_cast<char>(c < 0x80 ? c : '?');
    }
    return s;
}

void DllRunner::write_wstr(uint64_t va, const std::string& s) {
    for (size_t i = 0; i < s.size(); ++i) mem_.write16(va + i * 2, static_cast<uint8_t>(s[i]));
    mem_.write16(va + s.size() * 2, 0);
}

void DllRunner::write_cstr(uint64_t va, const std::string& s) {
    for (size_t i = 0; i < s.size(); ++i) mem_.write8(va + i, static_cast<uint8_t>(s[i]));
    mem_.write8(va + s.size(), 0);
}

std::string DllRunner::resolve_host_path(const std::string& xbox_path, bool* found) const {
    namespace fs = std::filesystem;
    if (found) *found = false;
    if (game_dir_.empty() || xbox_path.empty()) return {};

    std::string p = xbox_path;
    // Strip Win32 extended/NT prefixes if present.
    if (p.rfind("\\\\?\\", 0) == 0 || p.rfind("\\??\\", 0) == 0)
        p.erase(0, 4);

    // Normalize slashes.
    std::replace(p.begin(), p.end(), '\\', '/');

    // Translate Xbox drive/mount prefixes (G:\, D:\, game:\) to game_dir_.
    std::string lp = lower(p);
    if (lp.rfind("g:/", 0) == 0 || lp.rfind("d:/", 0) == 0) {
        p.erase(0, 3);
    } else if (lp == "g:" || lp == "d:") {
        p.clear();
    } else if (lp.rfind("game:/", 0) == 0) {
        p.erase(0, 6);
    } else if (lp == "game:") {
        p.clear();
    } else if (lp.rfind("g:", 0) == 0 || lp.rfind("d:", 0) == 0) {
        p.erase(0, 2);
    } else if (lp.rfind("game:", 0) == 0) {
        p.erase(0, 5);
    } else if (p.size() >= 2 && p[1] == ':') {
        // Other drive letters (e.g., T:, U:, S:) also map under game_dir_ if present.
        p.erase(0, 2);
    }

    while (!p.empty() && p.front() == '/') p.erase(0, 1);

    // Split into path components and walk case-insensitively on Linux host.
    std::vector<std::string> parts;
    size_t start = 0;
    while (start < p.size()) {
        size_t slash = p.find('/', start);
        std::string comp = (slash == std::string::npos) ? p.substr(start) : p.substr(start, slash - start);
        if (!comp.empty() && comp != ".") parts.push_back(comp);
        if (slash == std::string::npos) break;
        start = slash + 1;
    }

    fs::path cur = game_dir_;
    std::error_code ec;
    for (size_t i = 0; i < parts.size(); ++i) {
        const std::string& comp = parts[i];
        fs::path direct = cur / comp;
        if (fs::exists(direct, ec)) {
            cur = direct;
            continue;
        }
        // Case-insensitive directory lookup.
        bool matched = false;
        std::string want = lower(comp);
        if (fs::is_directory(cur, ec)) {
            for (const auto& entry : fs::directory_iterator(cur, ec)) {
                if (lower(entry.path().filename().string()) == want) {
                    cur = entry.path();
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) {
            for (size_t j = i; j < parts.size(); ++j) cur /= parts[j];
            if (found) *found = false;
            return cur.string();
        }
    }

    if (found) *found = fs::exists(cur, ec);
    return cur.string();
}

uint64_t DllRunner::open_file(const std::string& guest_path, uint32_t access, uint32_t disp) {
    (void)access;
    (void)disp;
    namespace fs = std::filesystem;
    bool exists = false;
    std::string host_path = resolve_host_path(guest_path, &exists);
    std::error_code ec;
    if (!exists || fs::is_directory(host_path, ec)) {
        std::fprintf(stderr, "    [file] open FAIL \"%s\" -> \"%s\"\n",
                     guest_path.c_str(), host_path.c_str());
        set_last_error(2); // ERROR_FILE_NOT_FOUND
        return INVALID_HANDLE_VAL;
    }

    std::FILE* fp = std::fopen(host_path.c_str(), "rb");
    if (!fp) {
        std::fprintf(stderr, "    [file] open FAIL \"%s\" -> \"%s\"\n",
                     guest_path.c_str(), host_path.c_str());
        set_last_error(2);
        return INVALID_HANDLE_VAL;
    }

    uint64_t fsize = 0;
    if (fseeko(fp, 0, SEEK_END) == 0) {
        off_t end_pos = ftello(fp);
        if (end_pos > 0) fsize = static_cast<uint64_t>(end_pos);
        fseeko(fp, 0, SEEK_SET);
    }

    uint64_t h = (handle_next_ += 4);
    files_[h] = FileHandle{fp, guest_path, host_path, fsize};
    set_last_error(0);
    std::fprintf(stderr, "    [file] open handle=0x%llx \"%s\" -> \"%s\" (%llu bytes)\n",
                 static_cast<unsigned long long>(h),
                 guest_path.c_str(), host_path.c_str(),
                 static_cast<unsigned long long>(fsize));
    return h;
}

bool DllRunner::is_event_handle(uint64_t h) const {
    return events_.find(h) != events_.end();
}

bool DllRunner::is_event_signaled(uint64_t h) const {
    auto it = events_.find(h);
    if (it == events_.end()) return true;
    return it->second.signaled;
}

bool DllRunner::try_acquire_event(uint64_t h) {
    auto it = events_.find(h);
    if (it == events_.end()) return true;
    if (!it->second.signaled) return false;
    it->second.consume();
    return true;
}

uint64_t DllRunner::wait_single(uint64_t handle, uint32_t timeout_ms) {
    auto it = events_.find(handle);
    if (it != events_.end()) {
        if (it->second.signaled) {
            it->second.consume();
            return WAIT_OBJECT_0;
        }
        // timeout 0 is a poll; logging each one filled runs/ (hundreds of thousands of lines).
        if (timeout_ms != 0 && g_sync_log < 28) {
            ++g_sync_log;
            std::fprintf(stderr, "    [sync] WaitForSingleObject handle=0x%llx (event unsignaled) timeout=%u\n",
                         static_cast<unsigned long long>(handle), timeout_ms);
        }
        if (timeout_ms == 0) {
            uint64_t ret_va = mem_.read64(cpu_.regs().rsp);
            static int boot_polls = 0;
            if (ret_va - 0x140000000ULL == 0x5441bec && boot_polls < 4) {
                ++boot_polls;
                std::fprintf(stderr, "    [sync] boot-poll h=0x%llx sig=%d sem=%lld\n",
                             static_cast<unsigned long long>(handle),
                             it->second.signaled ? 1 : 0,
                             static_cast<long long>(it->second.sem_count));
            }
        }
        if (scheduler_mode_ && timeout_ms != 0) {
            wait_req_.active = true;
            wait_req_.wait_all = false;
            wait_req_.handles = {handle};
            return WAIT_OBJECT_0;
        }
        return WAIT_TIMEOUT;
    }

    std::fprintf(stderr, "    [sync] WaitForSingleObject handle=0x%llx (non-event) timeout=%u\n",
                 static_cast<unsigned long long>(handle), timeout_ms);
    return WAIT_OBJECT_0;
}

uint64_t DllRunner::wait_multiple(uint32_t count, uint64_t handles_ptr, bool wait_all, uint32_t timeout_ms) {
    if (count == 0 || count > 64 || !handles_ptr) {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return WAIT_FAILED;
    }
    std::vector<uint64_t> handles(count);
    for (uint32_t i = 0; i < count; ++i)
        handles[i] = mem_.read64(handles_ptr + i * 8);

    if (wait_all) {
        bool all_ready = true;
        bool any_event = false;
        for (uint64_t h : handles) {
            if (auto it = events_.find(h); it != events_.end()) {
                any_event = true;
                if (!it->second.signaled) all_ready = false;
            }
        }
        if (all_ready && any_event) {
            for (uint64_t h : handles) {
                if (auto it = events_.find(h); it != events_.end() && !it->second.manual_reset)
                    it->second.signaled = false;
            }
            return WAIT_OBJECT_0;
        }
        std::fprintf(stderr, "    [sync] WaitForMultipleObjects count=%u wait_all=1 timeout=%u (%s)\n",
                     count, timeout_ms, any_event ? "unsignaled" : "non-event");
        if (!any_event) return WAIT_OBJECT_0;
        if (scheduler_mode_ && timeout_ms != 0) {
            wait_req_.active = true;
            wait_req_.wait_all = true;
            wait_req_.handles = std::move(handles);
            return WAIT_OBJECT_0;
        }
        return WAIT_TIMEOUT;
    } else {
        bool any_event = false;
        for (uint32_t i = 0; i < count; ++i) {
            if (auto it = events_.find(handles[i]); it != events_.end()) {
                any_event = true;
                if (it->second.signaled) {
                    it->second.consume();
                    return WAIT_OBJECT_0 + i;
                }
            }
        }
        std::fprintf(stderr, "    [sync] WaitForMultipleObjects count=%u wait_all=0 timeout=%u (%s)\n",
                     count, timeout_ms, any_event ? "unsignaled" : "non-event");
        if (!any_event) return WAIT_OBJECT_0;
        if (scheduler_mode_ && timeout_ms != 0) {
            wait_req_.active = true;
            wait_req_.wait_all = false;
            wait_req_.handles = std::move(handles);
            return WAIT_OBJECT_0;
        }
        return WAIT_TIMEOUT;
    }
}

std::vector<PendingThread> DllRunner::take_pending_threads() {
    std::vector<PendingThread> out;
    out.swap(new_threads_);
    return out;
}

std::vector<uint64_t> DllRunner::take_resumed_threads() {
    std::vector<uint64_t> out;
    out.swap(resumed_threads_);
    return out;
}

WaitRequest DllRunner::take_wait_request() {
    WaitRequest req = std::move(wait_req_);
    wait_req_ = WaitRequest{};
    return req;
}

bool DllRunner::take_yield_request() {
    bool y = yield_requested_;
    yield_requested_ = false;
    return y;
}

bool DllRunner::in_image(uint64_t va) const {
    for (auto& img : loader_.images())
        if (va >= img.base_vaddr && va < img.base_vaddr + img.image_size) return true;
    return false;
}

std::string DllRunner::where(uint64_t va) const {
    char b[128];
    for (auto& img : loader_.images())
        if (va >= img.base_vaddr && va < img.base_vaddr + img.image_size) {
            std::snprintf(b, sizeof b, "%s+0x%llx", img.name.c_str(),
                          static_cast<unsigned long long>(va - img.base_vaddr));
            return b;
        }
    if (auto* t = loader_.thunk_at(va)) return "thunk " + t->module + "!" + t->name;
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(va));
    return b;
}

uint64_t DllRunner::call_guest(uint64_t fn, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4) {
    if (abort_ || !fn) return 0;
    cpu::Registers saved = cpu_.regs();
    auto& r = cpu_.regs();
    uint64_t top = (depth_ == 0 && !scheduler_mode_) ? STACK_TOP : saved.rsp - 0x200;
    uint64_t sentinel = SENTINEL - depth_ * 16;
    r.rsp = (top & ~0xFULL) - 0x40 - 8;
    mem_.write64(r.rsp, sentinel);
    r.rcx = a1; r.rdx = a2; r.r8 = a3; r.r9 = a4;
    r.rip = fn;
    r.rflags = 0x202;
    ++depth_;
    Stop s = loop(sentinel);
    --depth_;
    uint64_t ret = r.rax;
    if (s != Stop::Returned) {
        if (!abort_) { last_stop_ = s; report(s); }
        abort_ = true;
        return 0;
    }
    uint64_t gs = r.msr_gs_base;
    r = saved;
    r.msr_gs_base = gs;
    return ret;
}

DllRunner::Stop DllRunner::loop(uint64_t sentinel) {
    auto& r = cpu_.regs();
    while (true) {
        if (abort_) return Stop::Aborted;
        if (r.rip == sentinel) return Stop::Returned;
        ring_[ring_pos_++ % ring_.size()] = r.rip;
        if (const Thunk* t = loader_.thunk_at(r.rip)) {
            handle_thunk(*t);
            if (abort_) return Stop::Aborted;
            r.rip = mem_.read64(r.rsp);
            r.rsp += 8;
            continue;
        }
        if (!in_image(r.rip)) return Stop::WildJump;
        if (++insn_count_ > budget_) return Stop::Budget;
        if ((insn_count_ & 0xFFFFFFULL) == 0) {
            std::fprintf(stderr, "  [progress] insns=%llu rip=%s\n",
                         static_cast<unsigned long long>(insn_count_), where(r.rip).c_str());
            std::fflush(stderr);
        }
        cpu_.step();
        if (cpu_.fault()) return Stop::Fault;
        if (cpu_.halted()) return Stop::Halt;
    }
}

void DllRunner::handle_thunk(const Thunk& t) {
    auto& r = cpu_.regs();
    const std::string& n = t.name;
    if (thunk_log_ < 400) {
        ++thunk_log_;
        std::fprintf(stderr, "    [thunk] %-28s %-40s rcx=%llx rdx=%llx r8=%llx r9=%llx ret=%llx\n",
                    t.module.c_str(), n.c_str(),
                    (unsigned long long)r.rcx, (unsigned long long)r.rdx,
                    (unsigned long long)r.r8, (unsigned long long)r.r9, (unsigned long long)mem_.read64(r.rsp));
    }
    auto ret = [&](uint64_t v) { r.rax = v; };
    auto is = [&](std::initializer_list<const char*> names) {
        for (auto* x : names) if (n == x) return true;
        return false;
    };
    auto do_realloc = [&](uint64_t p, uint64_t sz) {
        uint64_t np = alloc(sz);
        if (auto it = alloc_sizes_.find(p); p && it != alloc_sizes_.end())
            for (uint64_t i = 0; i < std::min(it->second, sz); ++i) mem_.write8(np + i, mem_.read8(p + i));
        return np;
    };

    // ── GameInput.dll!#1 = GameInputCreate(IGameInput** out) ──────────────────
    // The game AddRef/Releases the returned pointer unconditionally, so a null
    // out (unknown-import default) wild-jumps to 0. Hand back a gdkobj fake COM object.
    if (t.module.size() >= 9 && strncasecmp(t.module.c_str(), "GameInput", 9) == 0 && n == "#1") {
        auto& st = g_gdk_states[this];
        const std::string iid = "{IGameInput}";
        uint64_t vtbl = 0;
        if (auto vit = st.iid_vtables.find(iid); vit != st.iid_vtables.end()) {
            vtbl = vit->second;
        } else {
            vtbl = alloc(64 * 8, 16);
            for (int i = 0; i < 64; ++i)
                mem_.write64(vtbl + static_cast<uint64_t>(i) * 8,
                             loader_.make_thunk("gdkobj", iid + "_m" + std::to_string(i)));
            st.iid_vtables[iid] = vtbl;
        }
        uint64_t obj = alloc(16, 16);
        mem_.write64(obj + 0, vtbl);
        mem_.write64(obj + 8, 1);
        if (arg(0)) mem_.write64(arg(0), obj);
        std::fprintf(stderr, "    [gdk] GameInputCreate out=0x%llx -> obj=0x%llx S_OK ret=%s\n",
                     static_cast<unsigned long long>(arg(0)), static_cast<unsigned long long>(obj),
                     where(mem_.read64(r.rsp)).c_str());
        return ret(0);
    }

    // ── XCRDAPI.dll!DStorageGetFactory(REFIID riid, void** ppv) ───────────────
    // Null *ppv (unknown-import default) makes the game call through a 0 vtable.
    if (n == "DStorageGetFactory") {
        uint64_t obj = make_fake_com("{IDStorageFactory}");
        if (arg(1)) mem_.write64(arg(1), obj);
        std::fprintf(stderr, "    [gdk] DStorageGetFactory riid=%s ppv=0x%llx -> obj=0x%llx S_OK ret=%s\n",
                     format_guid(mem_, arg(0)).c_str(), static_cast<unsigned long long>(arg(1)),
                     static_cast<unsigned long long>(obj), where(mem_.read64(r.rsp)).c_str());
        return ret(0);
    }

    // ── XGameRuntime (*ApiImpl*) & fake COM objects (gdkobj) ──────────────────
    if (t.module == "xgameruntime") {
        auto& st = g_gdk_states[this];
        uint64_t ret_addr = mem_.read64(r.rsp);
        if (n.rfind("InitializeApiImpl", 0) == 0) {
            ++st.init_calls;
            std::fprintf(stderr, "    [gdk] xgameruntime!%s rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx ret=%s -> S_OK\n",
                         n.c_str(),
                         static_cast<unsigned long long>(arg(0)),
                         static_cast<unsigned long long>(arg(1)),
                         static_cast<unsigned long long>(arg(2)),
                         static_cast<unsigned long long>(arg(3)),
                         where(ret_addr).c_str());
            return ret(0);
        }
        if (n == "UninitializeApiImpl") {
            ++st.uninit_calls;
            std::fprintf(stderr, "    [gdk] xgameruntime!UninitializeApiImpl ret=%s -> 0\n",
                         where(ret_addr).c_str());
            return ret(0);
        }
        if (n == "QueryApiImpl") {
            uint64_t prov_va = arg(0);
            uint64_t iid_va  = arg(1);
            uint64_t out_va  = arg(2);
            std::string prov = format_guid(mem_, prov_va);
            std::string iid  = format_guid(mem_, iid_va);

            auto& rec = st.queries[{prov, iid}];
            rec.provider = prov;
            rec.iid      = iid;
            ++rec.calls;

            if (should_deny_gdk_guid(prov, iid)) {
                if (out_va) mem_.write64(out_va, 0);
                rec.hr   = kRegdbEClassNotReg;
                rec.note = "REGDB_E_CLASSNOTREG (fallback)";
                std::fprintf(stderr, "    [gdk] QueryApiImpl provider=%s iid=%s out=0x%llx -> REGDB_E_CLASSNOTREG (0x%08x) ret=%s\n",
                             prov.c_str(), iid.c_str(),
                             static_cast<unsigned long long>(out_va),
                             kRegdbEClassNotReg,
                             where(ret_addr).c_str());
                return ret(kRegdbEClassNotReg);
            }

            // Allocate/fetch cached 64-entry vtable for this IID.
            uint64_t vtbl = 0;
            if (auto vit = st.iid_vtables.find(iid); vit != st.iid_vtables.end()) {
                vtbl = vit->second;
            } else {
                constexpr int kVtableSlots = 64;
                vtbl = alloc(kVtableSlots * 8, 16);
                for (int i = 0; i < kVtableSlots; ++i) {
                    uint64_t th = loader_.make_thunk("gdkobj", iid + "_m" + std::to_string(i));
                    mem_.write64(vtbl + static_cast<uint64_t>(i) * 8, th);
                }
                st.iid_vtables[iid] = vtbl;
            }

            // Fake COM object layout: [vtbl_ptr][refcount]
            uint64_t obj = alloc(16, 16);
            mem_.write64(obj + 0, vtbl);
            mem_.write64(obj + 8, 1);
            if (out_va) mem_.write64(out_va, obj);
            rec.hr = 0;
            rec.note = "fake COM object";

            std::fprintf(stderr, "    [gdk] QueryApiImpl provider=%s iid=%s out=0x%llx -> obj=0x%llx vtbl=0x%llx hr=0x0 ret=%s\n",
                         prov.c_str(), iid.c_str(),
                         static_cast<unsigned long long>(out_va),
                         static_cast<unsigned long long>(obj),
                         static_cast<unsigned long long>(vtbl),
                         where(ret_addr).c_str());
            return ret(0);
        }
        std::fprintf(stderr, "    [gdk] xgameruntime!%s (unhandled) rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx ret=%s -> 0\n",
                     n.c_str(),
                     static_cast<unsigned long long>(arg(0)),
                     static_cast<unsigned long long>(arg(1)),
                     static_cast<unsigned long long>(arg(2)),
                     static_cast<unsigned long long>(arg(3)),
                     where(ret_addr).c_str());
        return ret(0);
    }

    if (t.module == "gdkobj") {
        auto& st = g_gdk_states[this];
        uint64_t ret_addr = mem_.read64(r.rsp);
        std::string iid = n;
        int m_idx = -1;
        if (auto pos = n.rfind("_m"); pos != std::string::npos) {
            iid = n.substr(0, pos);
            m_idx = std::atoi(n.c_str() + pos + 2);
        }
        auto& mst = st.methods[{iid, m_idx}];
        ++mst.calls;

        if (m_idx == 0) { // IUnknown::QueryInterface(this, riid, ppvObject)
            std::string riid = format_guid(mem_, arg(1));
            uint64_t qi_obj = arg(0);
            // IDXGIDevice / IDXGIAdapter* / IDXGIOutput* need their own vtable layout.
            if (arg(1) && iid.rfind("{IDXGI", 0) != 0) {
                uint32_t d1 = mem_.read32(arg(1));
                if (d1 == 0x54ec77fa || d1 == 0x77db970f || d1 == 0x05008617) qi_obj = make_fake_com("{IDXGIDevice}");
            }
            if (arg(2)) mem_.write64(arg(2), qi_obj);
            mst.stub_desc = "QueryInterface (*r8=this, S_OK)";
            if (mst.calls <= 5) {
                std::fprintf(stderr, "    [gdkobj] %s m0(QueryInterface) this=0x%llx riid=%s ppv=0x%llx ret=%s -> S_OK\n",
                             iid.c_str(),
                             static_cast<unsigned long long>(arg(0)),
                             riid.c_str(),
                             static_cast<unsigned long long>(arg(2)),
                             where(ret_addr).c_str());
            }
            return ret(0);
        }
        if (m_idx == 1) { // IUnknown::AddRef
            mst.stub_desc = "AddRef (1)";
            if (mst.calls <= 2) {
                std::fprintf(stderr, "    [gdkobj] %s m1(AddRef) this=0x%llx ret=%s -> 1\n",
                             iid.c_str(), static_cast<unsigned long long>(arg(0)), where(ret_addr).c_str());
            }
            return ret(1);
        }
        if (m_idx == 2) { // IUnknown::Release
            mst.stub_desc = "Release (1)";
            if (mst.calls <= 2) {
                std::fprintf(stderr, "    [gdkobj] %s m2(Release) this=0x%llx ret=%s -> 1\n",
                             iid.c_str(), static_cast<unsigned long long>(arg(0)), where(ret_addr).c_str());
            }
            return ret(1);
        }

        // IID-specific COM method stubs
        if (iid == "{ID3DBlob}") { // obj+16 = buffer, obj+24 = size
            if (m_idx == 3) return ret(mem_.read64(arg(0) + 16));
            if (m_idx == 4) return ret(mem_.read64(arg(0) + 24));
        }
        if (iid == "{073b7dcb-1fcf-4030-94be-e3c9eb623428}") {
            if (m_idx == 12) {
                // XTaskQueueCreate(this, workMode, completionMode, XTaskQueueHandle* out)
                uint32_t work_mode = static_cast<uint32_t>(arg(1));
                uint32_t comp_mode = static_cast<uint32_t>(arg(2));
                uint64_t h = (handle_next_ += 4);
                task_queues_[h] = TaskQueueObj{work_mode, comp_mode, false, {}};
                if (arg(3)) mem_.write64(arg(3), h);
                mst.stub_desc = "XTaskQueueCreate (*r9=queue_handle, S_OK)";
                if (mst.calls <= 10) {
                    std::fprintf(stderr, "    [gdkobj] %s m12(XTaskQueueCreate) work=%u comp=%u out=0x%llx -> handle=0x%llx ret=%s\n",
                                 iid.c_str(),
                                 work_mode,
                                 comp_mode,
                                 static_cast<unsigned long long>(arg(3)),
                                 static_cast<unsigned long long>(h),
                                 where(ret_addr).c_str());
                    std::fflush(stderr);
                }
                return ret(0);
            }
            if (m_idx == 16) {
                // XTaskQueueDispatch(this, queue, port, timeoutInMs) -> bool
                uint64_t qh      = arg(1);
                uint32_t port    = static_cast<uint32_t>(arg(2));
                uint32_t timeout = static_cast<uint32_t>(arg(3));
                mst.stub_desc = "XTaskQueueDispatch (pop & run callback)";
                auto qit = task_queues_.find(qh);
                if (qit != task_queues_.end()) {
                    for (size_t i = 0; i < qit->second.items.size(); ++i) {
                        if (qit->second.items[i].port == port) {
                            TaskQueueItem item = qit->second.items[i];
                            qit->second.items.erase(qit->second.items.begin() + static_cast<std::ptrdiff_t>(i));
                            std::fprintf(stderr, "    [gdkobj] %s m16(XTaskQueueDispatch) queue=0x%llx port=%u timeout=%u -> run cb=0x%llx (%s) ctx=0x%llx\n",
                                         iid.c_str(),
                                         static_cast<unsigned long long>(qh),
                                         port, timeout,
                                         static_cast<unsigned long long>(item.callback),
                                         where(item.callback).c_str(),
                                         static_cast<unsigned long long>(item.context));
                            call_guest(item.callback, item.context, 0);
                            return ret(1);
                        }
                    }
                }
                if (mst.calls <= 10) {
                    std::fprintf(stderr, "    [gdkobj] %s m16(XTaskQueueDispatch) queue=0x%llx port=%u timeout=%u -> empty (0) ret=%s\n",
                                 iid.c_str(),
                                 static_cast<unsigned long long>(qh),
                                 port, timeout,
                                 where(ret_addr).c_str());
                }
                return ret(0);
            }
            if (m_idx == 17) {
                // XTaskQueueCloseHandle(this, queue)
                uint64_t qh = arg(1);
                task_queues_.erase(qh);
                mst.stub_desc = "XTaskQueueCloseHandle";
                return ret(0);
            }
            if (m_idx == 19) {
                // XTaskQueueSubmitDelayedCallback(this, queue, port, delayMs, callbackContext, callback)
                uint64_t qh    = arg(1);
                uint32_t port  = static_cast<uint32_t>(arg(2));
                uint32_t delay = static_cast<uint32_t>(arg(3));
                uint64_t ctx   = arg(4);
                uint64_t cb    = arg(5);
                mst.stub_desc = "XTaskQueueSubmitDelayedCallback (enqueue/dispatch)";
                std::fprintf(stderr, "    [gdkobj] %s m19(XTaskQueueSubmitDelayedCallback) queue=0x%llx port=%u delay=%u ctx=0x%llx cb=0x%llx (%s) ret=%s\n",
                             iid.c_str(),
                             static_cast<unsigned long long>(qh),
                             port, delay,
                             static_cast<unsigned long long>(ctx),
                             static_cast<unsigned long long>(cb),
                             where(cb).c_str(),
                             where(ret_addr).c_str());
                if (cb) {
                    task_queues_[qh].items.push_back(TaskQueueItem{port, cb, ctx});
                    pump_auto_task_queues();
                }
                return ret(0);
            }
            if (m_idx == 22) {
                // XTaskQueueTerminate(this, queue, wait, callbackContext, callback)
                uint64_t qh   = arg(1);
                uint32_t wait = static_cast<uint32_t>(arg(2));
                uint64_t ctx  = arg(3);
                uint64_t cb   = arg(4);
                mst.stub_desc = "XTaskQueueTerminate (drain & notify)";
                std::fprintf(stderr, "    [gdkobj] %s m22(XTaskQueueTerminate) queue=0x%llx wait=%u ctx=0x%llx cb=0x%llx ret=%s\n",
                             iid.c_str(),
                             static_cast<unsigned long long>(qh),
                             wait,
                             static_cast<unsigned long long>(ctx),
                             static_cast<unsigned long long>(cb),
                             where(ret_addr).c_str());
                if (auto qit = task_queues_.find(qh); qit != task_queues_.end()) {
                    qit->second.terminated = true;
                }
                if (cb) {
                    task_queues_[qh].items.push_back(TaskQueueItem{1, cb, ctx});
                    pump_auto_task_queues();
                }
                return ret(0);
            }
            if (m_idx == 29) {
                // No-arg XGameRuntime/XTaskQueue init helper (return ignored by caller)
                mst.stub_desc = "init helper (no-arg, S_OK)";
                if (mst.calls <= 10) {
                    std::fprintf(stderr, "    [gdkobj] %s m29(init_helper) this=0x%llx ret=%s -> S_OK\n",
                                 iid.c_str(),
                                 static_cast<unsigned long long>(arg(0)),
                                 where(ret_addr).c_str());
                    std::fflush(stderr);
                }
                return ret(0);
            }
        }

        if (iid.rfind("{bf2346b2", 0) == 0) {
            if (m_idx == 15) {
                // Get state / notification info into 24-byte buffer at rdx
                // Note: the title checks BYTE PTR [rdx+0x0c] == 0 to proceed with registration,
                // while the title's callback checks BYTE PTR [rdx+0x0c] == 1 to SetEvent(context).
                uint64_t out_va = arg(1);
                if (out_va) {
                    for (int i = 0; i < 24; ++i) mem_.write8(out_va + i, 0);
                }
                mst.stub_desc = "GetNotificationState (*rdx zeroed, S_OK)";
                std::fprintf(stderr, "    [gdkobj] %s m15(GetNotificationState) this=0x%llx out=0x%llx ret=%s -> S_OK\n",
                             iid.c_str(),
                             static_cast<unsigned long long>(arg(0)),
                             static_cast<unsigned long long>(out_va),
                             where(ret_addr).c_str());
                return ret(0);
            }
            if (m_idx == 16) {
                // Register notification callback on XTaskQueue:
                // (this=rcx, queue=rdx, context=r8 [event handle], callback=r9, token_out=[rsp+0x28]=arg(4))
                // The callback has signature void cb(void* context, const State* state)
                // and checks BYTE PTR [rdx+0xc] == 1 before calling SetEvent(rcx).
                uint64_t qh        = arg(1);
                uint64_t ctx       = arg(2);
                uint64_t cb        = arg(3);
                uint64_t token_out = arg(4);
                uint64_t token     = (handle_next_ += 4);
                if (token_out) mem_.write64(token_out, token);
                mst.stub_desc = "RegisterChanged(queue, ctx, cb, *token_out) -> submit & run cb";

                // Allocate 24-byte notification state struct with byte[0x0c] = 1 so the callback
                // takes the active branch (SetEvent(ctx)).
                uint64_t state_va = alloc(32, 16);
                for (int i = 0; i < 32; ++i) mem_.write8(state_va + i, 0);
                mem_.write8(state_va + 0x0c, 1);

                std::fprintf(stderr, "    [gdkobj] %s m16(RegisterNotification) queue=0x%llx ctx=0x%llx (%s) cb=0x%llx (%s) token_out=0x%llx -> token=0x%llx state=0x%llx ret=%s\n",
                             iid.c_str(),
                             static_cast<unsigned long long>(qh),
                             static_cast<unsigned long long>(ctx),
                             describe_handle(ctx).c_str(),
                             static_cast<unsigned long long>(cb),
                             where(cb).c_str(),
                             static_cast<unsigned long long>(token_out),
                             static_cast<unsigned long long>(token),
                             static_cast<unsigned long long>(state_va),
                             where(ret_addr).c_str());
                std::fflush(stderr);

                // Submit to the queue and execute the callback with (rcx=ctx, rdx=state_va).
                if (cb) {
                    call_guest(cb, ctx, state_va);
                }
                // Ensure the event is signaled if ctx is an event handle (the callback itself calls SetEvent(ctx)).
                if (auto eit = events_.find(ctx); eit != events_.end()) {
                    eit->second.signaled = true;
                }
                return ret(0);
            }
            if (m_idx == 17) {
                // Unregister notification callback: (this=rcx, token=rdx, wait=r8b) -> bool
                mst.stub_desc = "UnregisterNotification (return 1)";
                std::fprintf(stderr, "    [gdkobj] %s m17(UnregisterNotification) token=0x%llx wait=%llu ret=%s -> 1\n",
                             iid.c_str(),
                             static_cast<unsigned long long>(arg(1)),
                             static_cast<unsigned long long>(arg(2) & 0xFF),
                             where(ret_addr).c_str());
                return ret(1);
            }
        }

        // DXGI chain: IDXGIDevice::GetAdapter (m7), IDXGIAdapter::EnumOutputs (m7),
        // IDXGIObject::GetParent (m6, riid/ppv).
        if (iid == "{IDXGIDevice}" && m_idx == 7) {
            if (arg(1)) mem_.write64(arg(1), make_fake_com("{IDXGIAdapter}"));
            mst.stub_desc = "GetAdapter (*rdx=fake adapter)";
            return ret(0);
        }
        if (iid == "{IDXGIAdapter}" && m_idx == 7) {
            mst.stub_desc = "EnumOutputs (idx 0 only)";
            if (static_cast<uint32_t>(arg(1)) != 0) return ret(0x887A0002); // DXGI_ERROR_NOT_FOUND
            if (arg(2)) mem_.write64(arg(2), make_fake_com("{IDXGIOutput}"));
            return ret(0);
        }
        if (iid.rfind("{IDXGI", 0) == 0 && m_idx == 6) {
            static const char* parent[] = {"{IDXGIAdapter}", "{IDXGIFactory}"};
            if (arg(2)) mem_.write64(arg(2), make_fake_com(iid == "{IDXGIDevice}" ? parent[0] : parent[1]));
            mst.stub_desc = "GetParent (*r8=fake parent)";
            return ret(0);
        }

        if (iid == "{IDStorageFactory}" && m_idx >= 3 && m_idx <= 5) {
            static const char* kids[] = {"{IDStorageQueue}", "{IDStorageFile}", "{IDStorageStatusArray}"};
            uint64_t obj = make_fake_com(kids[m_idx - 3]);
            if (arg(3)) mem_.write64(arg(3), obj);
            mst.stub_desc = "create child fake COM (*r9=obj, S_OK)";
            if (mst.calls <= 10)
                std::fprintf(stderr, "    [gdkobj] %s m%d arg1=0x%llx ppv=0x%llx -> %s obj=0x%llx ret=%s\n",
                             iid.c_str(), m_idx, static_cast<unsigned long long>(arg(1)),
                             static_cast<unsigned long long>(arg(3)), kids[m_idx - 3],
                             static_cast<unsigned long long>(obj), where(ret_addr).c_str());
            return ret(0);
        }
        // CreateQueue(this, desc, riid, ppv). Called as vtbl+0x50 from exe+0x28c95c7.
        // Returning S_OK without writing *ppv left a null queue, so the rpf loader never started.
        if (iid == "{IDStorageFactory}" && m_idx == 10) {
            uint64_t obj = make_fake_com("{IDStorageQueue}");
            if (arg(3)) mem_.write64(arg(3), obj);
            mst.stub_desc = "CreateQueue (*r9=queue, S_OK)";
            if (mst.calls <= 8)
                std::fprintf(stderr, "    [gdkobj] IDStorageFactory CreateQueue desc=0x%llx -> obj=0x%llx ret=%s\n",
                             static_cast<unsigned long long>(arg(1)),
                             static_cast<unsigned long long>(obj), where(ret_addr).c_str());
            return ret(0);
        }

        // Device method 80 (vtbl+0x280) at exe+0x2482448. The out pointer is the
        // 6th argument; the caller then uses that object. Leaving it null
        // makes a later virtual call jump to 0.
        if (iid == "{5405c344-d457-444e}" && m_idx == 80) {
            uint64_t obj = make_fake_com("{D3D12Resource}");
            uint64_t pp = arg(5);
            if (pp > 0x10000 && pp < (1ULL << 47)) mem_.write64(pp, obj);
            mst.stub_desc = "m80 (*stack=resource, S_OK)";
            if (mst.calls <= 6)
                std::fprintf(stderr, "    [d3d12] device m80 -> resource 0x%llx at 0x%llx ret=%s\n",
                             static_cast<unsigned long long>(obj),
                             static_cast<unsigned long long>(pp), where(ret_addr).c_str());
            return ret(0);
        }
        if (iid == "{5405c344-d457-444e}" && m_idx == 15) { // ID3D12Device::GetDescriptorHandleIncrementSize
            mst.stub_desc = "GetDescriptorHandleIncrementSize -> 0x20";
            return ret(0x20);
        }
        if (iid == "{5405c344-d457-444e}" && m_idx == 24) { // CopyDescriptorsSimple: void
            mst.stub_desc = "CopyDescriptorsSimple";
            return ret(0);
        }
        if (iid == "{5405c344-d457-444e}" && m_idx == 25) { // GetResourceAllocationInfo(ret*, this, mask, n, descs)
            uint64_t out = arg(0), d = arg(4);
            uint64_t w = mem_.read64(d + 0x10), hm = mem_.read64(d + 0x18);
            uint64_t h = std::max<uint64_t>(hm & 0xffffffff, 1);
            uint64_t depth = std::max<uint64_t>((hm >> 32) & 0xffff, 1), mips = (hm >> 48) & 0xffff;
            bool buf = (mem_.read64(d) & 0xffffffff) == 1;
            uint64_t size = buf ? w : w * h * depth * 8 * (mips > 1 ? 2 : 1);
            uint64_t al = (mem_.read64(d + 8) == 0x1000 && size <= 0x10000) ? 0x1000 : 0x10000;
            size = (std::max<uint64_t>(size, 1) + al - 1) & ~(al - 1);
            mem_.write64(out, size);
            mem_.write64(out + 8, al);
            mst.stub_desc = "GetResourceAllocationInfo";
            return ret(out);
        }
        // D3D12-style factory methods: (..., REFIID riid, void** ppv). If arg(i) looks like a
        // known-readable GUID and arg(i+1) is a writable pointer, hand back a new fake object.
        // Stack slots past the real args can look like a GUID plus a code address (saved
        // return address). Writing the object there patches the caller's epilogue.
        auto executable_va = [&](uint64_t va) {
            for (auto& img : loader_.images()) {
                if (va < img.base_vaddr || va >= img.base_vaddr + img.image_size) continue;
                uint64_t nt = img.base_vaddr + mem_.read32(img.base_vaddr + 0x3c);
                if (mem_.read32(nt) != 0x4550) return false;
                uint16_t nsec = mem_.read16(nt + 6);
                uint64_t sec = nt + 24 + mem_.read16(nt + 20);
                uint32_t rva = static_cast<uint32_t>(va - img.base_vaddr);
                for (uint16_t s = 0; s < nsec && s < 96; ++s, sec += 40) {
                    uint32_t sv = mem_.read32(sec + 12), sz = mem_.read32(sec + 8);
                    if (rva >= sv && rva < sv + sz)
                        return (mem_.read32(sec + 36) & 0x20000000u) != 0; // IMAGE_SCN_MEM_EXECUTE
                }
                return false;
            }
            return false;
        };
        for (int i = 1; i <= 7 && iid.size() == 20 && iid[9] == '-'; ++i) {
            uint64_t riid = arg(i), ppv = arg(i + 1);
            if (riid < 0x10000 || ppv < 0x10000 || riid >= (1ULL << 47) || ppv >= (1ULL << 47)) continue;
            uint64_t lo = mem_.read64(riid), hi = mem_.read64(riid + 8);
            unsigned version = static_cast<unsigned>(lo >> 60);
            if (!lo || !hi || version < 1 || version > 5) continue;
            if ((hi >> 56) == 0 && (lo >> 48) == 0) continue;
            if (mem_.read64(ppv) >= (1ULL << 47)) continue;
            if (executable_va(ppv)) continue;
            char b[48];
            std::snprintf(b, sizeof b, "{%08x-%04x-%04x}", static_cast<unsigned>(lo & 0xffffffff),
                          static_cast<unsigned>((lo >> 32) & 0xffff), static_cast<unsigned>(lo >> 48));
            uint64_t obj = make_fake_com(b);
            mem_.write64(ppv, obj);
            mst.stub_desc = "riid/ppv child fake COM";
            if (mst.calls <= 10)
                std::fprintf(stderr, "    [gdkobj] %s m%d riid@arg%d %s -> obj=0x%llx ret=%s\n", iid.c_str(), m_idx, i, b,
                             static_cast<unsigned long long>(obj), where(ret_addr).c_str());
            return ret(0);
        }

        // m3+ generic COM method stub
        mst.stub_desc = "default (return 0 / S_OK)";
        if (mst.calls <= 10) {
            std::fprintf(stderr, "    [gdkobj] %s m%d rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx ret=%s -> 0\n",
                         iid.c_str(), m_idx,
                         static_cast<unsigned long long>(arg(0)),
                         static_cast<unsigned long long>(arg(1)),
                         static_cast<unsigned long long>(arg(2)),
                         static_cast<unsigned long long>(arg(3)),
                         where(ret_addr).c_str());
            std::fflush(stderr);
        }
        return ret(0);
    }

    // ── Heap / Virtual Memory ─────────────────────────────────────────────────
    if (is({"GetProcessHeap"})) return ret(0xFEED0000);
    if (is({"HeapAlloc"})) return ret(alloc(arg(2)));
    if (is({"HeapReAlloc"})) return ret(do_realloc(arg(2), arg(3)));
    if (is({"HeapSize"})) { auto it = alloc_sizes_.find(arg(2)); return ret(it != alloc_sizes_.end() ? it->second : ~0ULL); }
    if (is({"HeapFree", "VirtualProtect"})) return ret(1);
    if (is({"LocalFree"})) return ret(0);
    if (is({"malloc", "_malloc_base", "operator new", "??2@YAPEAX_K@Z", "??_U@YAPEAX_K@Z"})) return ret(alloc(arg(0)));
    if (is({"calloc", "_calloc_base"})) return ret(alloc(arg(0) * arg(1)));
    if (is({"realloc", "_realloc_base"})) return ret(do_realloc(arg(0), arg(1)));
    if (is({"_aligned_malloc"})) return ret(alloc(arg(0), std::max<uint64_t>(arg(1), 16)));
    if (is({"free", "_free_base", "_aligned_free"})) return ret(0);
    if (is({"VirtualAlloc", "VirtualAllocEx", "XMemVirtualAlloc"})) {
        bool is_ex = (n == "VirtualAllocEx");
        uint64_t addr = is_ex ? arg(1) : arg(0);
        uint64_t sz   = is_ex ? arg(2) : arg(1);
        uint32_t type = static_cast<uint32_t>(is_ex ? arg(3) : arg(2));
        return ret(virtual_alloc(addr, sz, type));
    }
    if (is({"VirtualFree", "VirtualFreeEx", "XMemVirtualFree"})) {
        bool is_ex = (n == "VirtualFreeEx");
        uint64_t addr = is_ex ? arg(1) : arg(0);
        uint32_t type = static_cast<uint32_t>(is_ex ? arg(3) : arg(2));
        return ret(virtual_free(addr, type) ? 1 : 0);
    }
    if (is({"XMemAlloc", "XMemAllocDefault"})) {
        uint64_t sz = arg(0);
        uint64_t attr = arg(1);
        // Decode alignment from XALLOC_ATTRIBUTES if present, default to 64 KiB for large or 4 KiB
        uint32_t align_code = static_cast<uint32_t>((attr >> 24) & 0x1F);
        uint64_t align = (sz >= VALLOC_ALIGN) ? VALLOC_ALIGN : 0x1000ULL;
        if (align_code >= 4 && align_code <= 20) align = 1ULL << align_code;
        uint64_t res = (sz >= VALLOC_ALIGN) ? virtual_alloc(0, sz, MEM_RESERVE | MEM_COMMIT)
                                            : alloc(sz, align);
        std::fprintf(stderr, "    [xmem] %s size=0x%llx (%llu MB) attr=0x%llx -> 0x%llx\n",
                     n.c_str(),
                     static_cast<unsigned long long>(sz),
                     static_cast<unsigned long long>(sz >> 20),
                     static_cast<unsigned long long>(attr),
                     static_cast<unsigned long long>(res));
        return ret(res);
    }
    if (is({"XMemFree", "XMemFreeDefault"})) {
        virtual_free(arg(0), MEM_RELEASE);
        return ret(0);
    }
    if (is({"XMemAllocatePhysical"})) {
        uint64_t sz = arg(0);
        uint64_t align = std::max<uint64_t>(arg(2), VALLOC_ALIGN);
        uint64_t res = virtual_alloc(0, (sz + align - 1) & ~(align - 1), MEM_RESERVE | MEM_COMMIT);
        std::fprintf(stderr, "    [xmem] XMemAllocatePhysical size=0x%llx align=0x%llx -> 0x%llx\n",
                     static_cast<unsigned long long>(sz),
                     static_cast<unsigned long long>(align),
                     static_cast<unsigned long long>(res));
        return ret(res);
    }
    if (is({"XMemFreePhysical"})) {
        virtual_free(arg(0), MEM_RELEASE);
        return ret(1);
    }
    if (is({"XMemSetAllocationHooks"})) {
        auto& st = g_gdk_states[this];
        st.xmem_alloc_hook = arg(0);
        st.xmem_free_hook  = arg(1);
        std::fprintf(stderr, "    [xmem] XMemSetAllocationHooks alloc=0x%llx free=0x%llx\n",
                     static_cast<unsigned long long>(arg(0)),
                     static_cast<unsigned long long>(arg(1)));
        return ret(0);
    }
    if (is({"XMemGetAllocationHysteresis"})) {
        return ret(g_gdk_states[this].xmem_hysteresis);
    }
    if (is({"XMemSetAllocationHysteresis"})) {
        g_gdk_states[this].xmem_hysteresis = arg(0);
        return ret(1);
    }
    if (is({"VirtualQuery", "VirtualQueryEx"})) {
        bool is_ex = (n == "VirtualQueryEx");
        uint64_t addr   = is_ex ? arg(1) : arg(0);
        uint64_t buf_va = is_ex ? arg(2) : arg(1);
        uint64_t len    = is_ex ? arg(3) : arg(2);
        if (!buf_va || len < 48) return ret(0);
        uint64_t base = addr & ~0xFFFULL;
        uint64_t alloc_base = base;
        uint64_t reg_size = 0x10000ULL;
        uint32_t state = MEM_COMMIT;
        for (const auto& [vb, vsz] : vallocs_) {
            if (addr >= vb && addr < vb + vsz) {
                alloc_base = vb;
                reg_size = (vb + vsz) - base;
                break;
            }
        }
        mem_.write64(buf_va + 0,  base);       // BaseAddress
        mem_.write64(buf_va + 8,  alloc_base); // AllocationBase
        mem_.write32(buf_va + 16, 0x04);       // AllocationProtect = PAGE_READWRITE
        mem_.write16(buf_va + 20, 0);          // PartitionId
        mem_.write64(buf_va + 24, reg_size);   // RegionSize
        mem_.write32(buf_va + 32, state);      // State = MEM_COMMIT
        mem_.write32(buf_va + 36, 0x04);       // Protect = PAGE_READWRITE
        mem_.write32(buf_va + 40, 0x20000);    // Type = MEM_PRIVATE
        return ret(48);
    }

    // ── File I/O ──────────────────────────────────────────────────────────────
    if (is({"CreateFileW"})) {
        std::string path = read_str(arg(0), true);
        if (path.empty())
            std::fprintf(stderr, "    [file] CreateFileW empty path ptr=0x%llx caller=%s\n",
                         static_cast<unsigned long long>(arg(0)), where(mem_.read64(r.rsp)).c_str());
        return ret(open_file(path, static_cast<uint32_t>(arg(1)), static_cast<uint32_t>(arg(4))));
    }
    if (is({"CreateFileA"})) {
        std::string path = read_str(arg(0), false);
        return ret(open_file(path, static_cast<uint32_t>(arg(1)), static_cast<uint32_t>(arg(4))));
    }
    if (is({"ReadFile"})) {
        uint64_t h = arg(0);
        uint64_t buf_va = arg(1);
        uint32_t to_read = static_cast<uint32_t>(arg(2));
        uint64_t nread_va = arg(3);
        uint64_t ov_va = arg(4);
        auto it = files_.find(h);
        if (it == files_.end() || !it->second.fp) {
            set_last_error(6); // ERROR_INVALID_HANDLE
            return ret(0);
        }
        std::FILE* fp = it->second.fp;
        if (ov_va) {
            uint64_t off = static_cast<uint64_t>(mem_.read32(ov_va + 16))
                         | (static_cast<uint64_t>(mem_.read32(ov_va + 20)) << 32);
            fseeko(fp, static_cast<off_t>(off), SEEK_SET);
        }
        size_t got = 0;
        if (to_read > 0) {
            if (uint8_t* dst = mem_.raw_ptr(buf_va, to_read)) {
                got = std::fread(dst, 1, to_read, fp);
            } else {
                std::vector<uint8_t> tmp(to_read);
                got = std::fread(tmp.data(), 1, to_read, fp);
                for (size_t i = 0; i < got; ++i) mem_.write8(buf_va + i, tmp[i]);
            }
        }
        if (nread_va) mem_.write32(nread_va, static_cast<uint32_t>(got));
        if (ov_va) {
            mem_.write64(ov_va + 0, 0);   // Internal = STATUS_SUCCESS
            mem_.write64(ov_va + 8, got); // InternalHigh = bytes read
            uint64_t h_ev = mem_.read64(ov_va + 24);
            if (auto ev = events_.find(h_ev); ev != events_.end()) ev->second.signaled = true;
        }
        if (read_log_ < 100) {
            ++read_log_;
            std::fprintf(stderr, "    [file] read handle=0x%llx req=%u got=%zu\n",
                         static_cast<unsigned long long>(h), to_read, got);
        }
        set_last_error(0);
        return ret(1);
    }
    if (is({"GetFileSizeEx"})) {
        uint64_t h = arg(0), out_va = arg(1);
        auto it = files_.find(h);
        if (it == files_.end()) {
            set_last_error(6);
            return ret(0);
        }
        if (out_va) mem_.write64(out_va, it->second.size);
        set_last_error(0);
        return ret(1);
    }
    if (is({"SetFilePointerEx"})) {
        uint64_t h = arg(0);
        int64_t dist = static_cast<int64_t>(arg(1));
        uint64_t new_pos_va = arg(2);
        uint32_t method = static_cast<uint32_t>(arg(3));
        auto it = files_.find(h);
        if (it == files_.end() || !it->second.fp) {
            set_last_error(6);
            return ret(0);
        }
        int whence = SEEK_SET;
        if (method == 1) whence = SEEK_CUR;
        else if (method == 2) whence = SEEK_END;
        if (fseeko(it->second.fp, static_cast<off_t>(dist), whence) != 0) {
            set_last_error(131); // ERROR_NEGATIVE_SEEK
            return ret(0);
        }
        off_t pos = ftello(it->second.fp);
        if (new_pos_va) mem_.write64(new_pos_va, static_cast<uint64_t>(pos));
        set_last_error(0);
        return ret(1);
    }
    if (is({"GetFileAttributesW", "GetFileAttributesA"})) {
        namespace fs = std::filesystem;
        std::string gp = read_str(arg(0), n.back() == 'W');
        bool exists = false;
        std::string hp = resolve_host_path(gp, &exists);
        std::error_code ec;
        if (!exists) {
            set_last_error(2);
            return ret(0xFFFFFFFFu); // INVALID_FILE_ATTRIBUTES
        }
        set_last_error(0);
        return ret(fs::is_directory(hp, ec) ? 0x10u : 0x80u);
    }
    if (is({"GetFileAttributesExW"})) {
        namespace fs = std::filesystem;
        std::string gp = read_str(arg(0), true);
        uint64_t info_va = arg(2);
        bool exists = false;
        std::string hp = resolve_host_path(gp, &exists);
        std::error_code ec;
        if (!exists || !info_va) {
            set_last_error(2);
            return ret(0);
        }
        bool is_dir = fs::is_directory(hp, ec);
        uint64_t fsz = is_dir ? 0 : fs::file_size(hp, ec);
        for (int i = 0; i < 36; ++i) mem_.write8(info_va + i, 0);
        mem_.write32(info_va + 0, is_dir ? 0x10u : 0x80u);
        mem_.write64(info_va + 4, 0x01DB000000000000ULL);
        mem_.write64(info_va + 12, 0x01DB000000000000ULL);
        mem_.write64(info_va + 20, 0x01DB000000000000ULL);
        mem_.write32(info_va + 28, static_cast<uint32_t>(fsz >> 32));
        mem_.write32(info_va + 32, static_cast<uint32_t>(fsz & 0xFFFFFFFFu));
        set_last_error(0);
        return ret(1);
    }
    if (is({"CloseHandle"})) {
        uint64_t h = arg(0);
        if (auto it = files_.find(h); it != files_.end()) {
            std::fprintf(stderr, "    [file] close handle=0x%llx \"%s\"\n",
                         static_cast<unsigned long long>(h), it->second.guest_path.c_str());
            if (it->second.fp) std::fclose(it->second.fp);
            files_.erase(it);
            return ret(1);
        }
        if (auto it = events_.find(h); it != events_.end()) {
            events_.erase(it);
            return ret(1);
        }
        return ret(1);
    }

    // ── TLS / FLS ─────────────────────────────────────────────────────────────
    if (is({"TlsAlloc", "FlsAlloc"})) {
        uint32_t i = tls_next_++;
        tls_[{current_tid_, i}] = 0;
        return ret(i);
    }
    if (is({"TlsGetValue", "FlsGetValue"})) {
        auto it = tls_.find({current_tid_, static_cast<uint32_t>(arg(0))});
        return ret(it != tls_.end() ? it->second : 0);
    }
    if (is({"TlsSetValue", "FlsSetValue"})) {
        tls_[{current_tid_, static_cast<uint32_t>(arg(0))}] = arg(1);
        return ret(1);
    }
    if (is({"TlsFree", "FlsFree"})) return ret(1);

    // ── Synchronization & Threads ─────────────────────────────────────────────
    if (is({"CreateEventW", "CreateEventA"})) {
        bool manual = arg(1) != 0;
        bool initial = arg(2) != 0;
        std::string ename = read_str(arg(3), n.back() == 'W');
        uint64_t h = (handle_next_ += 4);
        events_[h] = EventObj{manual, initial, ename};
        return ret(h);
    }
    if (is({"CreateEventExW"})) {
        std::string ename = read_str(arg(1), true);
        uint32_t flags = static_cast<uint32_t>(arg(2));
        bool manual = (flags & 0x1u) != 0;
        bool initial = (flags & 0x2u) != 0;
        uint64_t h = (handle_next_ += 4);
        events_[h] = EventObj{manual, initial, ename};
        return ret(h);
    }
    if (is({"SetEvent"})) {
        uint64_t h = arg(0);
        if (auto it = events_.find(h); it != events_.end()) it->second.signaled = true;
        if (g_sync_log < 24) {
            ++g_sync_log;
            std::fprintf(stderr, "    [sync] SetEvent h=0x%llx caller=%s\n",
                         static_cast<unsigned long long>(h), where(mem_.read64(r.rsp)).c_str());
        }
        return ret(1);
    }
    if (is({"ResetEvent"})) {
        uint64_t h = arg(0);
        if (auto it = events_.find(h); it != events_.end()) it->second.signaled = false;
        return ret(1);
    }
    if (is({"WaitForSingleObject", "WaitForSingleObjectEx"})) {
        if (!events_.count(arg(0))) {
            const char* kind = "unknown";
            for (auto& pt : pending_threads_) if (pt.handle == arg(0)) kind = "thread";
            if (files_.count(arg(0))) kind = "file";
            std::fprintf(stderr, "    [sync] wait non-event 0x%llx kind=%s caller=%s\n",
                         static_cast<unsigned long long>(arg(0)), kind, where(mem_.read64(r.rsp)).c_str());
        }
        return ret(wait_single(arg(0), static_cast<uint32_t>(arg(1))));
    }
    if (is({"WaitForMultipleObjects", "WaitForMultipleObjectsEx"})) {
        return ret(wait_multiple(static_cast<uint32_t>(arg(0)), arg(1), arg(2) != 0,
                                 static_cast<uint32_t>(arg(3))));
    }
    if (is({"CreateThread"})) {
        uint64_t stack_sz = arg(1);
        uint64_t entry    = arg(2);
        uint64_t param    = arg(3);
        uint64_t flags    = arg(4);
        uint64_t tid_va   = arg(5);
        uint64_t h        = (handle_next_ += 4);
        uint32_t tid      = (tid_next_ += 4);
        bool suspended    = (flags & 0x4ULL) != 0;
        if (tid_va) mem_.write32(tid_va, tid);
        PendingThread pt{entry, param, stack_sz, h, tid, suspended};
        pending_threads_.push_back(pt);
        new_threads_.push_back(pt);
        std::fprintf(stderr, "    [thread] create entry=0x%llx (%s) param=0x%llx stack=0x%llx handle=0x%llx tid=%u%s\n",
                     static_cast<unsigned long long>(entry), where(entry).c_str(),
                     static_cast<unsigned long long>(param),
                     static_cast<unsigned long long>(stack_sz),
                     static_cast<unsigned long long>(h), tid,
                     suspended ? " [suspended]" : "");
        return ret(h);
    }
    if (is({"ResumeThread"})) {
        uint64_t h = arg(0);
        for (auto& pt : pending_threads_)
            if (pt.handle == h) pt.suspended = false;
        resumed_threads_.push_back(h);
        return ret(1);
    }
    if (is({"SuspendThread"})) return ret(0);
    if (is({"Sleep", "SleepEx", "SwitchToThread"})) {
        if (scheduler_mode_) yield_requested_ = true;
        return ret(0);
    }
    if (is({"SetThreadPriority", "GetThreadPriority", "SetThreadGroupAffinity", "GetThreadGroupAffinity",
            "SetProcessPriorityBoost"})) return ret(1);

    if (is({"InitializeCriticalSection", "InitializeCriticalSectionEx",
            "InitializeCriticalSectionAndSpinCount", "DisableThreadLibraryCalls"})) return ret(1);
    if (is({"EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection",
            "AcquireSRWLockExclusive", "ReleaseSRWLockExclusive", "AcquireSRWLockShared",
            "ReleaseSRWLockShared", "InitializeSRWLock", "InitializeSListHead",
            "InitializeConditionVariable", "WakeAllConditionVariable", "WakeConditionVariable"})) return ret(0);
    if (is({"TryAcquireSRWLockExclusive", "TryEnterCriticalSection"})) return ret(1);
    if (is({"ReleaseMutex"})) {
        if (auto it = events_.find(arg(0)); it != events_.end()) it->second.signaled = true;
        return ret(1);
    }
    if (is({"ReleaseSemaphore"})) {
        if (auto it = events_.find(arg(0)); it != events_.end() && it->second.sem_count >= 0) {
            if (arg(2)) mem_.write32(arg(2), static_cast<uint32_t>(it->second.sem_count));
            it->second.sem_count += static_cast<int64_t>(static_cast<int32_t>(arg(1)));
            it->second.signaled = it->second.sem_count > 0;
            if (g_sync_log < 24) {
                ++g_sync_log;
                std::fprintf(stderr, "    [sync] ReleaseSemaphore h=0x%llx +%u count=%lld caller=%s\n",
                             static_cast<unsigned long long>(arg(0)), static_cast<unsigned>(arg(1)),
                             static_cast<long long>(it->second.sem_count), where(mem_.read64(r.rsp)).c_str());
            }
        }
        return ret(1);
    }
    if (is({"InitOnceExecuteOnce"})) {
        uint64_t once = arg(0), fn = arg(1), param = arg(2), ctx = arg(3);
        if (mem_.read64(once) == 0) {
            mem_.write64(once, 2);
            call_guest(fn, once, param, ctx);
        }
        return ret(1);
    }
    if (is({"InitOnceBeginInitialize"})) {
        uint64_t once = arg(0);
        mem_.write32(arg(2), mem_.read64(once) == 0 ? 1 : 0); // fPending
        return ret(1);
    }
    if (is({"InitOnceComplete"})) { mem_.write64(arg(0), 2); return ret(1); }

    if (is({"EncodePointer", "DecodePointer", "RtlEncodePointer", "RtlDecodePointer"})) return ret(arg(0));

    // ── Module / Loader ───────────────────────────────────────────────────────
    if (is({"GetModuleHandleW", "GetModuleHandleA", "GetModuleHandleExW", "LoadLibraryW",
            "LoadLibraryA", "LoadLibraryExW", "LoadLibraryExA"})) {
        bool ex = n == "GetModuleHandleExW";
        uint64_t namep = ex ? arg(1) : arg(0);
        uint64_t h = 0;
        if (!namep) h = cur_base_;
        else {
            std::string want = lower(read_str(namep, n.back() == 'W'));
            for (auto& img : loader_.images())
                if (img.name == want || img.name == want + ".dll") h = img.base_vaddr;
            // System DLLs (kernel32, api-ms-*) are not mapped: hand out a pseudo handle,
            // GetProcAddress resolves names to thunks regardless of the module.
            if (!h) h = 0x7FFE00000000ULL;
        }
        if (ex) { if (arg(2)) mem_.write64(arg(2), h); return ret(h != 0); }
        return ret(h);
    }
    if (is({"GetModuleFileNameW", "GetModuleFileNameA"})) {
        std::string s = "G:\\" + exe_name_;
        for (auto& img : loader_.images()) if (img.base_vaddr == arg(0)) s = "G:\\" + img.name;
        if (n.back() == 'W') write_wstr(arg(1), s);
        else write_cstr(arg(1), s);
        return ret(s.size());
    }
    if (is({"GetProcAddress"})) {
        std::string fn = (arg(1) >> 16) ? read_str(arg(1), false) : "#" + std::to_string(arg(1));
        if (auto e = loader_.find_export(fn)) return ret(*e);
        if (fn.find("ApiImpl") != std::string::npos)
            return ret(loader_.make_thunk("xgameruntime", fn));
        return ret(loader_.make_thunk("getprocaddress", fn));
    }
    if (is({"FreeLibrary"})) return ret(1);

    // ── String conversion (needed for Win32 path conversion before CreateFileW)
    if (is({"MultiByteToWideChar"})) {
        uint64_t src_va = arg(2);
        int32_t  cb_src = static_cast<int32_t>(arg(3));
        uint64_t dst_va = arg(4);
        int32_t  cch_dst = static_cast<int32_t>(arg(5));
        if (!src_va) { set_last_error(87); return ret(0); }
        std::vector<uint8_t> bytes;
        if (cb_src < 0) {
            for (int i = 0; i < 4096; ++i) {
                uint8_t b = mem_.read8(src_va + i);
                bytes.push_back(b);
                if (b == 0) break;
            }
        } else {
            bytes.reserve(static_cast<size_t>(cb_src));
            for (int32_t i = 0; i < cb_src; ++i) bytes.push_back(mem_.read8(src_va + i));
        }
        std::vector<uint16_t> wide;
        wide.reserve(bytes.size());
        for (size_t i = 0; i < bytes.size(); ) {
            uint8_t b = bytes[i];
            if (b < 0x80) {
                wide.push_back(b);
                ++i;
            } else if ((b & 0xE0) == 0xC0 && i + 1 < bytes.size()) {
                uint16_t cp = static_cast<uint16_t>(((b & 0x1F) << 6) | (bytes[i + 1] & 0x3F));
                wide.push_back(cp);
                i += 2;
            } else if ((b & 0xF0) == 0xE0 && i + 2 < bytes.size()) {
                uint16_t cp = static_cast<uint16_t>(((b & 0x0F) << 12) | ((bytes[i + 1] & 0x3F) << 6) | (bytes[i + 2] & 0x3F));
                wide.push_back(cp);
                i += 3;
            } else {
                wide.push_back(b);
                ++i;
            }
        }
        if (cch_dst == 0) return ret(wide.size());
        if (static_cast<size_t>(cch_dst) < wide.size()) {
            set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
            return ret(0);
        }
        for (size_t i = 0; i < wide.size(); ++i) mem_.write16(dst_va + i * 2, wide[i]);
        return ret(wide.size());
    }
    if (is({"WideCharToMultiByte"})) {
        uint64_t src_va = arg(2);
        int32_t  cch_src = static_cast<int32_t>(arg(3));
        uint64_t dst_va = arg(4);
        int32_t  cb_dst = static_cast<int32_t>(arg(5));
        if (!src_va) { set_last_error(87); return ret(0); }
        std::vector<uint16_t> wide;
        if (cch_src < 0) {
            for (int i = 0; i < 4096; ++i) {
                uint16_t w = mem_.read16(src_va + i * 2);
                wide.push_back(w);
                if (w == 0) break;
            }
        } else {
            wide.reserve(static_cast<size_t>(cch_src));
            for (int32_t i = 0; i < cch_src; ++i) wide.push_back(mem_.read16(src_va + i * 2));
        }
        std::vector<uint8_t> out;
        out.reserve(wide.size());
        for (uint16_t w : wide) {
            if (w < 0x80) {
                out.push_back(static_cast<uint8_t>(w));
            } else if (w < 0x800) {
                out.push_back(static_cast<uint8_t>(0xC0 | (w >> 6)));
                out.push_back(static_cast<uint8_t>(0x80 | (w & 0x3F)));
            } else {
                out.push_back(static_cast<uint8_t>(0xE0 | (w >> 12)));
                out.push_back(static_cast<uint8_t>(0x80 | ((w >> 6) & 0x3F)));
                out.push_back(static_cast<uint8_t>(0x80 | (w & 0x3F)));
            }
        }
        if (cb_dst == 0) return ret(out.size());
        if (static_cast<size_t>(cb_dst) < out.size()) {
            set_last_error(122);
            return ret(0);
        }
        for (size_t i = 0; i < out.size(); ++i) mem_.write8(dst_va + i, out[i]);
        return ret(out.size());
    }

    // ── Errors / Time / System Info ───────────────────────────────────────────
    if (is({"GetLastError"})) return ret(get_last_error());
    if (is({"SetLastError"})) { set_last_error(static_cast<uint32_t>(arg(0))); return ret(0); }

    if (is({"QueryPerformanceCounter"})) { mem_.write64(arg(0), insn_count_ * 10); return ret(1); }
    if (is({"QueryPerformanceFrequency"})) { mem_.write64(arg(0), 10'000'000); return ret(1); }
    if (is({"GetTickCount64", "GetTickCount"})) return ret(insn_count_ / 1000);
    if (is({"GetCurrentThreadId"})) return ret(current_tid_);
    if (is({"GetCurrentProcessId", "GetProcessId"})) return ret(4);
    if (is({"GetCurrentThread"})) return ret(~1ULL);
    if (is({"GetCurrentProcess"})) return ret(~0ULL);
    if (is({"GetCurrentThreadStackLimits"})) {
        uint64_t teb = cpu_.regs().msr_gs_base;
        if (arg(0)) mem_.write64(arg(0), mem_.read64(teb + 0x10));
        if (arg(1)) mem_.write64(arg(1), mem_.read64(teb + 0x08));
        return ret(0);
    }
    if (is({"GetSystemTimeAsFileTime", "GetSystemTimePreciseAsFileTime"})) {
        mem_.write64(arg(0), 0x01DB000000000000ULL); return ret(0);
    }
    if (is({"IsProcessorFeaturePresent"})) return ret(1);
    if (is({"IsDebuggerPresent"})) return ret(0);
    if (is({"OutputDebugStringA", "OutputDebugStringW"})) {
        std::string msg = read_str(arg(0), n.back() == 'W');
        while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r')) msg.pop_back();
        if (!msg.empty()) std::fprintf(stderr, "    [debug] %s\n", msg.c_str());
        return ret(0);
    }
    if (is({"GetSystemInfo", "GetNativeSystemInfo"})) {
        uint64_t p = arg(0);
        for (int i = 0; i < 48; ++i) mem_.write8(p + i, 0);
        mem_.write16(p, 9);                  // AMD64
        mem_.write32(p + 4, 0x1000);         // page size
        mem_.write64(p + 8, 0x10000);
        mem_.write64(p + 16, 0x7FFFFFFEFFFFULL);
        mem_.write64(p + 24, 0xFF);
        mem_.write32(p + 32, 8);             // processors
        mem_.write32(p + 36, 8664);
        mem_.write32(p + 40, 0x10000);       // allocation granularity
        return ret(0);
    }
    if (is({"GlobalMemoryStatusEx"})) {
        uint64_t p = arg(0);
        if (p) {
            for (int i = 4; i < 64; ++i) mem_.write8(p + i, 0);
            mem_.write32(p + 0, 64);
            mem_.write32(p + 4, 20);                              // dwMemoryLoad
            mem_.write64(p + 8,  10ULL * 1024 * 1024 * 1024);     // ullTotalPhys (10 GiB)
            mem_.write64(p + 16,  8ULL * 1024 * 1024 * 1024);     // ullAvailPhys
            mem_.write64(p + 24, 10ULL * 1024 * 1024 * 1024);     // ullTotalPageFile
            mem_.write64(p + 32,  8ULL * 1024 * 1024 * 1024);     // ullAvailPageFile
            mem_.write64(p + 40, 16ULL * 1024 * 1024 * 1024);     // ullTotalVirtual
            mem_.write64(p + 48, 12ULL * 1024 * 1024 * 1024);     // ullAvailVirtual
        }
        return ret(1);
    }
    if (is({"GetStartupInfoW"})) {
        uint64_t p = arg(0);
        if (p) {
            for (int i = 0; i < 104; ++i) mem_.write8(p + i, 0);
            mem_.write32(p + 0, 104);
        }
        return ret(0);
    }
    if (is({"GetCommandLineW", "GetCommandLineA"})) {
        uint64_t p = alloc(128);
        if (n.back() == 'W') write_wstr(p, exe_name_.c_str());
        else write_cstr(p, exe_name_.c_str());
        return ret(p);
    }
    if (is({"GetEnvironmentStringsW"})) return ret(alloc(8));
    if (is({"FreeEnvironmentStringsW"})) return ret(1);
    if (is({"GetACP", "GetOEMCP"})) return ret(65001);
    // mutex = auto-reset event signaled while unowned; semaphore = counted event.
    if (is({"CreateMutexW", "CreateMutexA"})) {
        uint64_t h = (handle_next_ += 4);
        events_[h] = EventObj{false, arg(1) == 0, read_str(arg(2), n.back() == 'W')};
        return ret(h);
    }
    if (is({"CreateMutexExW"})) {
        uint64_t h = (handle_next_ += 4);
        events_[h] = EventObj{false, (arg(2) & 0x1u) == 0, read_str(arg(1), true)};
        return ret(h);
    }
    if (is({"CreateSemaphoreW", "CreateSemaphoreExW"})) {
        int64_t init = static_cast<int32_t>(arg(1));
        uint64_t h = (handle_next_ += 4);
        events_[h] = EventObj{false, init > 0, read_str(arg(3), true), init};
        std::fprintf(stderr, "    [sync] CreateSemaphore h=0x%llx init=%lld\n",
                     static_cast<unsigned long long>(h), static_cast<long long>(init));
        return ret(h);
    }

    // ── CRT initialization ────────────────────────────────────────────────────
    if (is({"_initterm", "_initterm_e"})) {
        bool e = n == "_initterm_e";
        for (uint64_t p = arg(0), end = arg(1); p < end; p += 8) {
            uint64_t fn = mem_.read64(p);
            if (!fn) continue;
            uint64_t rv = call_guest(fn);
            if (abort_) return;
            if (e && static_cast<int>(rv) != 0) return ret(rv);
        }
        return ret(0);
    }
    if (is({"_register_onexit_function", "_crt_atexit", "atexit", "_initialize_onexit_table",
            "_execute_onexit_table", "_configure_narrow_argv", "_initialize_narrow_environment",
            "_set_new_mode", "_configthreadlocale", "__acrt_initialize", "_seh_filter_dll",
            "_seh_filter_exe", "_set_app_type", "_set_fmode", "__setusermatherr",
            "_register_thread_local_exe_atexit_callback", "SetUnhandledExceptionFilter"}))
        return ret(0);
    if (is({"__p__commode"})) {
        static uint64_t commode_va = 0;
        if (!commode_va) commode_va = alloc(8);
        return ret(commode_va);
    }
    if (is({"__p___argc"})) {
        auto& st = g_gdk_states[this];
        if (!st.argc_va) {
            st.argc_va = alloc(8);
            mem_.write32(st.argc_va, 1);
        }
        return ret(st.argc_va);
    }
    if (is({"__p___argv"})) {
        auto& st = g_gdk_states[this];
        if (!st.argv_va) {
            uint64_t arg0 = alloc(64);
            write_cstr(arg0, exe_name_.c_str());
            uint64_t arr = alloc(16);
            mem_.write64(arr + 0, arg0);
            mem_.write64(arr + 8, 0);
            st.argv_va = alloc(8);
            mem_.write64(st.argv_va, arr);
        }
        return ret(st.argv_va);
    }
    if (is({"RegisterAppStateChangeNotification", "RegisterAppConstrainedChangeNotification"})) {
        if (arg(2)) mem_.write64(arg(2), handle_next_ += 4);
        return ret(0); // ERROR_SUCCESS
    }

    // ── CRT string functions (guest memory, real semantics) ──────────────────
    auto lc = [](uint8_t c) { return static_cast<uint8_t>(std::tolower(c)); };
    auto cmp_n = [&](uint64_t a, uint64_t b, uint64_t lim, bool icase) -> int {
        for (uint64_t i = 0; i < lim; ++i) {
            uint8_t x = mem_.read8(a + i), y = mem_.read8(b + i);
            if (icase) { x = lc(x); y = lc(y); }
            if (x != y) return x < y ? -1 : 1;
            if (!x) return 0;
        }
        return 0;
    };
    auto ret_int = [&](int v) { ret(static_cast<uint64_t>(static_cast<int64_t>(v))); };
    if (is({"strlen"})) { uint64_t i = 0; while (mem_.read8(arg(0) + i)) ++i; return ret(i); }
    if (is({"strcmp"}))   return ret_int(cmp_n(arg(0), arg(1), ~0ULL, false));
    if (is({"strncmp"}))  return ret_int(cmp_n(arg(0), arg(1), arg(2), false));
    if (is({"_stricmp"})) return ret_int(cmp_n(arg(0), arg(1), ~0ULL, true));
    if (is({"_strnicmp"})) return ret_int(cmp_n(arg(0), arg(1), arg(2), true));
    if (is({"strcpy"})) {
        uint64_t i = 0;
        for (uint8_t c; (c = mem_.read8(arg(1) + i)); ++i) mem_.write8(arg(0) + i, c);
        mem_.write8(arg(0) + i, 0);
        return ret(arg(0));
    }
    if (is({"strtok_s"})) {
        uint64_t s = arg(0) ? arg(0) : mem_.read64(arg(2)), delim = arg(1);
        auto is_delim = [&](uint8_t c) {
            for (uint64_t i = 0; uint8_t d = mem_.read8(delim + i); ++i) if (c == d) return true;
            return false;
        };
        if (!s) return ret(0);
        while (mem_.read8(s) && is_delim(mem_.read8(s))) ++s;
        if (!mem_.read8(s)) { mem_.write64(arg(2), s); return ret(0); }
        uint64_t tok = s;
        while (mem_.read8(s) && !is_delim(mem_.read8(s))) ++s;
        if (mem_.read8(s)) mem_.write8(s++, 0);
        mem_.write64(arg(2), s);
        return ret(tok);
    }

    // ── CRT math: float/double args in xmm0/xmm1, result in xmm0 ─────────────
    {
        auto& x0 = r.ymm[0].lo; auto& x1 = r.ymm[1].lo;
        auto f1 = [&](float (*fn)(float)) { x0.f[0] = fn(x0.f[0]); };
        auto d1 = [&](double (*fn)(double)) { x0.df[0] = fn(x0.df[0]); };
        if (is({"sinf"}))   return f1(std::sin);
        if (is({"cosf"}))   return f1(std::cos);
        if (is({"tanf"}))   return f1(std::tan);
        if (is({"log10f"})) return f1(std::log10);
        if (is({"exp2f"}))  return f1(std::exp2);
        if (is({"atan2f"})) { x0.f[0] = std::atan2(x0.f[0], x1.f[0]); return; }
        if (is({"powf"}))   { x0.f[0] = std::pow(x0.f[0], x1.f[0]); return; }
        if (is({"log"}))    return d1(std::log);
        if (is({"exp"}))    return d1(std::exp);
        if (is({"floor"}))  return d1(std::floor);
    }

    // ── CRT misc ──────────────────────────────────────────────────────────────
    if (is({"_time64"})) {
        uint64_t t64 = 1798761600ULL; // fixed: 2027-01-01
        if (arg(0)) mem_.write64(arg(0), t64);
        return ret(t64);
    }
    if (is({"rand_s"})) { mem_.write32(arg(0), static_cast<uint32_t>(std::rand())); return ret(0); }
    if (is({"___mb_cur_max_func"})) return ret(1);
    if (is({"isspace", "iswspace"})) {
        unsigned c = static_cast<unsigned>(arg(0));
        return ret(c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f');
    }
    if (is({"__pctype_func"})) {
        // "C" locale ctype table (index -1..255); returned pointer is at index 0.
        static uint64_t tbl = 0;
        if (!tbl) {
            tbl = alloc(2 * 257) + 2;
            for (int c = 0; c < 256; ++c) {
                uint16_t m = 0;
                if (c < 128) {
                    if (std::isupper(c)) m |= 0x1;
                    if (std::islower(c)) m |= 0x2;
                    if (std::isdigit(c)) m |= 0x4;
                    if (std::isspace(c)) m |= 0x8;
                    if (std::ispunct(c)) m |= 0x10;
                    if (std::iscntrl(c)) m |= 0x20;
                    if (c == ' ')        m |= 0x40;
                    if (std::isxdigit(c)) m |= 0x80;
                    if (std::isalpha(c)) m |= 0x100;
                }
                mem_.write16(tbl + 2 * c, m);
            }
        }
        return ret(tbl);
    }
    if (is({"__acrt_iob_func"})) {
        static uint64_t iob = 0;
        if (!iob) { iob = alloc(3 * 0x58); for (int i = 0; i < 3 * 0x58; ++i) mem_.write8(iob + i, 0); }
        return ret(iob + 0x58 * (arg(0) % 3));
    }
    // printf family: real formatter over the guest va_list (8-byte slots).
    auto gfmt = [&](uint64_t fmt, bool wfmt, uint64_t va, bool legacy_wide) -> std::vector<uint16_t> {
        std::vector<uint16_t> out;
        auto rd = [&](uint64_t i) -> uint16_t {
            return wfmt ? static_cast<uint16_t>(mem_.read8(fmt + i * 2) | (mem_.read8(fmt + i * 2 + 1) << 8)) : mem_.read8(fmt + i);
        };
        auto next = [&]() { uint64_t v = mem_.read64(va); va += 8; return v; };
        auto put = [&](const std::string& t) { for (unsigned char c : t) out.push_back(c); };
        for (uint64_t i = 0; out.size() < (1u << 20); ++i) {
            uint16_t c = rd(i);
            if (!c) break;
            if (c != '%') { out.push_back(c); continue; }
            std::string spec = "%";
            uint16_t f;
            while ((f = rd(++i)) && std::strchr("-+ #0", static_cast<char>(f))) spec += static_cast<char>(f);
            if (f == '*') { spec += std::to_string(static_cast<int>(next())); f = rd(++i); }
            else while (f >= '0' && f <= '9') { spec += static_cast<char>(f); f = rd(++i); }
            bool has_prec = false; int prec = -1;
            if (f == '.') {
                has_prec = true; f = rd(++i);
                if (f == '*') { prec = static_cast<int>(next()); f = rd(++i); }
                else { prec = 0; while (f >= '0' && f <= '9') { prec = prec * 10 + (f - '0'); f = rd(++i); } }
                if (prec >= 0) spec += "." + std::to_string(prec); else has_prec = false;
            }
            int size = 0; int wide_str = -1;   // size: 0 int, 1 short, 2 char, 8 64-bit
            for (;; f = rd(++i)) {
                if (f == 'h') { size = size == 1 ? 2 : 1; wide_str = 0; }
                else if (f == 'l') { if (size == 4) size = 8; else size = 4; wide_str = 1; }
                else if (f == 'w') wide_str = 1;
                else if (f == 'L' || f == 'z' || f == 'j' || f == 't') size = 8;
                else if (f == 'I') {
                    if (rd(i + 1) == '6' && rd(i + 2) == '4') { size = 8; i += 2; }
                    else if (rd(i + 1) == '3' && rd(i + 2) == '2') { size = 0; i += 2; }
                    else size = 8;
                } else break;
            }
            if (size == 4) size = 0;   // long is 32-bit on win64
            char buf[512];
            switch (f) {
            case 0: return out;
            case '%': out.push_back('%'); break;
            case 'd': case 'i': {
                int64_t v = static_cast<int64_t>(next());
                if (size == 0) v = static_cast<int32_t>(v); else if (size == 1) v = static_cast<int16_t>(v); else if (size == 2) v = static_cast<int8_t>(v);
                std::snprintf(buf, sizeof buf, (spec + "lld").c_str(), static_cast<long long>(v)); put(buf); break;
            }
            case 'u': case 'x': case 'X': case 'o': {
                uint64_t v = next();
                if (size == 0) v = static_cast<uint32_t>(v); else if (size == 1) v = static_cast<uint16_t>(v); else if (size == 2) v = static_cast<uint8_t>(v);
                std::snprintf(buf, sizeof buf, (spec + "ll" + static_cast<char>(f)).c_str(), static_cast<unsigned long long>(v)); put(buf); break;
            }
            case 'p': std::snprintf(buf, sizeof buf, "%016llX", static_cast<unsigned long long>(next())); put(buf); break;
            case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A': {
                uint64_t bits = next(); double d; std::memcpy(&d, &bits, 8);
                std::snprintf(buf, sizeof buf, (spec + static_cast<char>(f)).c_str(), d); put(buf); break;
            }
            case 'c': case 'C': {
                uint16_t ch = static_cast<uint16_t>(next());
                std::string pad = spec.substr(1); int w = std::atoi(pad.c_str() + (pad.find_first_not_of("-+ #0") == std::string::npos ? pad.size() : pad.find_first_not_of("-+ #0")));
                bool left = spec.find('-') != std::string::npos;
                if (!left) for (int k = 1; k < w; ++k) out.push_back(' ');
                out.push_back(ch);
                if (left) for (int k = 1; k < w; ++k) out.push_back(' ');
                break;
            }
            case 's': case 'S': case 'Z': {
                uint64_t p = next();
                bool w = wide_str >= 0 ? wide_str == 1 : ((f == 'S') != (wfmt && legacy_wide));
                if (f == 'Z' && p) { w = wide_str == 1; uint64_t b = mem_.read64(p + 8); p = b; }
                std::vector<uint16_t> str;
                if (!p) { for (char k : std::string("(null)")) str.push_back(k); }
                else for (uint64_t k = 0; k < (1u << 16) && (!has_prec || static_cast<int>(k) < prec); ++k) {
                    uint16_t ch = w ? static_cast<uint16_t>(mem_.read8(p + k * 2) | (mem_.read8(p + k * 2 + 1) << 8)) : mem_.read8(p + k);
                    if (!ch) break;
                    str.push_back(ch);
                }
                size_t fw = spec.find_first_not_of("%-+ #0");
                int width = fw == std::string::npos ? 0 : std::atoi(spec.c_str() + fw);
                bool left = spec.find('-') != std::string::npos;
                int padn = width > static_cast<int>(str.size()) ? width - static_cast<int>(str.size()) : 0;
                if (!left) out.insert(out.end(), padn, ' ');
                out.insert(out.end(), str.begin(), str.end());
                if (left) out.insert(out.end(), padn, ' ');
                break;
            }
            case 'n': { uint64_t p = next(); if (p) mem_.write32(p, static_cast<uint32_t>(out.size())); break; }
            default: out.push_back(f); break;
            }
        }
        return out;
    };
    // (options, buffer, count, [maxcount,] format, locale, va_list)
    auto do_printf = [&](bool wide, bool has_max, bool secure) {
        uint64_t opts = arg(0), buf = arg(1), cnt = arg(2);
        uint64_t maxc = has_max ? arg(3) : ~0ULL;
        int b = has_max ? 4 : 3;
        std::vector<uint16_t> o = gfmt(arg(b), wide, arg(b + 2), (opts & 4) != 0);
        uint64_t n = o.size();
        bool trunc = false;
        if (maxc != ~0ULL && maxc != static_cast<uint64_t>(-1) && n > maxc) { n = maxc; trunc = true; }
        if (buf && cnt) {
            uint64_t len = std::min<uint64_t>(n, cnt - 1);
            if (n > cnt - 1) trunc = true;
            for (uint64_t k = 0; k < len; ++k) {
                if (wide) mem_.write16(buf + k * 2, o[k]); else mem_.write8(buf + k, static_cast<uint8_t>(o[k]));
            }
            if (wide) mem_.write16(buf + len * 2, 0); else mem_.write8(buf + len, 0);
            if (trunc && secure && !has_max) { if (wide) mem_.write16(buf, 0); else mem_.write8(buf, 0); }
        }
        if (trunc && (secure || !(opts & 2)) && buf && cnt) return ret_int(-1);
        return ret_int(static_cast<int>(o.size()));
    };
    if (is({"__stdio_common_vsprintf"}))       return do_printf(false, false, false);
    if (is({"__stdio_common_vsprintf_s"}))     return do_printf(false, false, true);
    if (is({"__stdio_common_vsnprintf_s"}))    return do_printf(false, true, true);
    if (is({"__stdio_common_vswprintf"}))      return do_printf(true, false, false);
    if (is({"__stdio_common_vswprintf_s"}))    return do_printf(true, false, true);
    if (is({"__stdio_common_vsnwprintf_s"}))   return do_printf(true, true, true);
    if (is({"__stdio_common_vsscanf", "__stdio_common_vswscanf"})) return ret_int(0);   // nothing matched
    if (is({"_get_stream_buffer_pointers"})) {
        for (int k = 1; k <= 3; ++k) if (arg(k)) mem_.write64(arg(k), 0);
        return ret(0);
    }
    if (is({"wcscmp"})) {
        for (uint64_t i = 0;; ++i) {
            int a = mem_.read8(arg(0) + i * 2) | (mem_.read8(arg(0) + i * 2 + 1) << 8);
            int b = mem_.read8(arg(1) + i * 2) | (mem_.read8(arg(1) + i * 2 + 1) << 8);
            if (a != b) return ret_int(a < b ? -1 : 1);
            if (!a) return ret_int(0);
        }
    }
    if (is({"LocaleNameToLCID"})) return ret(0x409);
    if (is({"GetUserDefaultGeoName"})) {
        if (arg(0) && arg(1) >= 3) write_wstr(arg(0), "US");
        return ret(3);
    }
    // No registry on Xbox: every key is missing (ERROR_FILE_NOT_FOUND).
    if (is({"RegOpenKeyW", "RegOpenKeyExW", "RegQueryValueExW"})) return ret(2);
    if (is({"RegCloseKey"})) return ret(0);

    // ── WS2_32 by ordinal: offline mode, network is down ─────────────────────
    if (t.module.size() >= 6 && strncasecmp(t.module.c_str(), "WS2_32", 6) == 0) {
        constexpr uint64_t SOCKET_ERROR = 0xFFFFFFFFu, WSAENETDOWN = 10050;
        if (n == "#115") {                                   // WSAStartup(ver, WSADATA*)
            if (arg(1)) { mem_.write16(arg(1), 0x0202); mem_.write16(arg(1) + 2, 0x0202); }
            return ret(0);
        }
        if (n == "#116") return ret(0);                      // WSACleanup
        if (n == "#111") return ret(WSAENETDOWN);            // WSAGetLastError
        if (n == "#8" || n == "#14") return ret(__builtin_bswap32(static_cast<uint32_t>(arg(0))));
        if (n == "#9" || n == "#15") return ret(__builtin_bswap16(static_cast<uint16_t>(arg(0))));
        if (n == "#11") return ret(0xFFFFFFFFu);             // inet_addr -> INADDR_NONE
        if (n == "#23") return ret(~0ULL);                   // socket -> INVALID_SOCKET
        if (n == "#57") {                                    // gethostname
            if (arg(0) && arg(1) >= 10) write_cstr(arg(0), "localhost");
            return ret(0);
        }
        if (n == "#3") return ret(0);                        // closesocket
        std::fprintf(stderr, "    [net] WS2_32!%s -> SOCKET_ERROR (offline)\n", n.c_str());
        return ret(SOCKET_ERROR);
    }

    // ── Batch stubs: windowing, D3D12 device, XMem, CRT, misc ────────────────
    auto guid_str = [&](uint64_t p) {
        char b[48];
        std::snprintf(b, sizeof b, "{%08x-%04x-%04x}", static_cast<unsigned>(mem_.read64(p) & 0xffffffff),
                      static_cast<unsigned>((mem_.read64(p) >> 32) & 0xffff), static_cast<unsigned>(mem_.read64(p) >> 48));
        return std::string(b);
    };
    auto rand_fill = [&](uint64_t p, uint64_t len) {
        static uint64_t s = 0x9e3779b97f4a7c15ULL;
        for (uint64_t i = 0; i < len; ++i) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; mem_.write8(p + i, static_cast<uint8_t>(s)); }
    };
    if (is({"RegisterClassExA", "RegisterClassExW", "RegisterClassA", "RegisterClassW"})) return ret(0xC001);
    if (is({"CreateWindowExA", "CreateWindowExW"})) return ret(0x10010);
    if (is({"ShowWindow", "UpdateWindow", "SetForegroundWindow", "DestroyWindow"})) return ret(1);
    if (is({"PeekMessageA", "PeekMessageW", "TranslateMessage", "DispatchMessageA", "DispatchMessageW",
            "DefWindowProcA", "DefWindowProcW"})) return ret(0);
    if (is({"D3D12XboxCreateDevice"})) {
        uint64_t obj = make_fake_com(arg(2) ? guid_str(arg(2)) : "{D3D12Device}");
        if (arg(3)) mem_.write64(arg(3), obj);
        std::fprintf(stderr, "    [d3d12] D3D12XboxCreateDevice -> fake device 0x%llx\n", static_cast<unsigned long long>(obj));
        return ret(0);
    }
    if (is({"D3D12ConfigureVirtualMemoryX", "RegisterTraceGuidsW",
            "XMemTransferMemory"})) return ret(0);
    if (is({"XMemFreePhysicalPages"})) return ret(1);
    if (is({"XMemMapPhysicalPages", "XMemMapPhysicalPagesScatter"})) {
        // (VirtualAddress, NumberOfPages, PageArray, ...) -> VirtualAddress (NULL = failure)
        uint64_t va = arg(0);
        return ret(va ? va : alloc(std::max<uint64_t>(arg(1), 1) * 0x10000, 0x10000));
    }
    if (is({"D3D12SerializeVersionedRootSignature", "D3D12SerializeRootSignature"})) {
        // (desc, [version,] ID3DBlob** ppBlob, ID3DBlob** ppErr): hand back a small non-empty blob
        bool versioned = n == "D3D12SerializeVersionedRootSignature";
        uint64_t pp = versioned ? arg(1) : arg(2), pe = versioned ? arg(2) : arg(3);
        uint64_t blob = make_fake_com("{ID3DBlob}");
        uint64_t buf = alloc(0x100, 16);
        for (int i = 0; i < 0x100; i += 8) mem_.write64(buf + i, arg(0) ? mem_.read64(arg(0) + i % 0x40) : 0);
        mem_.write64(blob + 16, buf);
        mem_.write64(blob + 24, 0x100);
        if (pp) mem_.write64(pp, blob);
        if (pe) mem_.write64(pe, 0);
        return ret(0);
    }
    if (is({"XGSuggestSwizzleMode"})) return ret(0); // linear: our textures are flat
    if (is({"XGCreateTextureComputer"})) { // (const XG_RESOURCE_DESC*, XGTextureAddressComputer** out)
        if (arg(1)) mem_.write64(arg(1), make_fake_com("{XGTextureAddressComputer}"));
        return ret(0);
    }
    if (is({"XMemAllocatePhysicalPages"})) {
        // (Flags, PULONG_PTR NumberOfPages in/out, PULONG_PTR PageArray) -> BOOL
        static uint64_t next_pfn = 0x100000;
        uint64_t cnt = arg(1) ? mem_.read64(arg(1)) : 0;
        if (arg(2)) for (uint64_t i = 0; i < cnt; ++i) mem_.write64(arg(2) + i * 8, next_pfn++);
        return ret(1);
    }
    if (is({"XMemIsToolsMemAvailable"})) return ret(0);
    if (is({"XMemGetWorkingSetStatistics"})) { if (arg(0)) for (int i = 0; i < 64; i += 8) mem_.write64(arg(0) + i, 0); return ret(0); }
    if (is({"UuidCreate", "CoCreateGuid"})) { rand_fill(arg(0), 16); return ret(0); }
    if (is({"BCryptGenRandom"})) { rand_fill(arg(1), arg(2) & 0xffffffff); return ret(0); }
    if (is({"BCryptOpenAlgorithmProvider"})) { if (arg(0)) mem_.write64(arg(0), 0xBC000001); return ret(0); }
    if (is({"BCryptCloseAlgorithmProvider", "CoInitializeEx", "CoTaskMemFree"})) return ret(0);
    if (is({"CoCreateInstance"})) { if (arg(4)) mem_.write64(arg(4), 0); return ret(0x80040154); } // REGDB_E_CLASSNOTREG
    if (is({"StringFromGUID2"})) { std::string g = guid_str(arg(0)); write_wstr(arg(1), g); return ret(g.size() + 1); }
    if (is({"wcslen"})) { uint64_t i = 0; while (mem_.read8(arg(0) + i * 2) | mem_.read8(arg(0) + i * 2 + 1)) ++i; return ret(i); }
    if (is({"wcscat_s"})) {
        uint64_t d = arg(0), cap = arg(1), s = arg(2), i = 0, j = 0;
        while (i < cap && (mem_.read8(d + i * 2) | mem_.read8(d + i * 2 + 1))) ++i;
        for (;; ++j) {
            if (i + j >= cap) { if (cap) mem_.write16(d, 0); return ret(34); } // ERANGE
            uint16_t c = mem_.read8(s + j * 2) | (mem_.read8(s + j * 2 + 1) << 8);
            mem_.write16(d + (i + j) * 2, c);
            if (!c) break;
        }
        return ret(0);
    }
    if (is({"strcspn"})) {
        uint64_t i = 0;
        for (; uint8_t c = mem_.read8(arg(0) + i); ++i)
            for (uint64_t k = 0; uint8_t r2 = mem_.read8(arg(1) + k); ++k)
                if (r2 == c) return ret(i);
        return ret(i);
    }
    if (is({"atoi", "atol"})) return ret_int(std::atoi(read_str(arg(0), false).c_str()));
    if (is({"srand"})) { std::srand(static_cast<unsigned>(arg(0))); return ret(0); }
    if (is({"rand"})) return ret(std::rand() & 0x7fff);
    if (is({"qsort"})) {
        uint64_t base = arg(0), cnt = arg(1), sz = arg(2), cmp = arg(3);
        if (cnt > 1 && sz && cnt * sz <= 0x1000000) {
            uint64_t tmp = alloc(sz);
            for (uint64_t i = 1; i < cnt; ++i) {            // insertion sort through the guest comparator
                for (uint64_t k = 0; k < sz; ++k) mem_.write8(tmp + k, mem_.read8(base + i * sz + k));
                uint64_t j = i;
                while (j > 0 && static_cast<int32_t>(call_guest(cmp, base + (j - 1) * sz, tmp)) > 0) {
                    for (uint64_t k = 0; k < sz; ++k) mem_.write8(base + j * sz + k, mem_.read8(base + (j - 1) * sz + k));
                    --j;
                }
                for (uint64_t k = 0; k < sz; ++k) mem_.write8(base + j * sz + k, mem_.read8(tmp + k));
            }
        }
        return ret(0);
    }
    if (is({"setlocale"})) { static uint64_t c = 0; if (!c) { c = alloc(8); write_cstr(c, "C"); } return ret(c); }
    if (is({"___lc_codepage_func"})) return ret(65001);
    if (is({"___lc_locale_name_func"})) { static uint64_t z = 0; if (!z) z = alloc(64); return ret(z); }
    if (is({"_lock_locales", "_unlock_locales", "_set_invalid_parameter_handler"})) return ret(0);
    if (is({"_get_narrow_winmain_command_line"})) { static uint64_t e = 0; if (!e) e = alloc(8); return ret(e); }
    if (is({"GetLogicalProcessorInformation", "GetLogicalProcessorInformationEx"})) { set_last_error(50); return ret(0); }
    if (is({"RtlPcToFileHeader"})) { if (arg(1)) mem_.write64(arg(1), 0x140000000ULL); return ret(0x140000000ULL); }
    if (is({"GetEnvironmentVariableW", "GetEnvironmentVariableA"})) { set_last_error(203); return ret(0); }
    if (is({"GetUserDefaultLocaleName"})) { if (arg(0) && arg(1) >= 6) write_wstr(arg(0), "en-US"); return ret(6); }
    if (is({"GetFileTime"})) { for (int i = 1; i <= 3; ++i) if (arg(i)) mem_.write64(arg(i), 0x01D9000000000000ULL); return ret(1); }
    if (is({"GetLocalTime", "GetSystemTime"})) {
        static const uint16_t st[8] = {2024, 1, 1, 1, 0, 0, 0, 0};
        for (int i = 0; i < 8; ++i) mem_.write16(arg(0) + i * 2, st[i]);
        return ret(0);
    }
    if (is({"FileTimeToSystemTime"})) {
        static const uint16_t st[8] = {2024, 1, 1, 1, 0, 0, 0, 0};
        for (int i = 0; i < 8; ++i) mem_.write16(arg(1) + i * 2, st[i]);
        return ret(1);
    }
    if (is({"FindFirstFileW", "FindFirstFileA"})) { set_last_error(2); return ret(~0ULL); }
    if (is({"CreateDirectoryW", "CreateDirectoryA"})) return ret(1);

    for (auto& s : XboxGdkStubs::stubs())
        if (n == s.name) return ret(s.ret_val);

    // Unknown function: count calls and log first occurrence per function name, with the return address.
    ++unknown_counts_[t.module + "!" + n];
    if (unknown_logged_.insert(n).second) {
        uint64_t ret_addr = mem_.read64(r.rsp);
        std::fprintf(stderr, "    [unknown] %s!%s ret=0x%llx (%s)\n",
                     t.module.c_str(), n.c_str(),
                     static_cast<unsigned long long>(ret_addr),
                     where(ret_addr).c_str());
    }
    ret(0);
}

void DllRunner::report(Stop s) {
    auto& r = cpu_.regs();
    uint64_t rip = cpu_.fault() ? cpu_.fault_rip() : r.rip;
    std::fprintf(stderr, "  => STOP: %s at 0x%llx (%s)\n", stop_name(static_cast<int>(s)),
                (unsigned long long)rip, where(rip).c_str());
    if (cpu_.fault())
        std::fprintf(stderr, "     fault=%d (%s) mnemonic=%s\n", cpu_.fault(),
                    cpu_.fault() == 1 ? "undecodable" : "unimplemented",
                    cpu::mnemonic_name(cpu_.fault_mnemonic()));
    std::fprintf(stderr, "     bytes:");
    for (int i = 0; i < 16; ++i) std::fprintf(stderr, " %02x", mem_.read8(rip + i));
    std::fprintf(stderr, "\n     rax=%llx rcx=%llx rdx=%llx rsp=%llx r8=%llx r9=%llx\n",
                (unsigned long long)r.rax, (unsigned long long)r.rcx, (unsigned long long)r.rdx,
                (unsigned long long)r.rsp, (unsigned long long)r.r8, (unsigned long long)r.r9);
    std::fprintf(stderr, "     last rips:");
    for (size_t i = 0; i < ring_.size(); ++i) {
        uint64_t v = ring_[(ring_pos_ + i) % ring_.size()];
        if (v) std::fprintf(stderr, " %s", where(v).c_str());
    }
    std::fprintf(stderr, "\n     insns executed: %llu\n", (unsigned long long)insn_count_);
}

namespace {
struct LayoutFile { int chunk; std::string marker; std::string rel; };

std::string xml_attr(const std::string& line, const char* key) {
    std::string k = std::string(key) + "=\"";
    auto p = line.find(k);
    if (p == std::string::npos) return {};
    p += k.size();
    auto e = line.find('"', p);
    return e == std::string::npos ? std::string{} : line.substr(p, e - p);
}

// Parse layout_*_xs.xml: ordered (chunk, file) list, as the Xbox streaming installer sees it.
std::vector<LayoutFile> parse_layout(const std::string& game_dir) {
    namespace fs = std::filesystem;
    std::vector<LayoutFile> out;
    for (auto& e : fs::directory_iterator(game_dir)) {
        auto n = lower(e.path().filename().string());
        if (n.rfind("layout_", 0) != 0 || n.size() < 7 || n.substr(n.size() - 7) != "_xs.xml") continue;
        std::FILE* f = std::fopen(e.path().c_str(), "rb");
        if (!f) continue;
        std::string line; int chunk = -1; std::string marker; char buf[4096];
        while (std::fgets(buf, sizeof(buf), f)) {
            line = buf;
            if (line.find("<Chunk") != std::string::npos) {
                chunk = std::atoi(xml_attr(line, "Id").c_str());
                marker = xml_attr(line, "Marker");
            } else if (line.find("<FileGroup") != std::string::npos) {
                std::string rel = xml_attr(line, "DestinationPath") + xml_attr(line, "Include");
                std::replace(rel.begin(), rel.end(), '\\', '/');
                while (!rel.empty() && rel[0] == '/') rel.erase(0, 1);
                out.push_back({chunk, marker, rel});
            }
        }
        std::fclose(f);
        break;
    }
    return out;
}

// Imported DLL names (lowercase) read straight from a PE32+ file on disk.
std::vector<std::string> pe_import_names(const std::string& path) {
    std::vector<std::string> out;
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return out;
    std::fseek(f, 0, SEEK_END); long sz = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> d(static_cast<size_t>(sz));
    size_t rd = std::fread(d.data(), 1, d.size(), f);
    std::fclose(f);
    if (rd != d.size() || d.size() < 0x40) return out;
    auto u16 = [&](size_t o) -> uint32_t { return o + 2 <= d.size() ? d[o] | d[o+1] << 8 : 0; };
    auto u32 = [&](size_t o) -> uint32_t { return o + 4 <= d.size() ? u16(o) | u16(o+2) << 16 : 0; };
    size_t nt = u32(0x3C);
    if (u32(nt) != 0x4550) return out;
    uint32_t nsec = u16(nt + 6), opt_sz = u16(nt + 20);
    size_t opt = nt + 24;
    if (u16(opt) != 0x20B) return out;
    uint32_t imp_rva = u32(opt + 112 + 8);  // data dir #1
    size_t sec = opt + opt_sz;
    auto rva2off = [&](uint32_t rva) -> size_t {
        for (uint32_t i = 0; i < nsec; ++i) {
            size_t s = sec + i * 40;
            uint32_t va = u32(s + 12), vs = std::max(u32(s + 8), u32(s + 16)), raw = u32(s + 20);
            if (rva >= va && rva < va + vs) return raw + (rva - va);
        }
        return 0;
    };
    size_t o = rva2off(imp_rva);
    if (!imp_rva || !o) return out;
    for (; o + 20 <= d.size(); o += 20) {
        uint32_t name_rva = u32(o + 12);
        if (!name_rva) break;
        size_t no = rva2off(name_rva);
        std::string n;
        while (no && no < d.size() && d[no]) n += static_cast<char>(d[no++]);
        out.push_back(lower(n));
    }
    return out;
}
} // namespace

std::optional<LoadedImage> DllRunner::load_exe(const std::string& game_dir) {
    namespace fs = std::filesystem;
    game_dir_ = game_dir;
    exe_name_ = title_exe_name(game_dir);
    fs::path exe = fs::path(game_dir) / exe_name_;
    if (!fs::exists(exe)) return std::nullopt;
    auto img = loader_.load_pe(exe.string(), 0x140000000ULL);
    if (!img) {
        std::fprintf(stderr, "  [exe] load failed\n");
        return std::nullopt;
    }
    std::fprintf(stderr, "\n  [exe] %s base=0x%llx size=0x%llx entry=+0x%llx\n", img->name.c_str(),
                 (unsigned long long)img->base_vaddr, (unsigned long long)img->image_size,
                 (unsigned long long)(img->entry_point - img->base_vaddr));
    abort_ = false;
    depth_ = 0;
    insn_count_ = 0;
    thunk_log_ = 0;
    budget_ = 1'500'000'000ULL;
    cur_base_ = img->base_vaddr;
    mem_.write64(PEB + 0x10, img->base_vaddr);
    init_tls_slots(mem_.read64(TEB + 0x58)); // main thread: exe is mapped now
    cpu_.clear_fault();
    std::fill(ring_.begin(), ring_.end(), 0);
    return img;
}

void DllRunner::run_all(const std::string& game_dir, bool run_exe) {
    namespace fs = std::filesystem;
    game_dir_ = game_dir;
    setup_teb_peb();

    std::map<std::string, fs::path> on_disk;
    for (auto& e : fs::directory_iterator(game_dir))
        if (e.is_regular_file() && lower(e.path().extension().string()) == ".dll")
            on_disk[lower(e.path().filename().string())] = e.path();

    // 1) layout xml = install/launch order. Mount everything in chunk order up to "Launch".
    auto layout = parse_layout(game_dir);
    std::vector<std::string> dll_set;
    if (layout.empty()) {
        std::fprintf(stderr, "  [layout] no layout_*_xs.xml, using built-in DLL order\n");
        for (auto* n : LOAD_ORDER) dll_set.push_back(lower(n));
    } else {
        std::fprintf(stderr, "  [layout] %zu files, chunk order:\n", layout.size());
        int cur = -2, present = 0, total = 0;
        for (auto& lf : layout) {
            if (lf.chunk != cur) {
                cur = lf.chunk;
                std::fprintf(stderr, "  [chunk %d]%s%s\n", cur, lf.marker.empty() ? "" : " marker=",
                            lf.marker.c_str());
            }
            fs::path p = fs::path(game_dir) / lf.rel;
            std::error_code ec;
            bool ex = fs::exists(p, ec);
            uint64_t sz = ex ? fs::file_size(p, ec) : 0;
            const char* kind = "";
            ++total; present += ex;
            std::fprintf(stderr, "     %-58s %s%s\n", lf.rel.c_str(),
                        ex ? (std::to_string(sz >> 20) + "MB").c_str() : "ABSENT", kind);
            auto ln = lower(lf.rel);
            if (lf.chunk == 1002 || (ln.size() > 4 && ln.substr(ln.size() - 4) == ".dll"))
                if (ln.find('/') == std::string::npos) dll_set.push_back(ln);
        }
        std::fprintf(stderr, "  [layout] %d/%d files present\n", present, total);
    }

    // 2) order DLLs like the Windows loader: dependencies first (DFS on PE imports).
    std::vector<std::string> order;
    std::map<std::string, int> state;  // 0 new, 1 visiting, 2 done
    std::function<void(const std::string&)> visit = [&](const std::string& n) {
        if (state[n]) return;
        state[n] = 1;
        auto it = on_disk.find(n);
        if (it != on_disk.end())
            for (auto& dep : pe_import_names(it->second.string()))
                if (on_disk.count(dep) && std::find(dll_set.begin(), dll_set.end(), dep) != dll_set.end())
                    visit(dep);
        state[n] = 2;
        order.push_back(n);
    };
    for (auto& n : dll_set) visit(n);
    std::fprintf(stderr, "\n  [order] import-dependency order:");
    for (auto& n : order) std::fprintf(stderr, " %s", n.c_str());
    std::fprintf(stderr, "\n");

    std::vector<LoadedImage> loaded;
    uint64_t base = DLL_BASE;
    for (auto& name : order) {
        auto it = on_disk.find(name);
        if (it == on_disk.end()) { std::fprintf(stderr, "  [dll] %s missing\n", name.c_str()); continue; }
        auto img = loader_.load_pe(it->second.string(), base);
        base += DLL_STRIDE;
        if (!img) { std::fprintf(stderr, "  [dll] %s: load failed\n", name.c_str()); continue; }
        std::fprintf(stderr, "  [dll] %-34s base=0x%llx size=0x%llx entry=+0x%llx\n", img->name.c_str(),
                    (unsigned long long)img->base_vaddr, (unsigned long long)img->image_size,
                    (unsigned long long)(img->entry_point - img->base_vaddr));
        loaded.push_back(*img);
    }

    int ok = 0;
    for (auto& img : loaded) {
        std::fprintf(stderr, "\n  [DllMain] %s\n", img.name.c_str());
        if (img.entry_point == img.base_vaddr) { std::fprintf(stderr, "  => no entry point\n"); ++ok; continue; }
        abort_ = false; depth_ = 0; insn_count_ = 0; thunk_log_ = 0;
        cur_base_ = img.base_vaddr;
        mem_.write64(PEB + 0x10, img.base_vaddr);
        cpu_.clear_fault();
        std::fill(ring_.begin(), ring_.end(), 0);
        uint64_t rv = call_guest(img.entry_point, img.base_vaddr, 1 /*PROCESS_ATTACH*/, 0);
        if (!abort_) {
            std::fprintf(stderr, "  => returned %llu after %llu insns\n", (unsigned long long)rv,
                        (unsigned long long)insn_count_);
            ++ok;
        }
    }
    std::fprintf(stderr, "\n  [summary] %d/%zu DllMain returned\n", ok, loaded.size());
    exe_name_ = title_exe_name(game_dir);
    fs::path exe = fs::path(game_dir) / exe_name_;
    std::fprintf(stderr, "  [launch] %s %s\n", exe_name_.c_str(),
                fs::exists(exe) ? "present" : "ABSENT: no title entry point to jump to");
    if (!run_exe || !fs::exists(exe)) return;

    auto img = load_exe(game_dir);
    if (!img) return;
    uint64_t rv = call_guest(img->entry_point);
    std::fprintf(stderr, "  [exe] %s after %llu insns (rv=%llu)\n", abort_ ? "stopped" : "returned",
                (unsigned long long)insn_count_, (unsigned long long)rv);
}

} // namespace emu::kernel
