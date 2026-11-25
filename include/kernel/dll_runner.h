#pragma once
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include "kernel/loader.h"
#include "cpu/cpu.h"
#include "memory/memory_map.h"

namespace emu::kernel {

std::string title_exe_name(const std::string& dir);

struct PendingThread {
    uint64_t entry      = 0;
    uint64_t param      = 0;
    uint64_t stack_size = 0;
    uint64_t handle     = 0;
    uint32_t tid        = 0;
    bool     suspended  = false;
};

struct WaitRequest {
    bool                  active      = false;
    bool                  wait_all    = false;
    uint64_t              wake_rax    = 0; // value rax gets when the wait is released
    uint64_t              sleep_until = 0; // guest QPC tick that ends a Sleep
    std::vector<uint64_t> handles;
};

// Loads the title DLLs shipped in the dump and runs each DllMain(PROCESS_ATTACH)
// in the interpreter with a fake TEB/PEB and HLE'd Win32/CRT imports, until it
// returns or crashes. Reports where each one stopped.
class DllRunner {
public:
    static constexpr uint64_t kSentinel      = 0x3EFFFFFF0ULL;
    static constexpr uint64_t kMainTeb       = 0x3E0000000ULL;
    static constexpr uint64_t kMainPeb       = 0x3E0010000ULL;
    static constexpr uint64_t kMainStackTop  = 0x3D0000000ULL;
    static constexpr uint64_t kMainStackSize = 0x100000ULL;

    DllRunner(memory::MemoryMap& mem, cpu::CPU& cpu);
    ~DllRunner();

    DllRunner(const DllRunner&) = delete;
    DllRunner& operator=(const DllRunner&) = delete;

    void run_all(const std::string& game_dir, bool run_exe = false);

    // Load the title executable after run_all(game_dir, false) so an external
    // cooperative scheduler can drive the main thread and spawned guest threads.
    std::optional<LoadedImage> load_exe(const std::string& game_dir);

    // Pending guest threads recorded by CreateThread.
    const std::vector<PendingThread>& pending_threads() const { return pending_threads_; }
    std::vector<PendingThread>        take_pending_threads();
    std::vector<uint64_t>             take_resumed_threads();

    // Scheduler integration helpers.
    Loader&       loader()       { return loader_; }
    const Loader& loader() const { return loader_; }
    bool          in_image(uint64_t va) const;
    // Image that contains va. Hot loops stay inside one image, so the
    // scheduler can run a burst with a single range check.
    bool          image_span(uint64_t va, uint64_t& base, uint64_t& end) const;
    void          handle_thunk(const Thunk& t);
    std::string   where(uint64_t va) const;

    void          set_scheduler_mode(bool on)   { scheduler_mode_ = on; }
    void          set_current_tid(uint32_t tid) { current_tid_ = tid; }
    uint32_t      current_tid() const           { return current_tid_; }
    void          add_insn_count(uint64_t n)    { insn_count_ += n; guest_qpc_ += n * 10; }
    uint64_t      guest_qpc() const             { return guest_qpc_; }
    void          advance_qpc_to(uint64_t tick) { if (tick > guest_qpc_) guest_qpc_ = tick; }
    uint64_t      insn_count() const            { return insn_count_; }
    // Caps call_guest / DllMain as well as the scheduler loop. Without this,
    // one thunk (_initterm) runs until the hardcoded 1.5e9 ceiling.
    void          set_insn_budget(uint64_t n)   { budget_ = n; }

    WaitRequest   take_wait_request();
    bool          take_yield_request();
    bool          is_event_handle(uint64_t h) const;
    bool          is_event_signaled(uint64_t h) const;
    bool          try_acquire_event(uint64_t h, uint32_t tid = 0);
    uint64_t      alloc_stack(uint64_t size);
    uint64_t      alloc_teb(uint64_t stack_top, uint64_t stack_size, uint32_t tid);

    bool          aborted() const { return abort_; }
    void          clear_abort()   { abort_ = false; }

    void          set_trace_from(uint64_t va) { trace_from_ = va; }
    uint64_t      trace_from() const          { return trace_from_; }
    bool          trace_active() const        { return trace_active_; }
    void          set_trace_active(bool on)   { trace_active_ = on; }
    bool          consume_trace_step()        { if (trace_budget_ <= 0) return false; --trace_budget_; return true; }
    std::string   describe_handle(uint64_t h) const;
    void          pump_auto_task_queues();
    void          record_milestone(const std::string& label, uint64_t va);
    void          dump_milestones() const;

private:
    mutable int img_hint_ = -1;
    enum class Stop { Returned, Fault, Halt, WildJump, Budget, Aborted };

    struct FileHandle {
        std::FILE*  fp = nullptr;
        std::string guest_path;
        std::string host_path;
        uint64_t    size = 0;
    };

    struct FindEntry {
        std::string name;
        uint64_t    size = 0;
        bool        dir  = false;
    };
    struct FindState {
        bool                   wide = false;
        std::vector<FindEntry> entries;
        size_t                 index = 0;
    };

    struct EventObj {
        bool        manual_reset = false;
        bool        signaled     = false;
        std::string name;
        int64_t     sem_count    = -1; // >=0: semaphore count, -1: event/mutex
        bool        is_mutex     = false;
        uint32_t    owner        = 0;
        uint32_t    recursion    = 0;
        void take(uint32_t tid) {
            consume();
            if (is_mutex) { owner = tid; recursion = 1; }
        }
        void consume() {
            if (sem_count >= 0) signaled = --sem_count > 0;
            else if (!manual_reset) signaled = false;
        }
    };

    struct TaskQueueItem {
        uint64_t port     = 0; // 0 = work, 1 = completion
        uint64_t callback = 0;
        uint64_t context  = 0;
    };

    struct TaskQueueObj {
        uint32_t                   work_mode = 0;
        uint32_t                   comp_mode = 0;
        bool                       terminated = false;
        std::vector<TaskQueueItem> items;
    };

    struct Milestone {
        std::string label;
        uint64_t    va    = 0;
        uint64_t    insns = 0;
        uint32_t    tid   = 0;
    };

    memory::MemoryMap& mem_;
    cpu::CPU&          cpu_;
    Loader             loader_;
    std::string        game_dir_;
    std::string        exe_name_ = "title.exe";

    uint64_t heap_top_     = 0;
    uint64_t stack_cursor_ = 0x3CE000000ULL;
    std::map<uint64_t, uint64_t> alloc_sizes_;
    std::map<uint64_t, uint64_t> vallocs_;
    uint64_t big_top_ = 0x1000000000ULL; // lazy high reservations (>16 GiB)
    std::map<std::pair<uint32_t, uint32_t>, uint64_t> tls_;
    uint32_t tls_next_    = 1;
    std::map<uint32_t, uint32_t> last_errors_;
    uint64_t handle_next_ = 0x1000;
    uint32_t tid_next_    = 8;
    uint32_t current_tid_ = 8;
    uint64_t cur_base_    = 0;
    int      depth_       = 0;
    bool     abort_       = false;
    bool     scheduler_mode_  = false;
    bool     yield_requested_ = false;
    uint64_t insn_count_  = 0;
    uint64_t guest_qpc_   = 0;
    uint64_t budget_      = 20'000'000ULL;
    int      thunk_log_   = 0;
    int      read_log_    = 0;
    std::vector<uint64_t> ring_;
    size_t   ring_pos_    = 0;
    Stop     last_stop_   = Stop::Returned;

    std::map<uint64_t, FileHandle>   files_;
    std::map<uint64_t, FindState>    finds_;
    std::map<uint64_t, uint64_t>     ds_files_; // IDStorageFile object -> files_ handle
    std::map<uint64_t, EventObj>     events_;
    std::map<uint64_t, TaskQueueObj> task_queues_;
    std::vector<PendingThread>       pending_threads_;
    std::vector<PendingThread>       new_threads_;
    std::vector<uint64_t>            resumed_threads_;
    std::set<std::string>            unknown_logged_;
    std::map<std::string, uint64_t>  unknown_counts_;
    std::vector<Milestone>           milestones_;
    std::set<uint64_t>               milestone_seen_;
    uint64_t                         trace_from_   = 0;
    bool                             trace_active_ = false;
    int                              trace_budget_ = 200;
    WaitRequest                      wait_req_;

    void     setup_teb_peb();
    void     init_tls_slots(uint64_t tls_arr);
    void     attach_tls(uint64_t teb, bool run_callbacks);
    uint32_t exe_tls_slot_ = 0xFFFFFFFFu;
    bool     tls_attach_ran_ = false;
    uint64_t alloc(uint64_t size, uint64_t align = 16);
    uint64_t virtual_alloc(uint64_t req_addr, uint64_t size, uint32_t alloc_type);
    bool     virtual_free(uint64_t addr, uint32_t free_type);
    uint64_t call_guest(uint64_t fn, uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0, uint64_t a4 = 0);
    Stop     loop(uint64_t sentinel);
    uint64_t arg(int i);
    uint64_t make_fake_com(const std::string& iid);
    void     report(Stop s);
    std::string read_str(uint64_t va, bool wide) const;
    void     write_wstr(uint64_t va, const std::string& s);
    void     write_cstr(uint64_t va, const std::string& s);
    std::string resolve_host_path(const std::string& xbox_path, bool* found = nullptr) const;
    uint64_t open_file(const std::string& guest_path, uint32_t access, uint32_t disp);
    uint64_t wait_single(uint64_t handle, uint32_t timeout_ms);
    uint64_t wait_multiple(uint32_t count, uint64_t handles_ptr, bool wait_all, uint32_t timeout_ms);
    uint32_t get_last_error() const;
    void     set_last_error(uint32_t err);
};

} // namespace emu::kernel
