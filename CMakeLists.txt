cmake_minimum_required(VERSION 3.22)
project(basalt VERSION 0.1.0 LANGUAGES CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BASALT_ENABLE_JIT   "Enable x86-64 JIT recompiler"  ON)
option(BASALT_ENABLE_TESTS "Build test suite"               ON)
option(BASALT_SANITIZERS   "Enable ASan/UBSan"              OFF)

# ── Compiler flags ──────────────────────────────────────────────────────────
add_compile_options(
    -Wall -Wextra -Wpedantic
    -march=native
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:Debug>:-O0 -g3>
)

if(BASALT_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

# ── Third-party ──────────────────────────────────────────────────────────────
find_package(fmt QUIET)
find_package(spdlog QUIET)

# ── Core library ─────────────────────────────────────────────────────────────
add_library(basalt_core STATIC
    src/cpu/cpu.cpp
    src/cpu/decoder.cpp
    src/cpu/executor.cpp
    src/memory/memory_map.cpp
    src/memory/mmu.cpp
    src/gpu/command_processor.cpp
    src/gpu/ring_buffer.cpp
    src/hal/timer.cpp
    src/hal/interrupt_controller.cpp
    src/bus/pcie_bus.cpp
    src/kernel/loader.cpp
)

target_include_directories(basalt_core PUBLIC include)

# ── Main executable ───────────────────────────────────────────────────────────
add_executable(basalt src/main.cpp)
target_link_libraries(basalt PRIVATE basalt_core)

# ── Tests ─────────────────────────────────────────────────────────────────────
if(BASALT_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
