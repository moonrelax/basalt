# parallel incremental build: make -j$(nproc)
ifeq ($(origin CXX),default)
CXX := clang++
endif
CXXFLAGS ?= -std=c++23 -Iinclude -O2 -march=native -Wall -Wextra
OBJ      := build/obj

CORE := src/cpu/cpu.cpp src/cpu/decoder.cpp src/cpu/executor.cpp \
        src/memory/memory_map.cpp src/memory/mmu.cpp
APP  := src/gpu/command_processor.cpp src/gpu/ring_buffer.cpp \
        src/gpu/d3d12_xs.cpp src/gpu/swapchain.cpp \
        src/hal/interrupt_controller.cpp src/hal/timer.cpp \
        src/bus/pcie_bus.cpp src/host/guest_window.cpp src/kernel/loader.cpp \
        src/kernel/xbox_gdk_stubs.cpp src/kernel/dll_runner.cpp \
        src/kernel/scheduler.cpp src/kernel/xbox_launcher.cpp src/main.cpp
TESTS := tests/test_memory.cpp tests/test_mmu.cpp tests/test_cpu_basic.cpp tests/test_cpu_sse.cpp

o = $(patsubst %.cpp,$(OBJ)/%.o,$(1))

all: build/basalt
tests: build/basalt_tests

build/basalt: $(call o,$(CORE) $(APP)) $(OBJ)/src/cpu/native_run.o $(OBJ)/src/cpu/native_asm.o
	$(CXX) $^ -ldl -o $@
build/basalt_tests: $(call o,$(CORE) $(TESTS)) $(OBJ)/src/cpu/native_run.o $(OBJ)/src/cpu/native_asm.o
	$(CXX) $^ -lgtest_main -lgtest -pthread -o $@

$(OBJ)/tests/%.o: CXXFLAGS += -DGTEST_HAS_PTHREAD=1
$(OBJ)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(OBJ)/src/cpu/native_asm.o: src/cpu/native_run.S
	@mkdir -p $(dir $@)
	$(CXX) -march=native -c $< -o $@

-include $(shell find $(OBJ) -name '*.d' 2>/dev/null)
.PHONY: all tests
