#pragma once
#include "cpu/cpu.h"

namespace emu::cpu {

enum class NativeStop { Slice, Trap, Fault, Syscall };

// Run guest code on this CPU until a thunk (int3), a fault, or a few milliseconds.
NativeStop native_slice(Registers& regs);

} // namespace emu::cpu
