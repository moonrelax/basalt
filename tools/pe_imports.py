#!/usr/bin/env python3
"""PE32+ import table inventory tool for basalt.

Reads a PE32+ executable using only the Python standard library (struct),
lists every imported DLL and function (by name or ordinal), cross-references
against handled functions in src/kernel/dll_runner.cpp and
src/kernel/xbox_gdk_stubs.cpp, and writes docs/imports_status.md.

Usage:
    python3 -I tools/pe_imports.py <path/to/title.exe>
"""

from collections import defaultdict
from pathlib import Path
import re
import struct
import sys


def read_cstr(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("ascii", errors="replace")


def parse_pe_imports(pe_path: Path) -> list[tuple[str, str]]:
    """Parse the PE32+ (or PE32) import directory and return [(dll, func), ...]."""
    data = pe_path.read_bytes()
    if len(data) < 0x40:
        raise ValueError(f"{pe_path}: file too small to be a PE")

    e_magic, = struct.unpack_from("<H", data, 0)
    if e_magic != 0x5A4D:  # 'MZ'
        raise ValueError(f"{pe_path}: invalid DOS magic 0x{e_magic:04x}")

    e_lfanew, = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 24 > len(data):
        raise ValueError(f"{pe_path}: invalid e_lfanew 0x{e_lfanew:x}")

    sig, machine, num_sections, _ts, _sym_ptr, _num_syms, opt_size, _chars = (
        struct.unpack_from("<IHHIIIHH", data, e_lfanew)
    )
    if sig != 0x00004550:  # 'PE\0\0'
        raise ValueError(f"{pe_path}: invalid PE signature 0x{sig:08x}")

    opt_off = e_lfanew + 24
    if opt_off + opt_size > len(data):
        raise ValueError(f"{pe_path}: optional header truncated")

    magic, = struct.unpack_from("<H", data, opt_off)
    if magic == 0x020B:  # PE32+
        is_pe32_plus = True
        dd_off = opt_off + 112
        num_rva_off = opt_off + 108
        headers_size, = struct.unpack_from("<I", data, opt_off + 60)
    elif magic == 0x010B:  # PE32
        is_pe32_plus = False
        dd_off = opt_off + 96
        num_rva_off = opt_off + 92
        headers_size, = struct.unpack_from("<I", data, opt_off + 60)
    else:
        raise ValueError(f"{pe_path}: unsupported optional header magic 0x{magic:04x}")

    num_data_dirs, = struct.unpack_from("<I", data, num_rva_off)
    if num_data_dirs <= 1 or dd_off + 16 > opt_off + opt_size:
        return []

    imp_rva, imp_size = struct.unpack_from("<II", data, dd_off + 8)
    if imp_rva == 0:
        return []

    # Parse section headers
    sec_off = opt_off + opt_size
    sections = []
    for i in range(num_sections):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        _name, virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from(
            "<8sIIII", data, off
        )
        span = max(virt_size, raw_size)
        sections.append((virt_addr, span, raw_size, raw_ptr))

    def rva_to_off(rva: int) -> int | None:
        if rva == 0:
            return None
        if rva < headers_size:
            return rva
        for va, span, raw_size, raw_ptr in sections:
            if va <= rva < va + span:
                delta = rva - va
                if delta < raw_size:
                    return raw_ptr + delta
                return None
        return None

    desc_off = rva_to_off(imp_rva)
    if desc_off is None:
        raise ValueError(f"{pe_path}: cannot map import directory RVA 0x{imp_rva:x}")

    imports: list[tuple[str, str]] = []
    entry_size = 8 if is_pe32_plus else 4
    entry_fmt = "<Q" if is_pe32_plus else "<I"
    ord_flag = (1 << 63) if is_pe32_plus else (1 << 31)

    while desc_off + 20 <= len(data):
        orig_first_thunk, _td, _fwd, name_rva, first_thunk = struct.unpack_from(
            "<IIIII", data, desc_off
        )
        if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break
        desc_off += 20

        name_off = rva_to_off(name_rva)
        dll_name = read_cstr(data, name_off) if name_off is not None else "<unknown>"

        thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
        thunk_off = rva_to_off(thunk_rva)
        if thunk_off is None:
            continue

        while thunk_off + entry_size <= len(data):
            val, = struct.unpack_from(entry_fmt, data, thunk_off)
            if val == 0:
                break
            thunk_off += entry_size

            if val & ord_flag:
                func_name = f"#{val & 0xFFFF}"
            else:
                hint_name_rva = val & 0x7FFFFFFF
                hn_off = rva_to_off(hint_name_rva)
                if hn_off is not None and hn_off + 2 < len(data):
                    func_name = read_cstr(data, hn_off + 2)
                else:
                    func_name = f"<invalid_rva:0x{hint_name_rva:x}>"

            imports.append((dll_name, func_name))

    return imports


def strip_cpp_comments(src: str) -> str:
    # Remove // line comments and /* ... */ block comments without eating string contents.
    pattern = re.compile(
        r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/', re.DOTALL
    )
    def repl(m: re.Match[str]) -> str:
        s = m.group(0)
        return s if s.startswith('"') else ""
    return pattern.sub(repl, src)


def collect_handled_from_dll_runner(path: Path) -> set[str]:
    if not path.exists():
        return set()
    src = strip_cpp_comments(path.read_text(encoding="utf-8", errors="replace"))
    handled: set[str] = set()
    for block in re.findall(r"\bis\s*\(\s*\{(.*?)\}\s*\)", src, flags=re.DOTALL):
        for name in re.findall(r'"([^"]+)"', block):
            handled.add(name)
    return handled


def collect_handled_from_gdk_stubs(path: Path) -> set[str]:
    if not path.exists():
        return set()
    src = strip_cpp_comments(path.read_text(encoding="utf-8", errors="replace"))
    handled: set[str] = set()
    # Matches entries like { "XGameRuntime.dll", "XGameGetXboxTitleId", 0x..., "..." }
    for m in re.finditer(r'\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,', src):
        handled.add(m.group(2))
    return handled


def write_report(
    out_path: Path,
    pe_path: Path,
    imports: list[tuple[str, str]],
    handled_names: set[str],
    dll_runner_names: set[str],
    gdk_stub_names: set[str],
) -> tuple[int, int]:
    rows: list[tuple[str, str, str]] = []
    per_dll_total: dict[str, int] = defaultdict(int)
    per_dll_handled: dict[str, int] = defaultdict(int)
    per_dll_missing: dict[str, int] = defaultdict(int)

    for dll, fn in imports:
        status = "gere" if fn in handled_names else "manquant"
        rows.append((dll, fn, status))
        per_dll_total[dll] += 1
        if status == "gere":
            per_dll_handled[dll] += 1
        else:
            per_dll_missing[dll] += 1

    # Missing first (sorted by DLL then function), then handled (sorted by DLL then function).
    rows.sort(key=lambda r: (0 if r[2] == "manquant" else 1, r[0].lower(), r[1].lower()))

    total = len(rows)
    n_handled = sum(1 for _, _, st in rows if st == "gere")
    n_missing = total - n_handled

    lines: list[str] = []
    lines.append("# Inventaire des imports PE32+")
    lines.append("")
    lines.append(f"- Executable : `{pe_path.name}`")
    lines.append(f"- Total imports PE : **{total}** ({len(per_dll_total)} DLLs)")
    lines.append(f"- Geres (`dll_runner.cpp` : {len(dll_runner_names)} noms, `xbox_gdk_stubs.cpp` : {len(gdk_stub_names)} noms) : **{n_handled}**")
    lines.append(f"- Manquants : **{n_missing}**")
    lines.append("")
    lines.append("## Resume par DLL")
    lines.append("")
    lines.append("| dll | total | geres | manquants |")
    lines.append("| --- | ---: | ---: | ---: |")
    for dll in sorted(per_dll_total.keys(), key=lambda d: (-per_dll_missing[d], d.lower())):
        lines.append(
            f"| `{dll}` | {per_dll_total[dll]} | {per_dll_handled[dll]} | {per_dll_missing[dll]} |"
        )
    lines.append("")
    lines.append("## Liste complete (manquants tries par DLL, puis geres)")
    lines.append("")
    lines.append("| dll | fonction | statut |")
    lines.append("| --- | --- | --- |")
    for dll, fn, status in rows:
        esc_fn = fn.replace("|", "\\|")
        lines.append(f"| `{dll}` | `{esc_fn}` | {status} |")
    lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return n_handled, n_missing


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"Usage: python3 -I {argv[0]} <path/to/executable.exe>", file=sys.stderr)
        return 1

    pe_path = Path(argv[1])
    if not pe_path.is_file():
        print(f"Error: file not found: {pe_path}", file=sys.stderr)
        return 1

    repo_root = Path(__file__).resolve().parent.parent
    dll_runner_path = repo_root / "src" / "kernel" / "dll_runner.cpp"
    gdk_stubs_path = repo_root / "src" / "kernel" / "xbox_gdk_stubs.cpp"
    out_path = repo_root / "docs" / "imports_status.md"

    imports = parse_pe_imports(pe_path)
    dll_runner_names = collect_handled_from_dll_runner(dll_runner_path)
    gdk_stub_names = collect_handled_from_gdk_stubs(gdk_stubs_path)
    handled_names = dll_runner_names | gdk_stub_names

    n_handled, n_missing = write_report(
        out_path, pe_path, imports, handled_names, dll_runner_names, gdk_stub_names
    )

    dlls = sorted({dll for dll, _ in imports}, key=str.lower)
    print(f"PE: {pe_path}")
    print(f"DLLs imported: {len(dlls)}")
    print(f"Total imports: {len(imports)} (gere: {n_handled}, manquant: {n_missing})")
    print(f"Wrote: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
