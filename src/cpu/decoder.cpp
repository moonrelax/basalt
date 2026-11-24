#include "cpu/decoder.h"
#include <cstring>

namespace emu::cpu {

// ── Helpers ───────────────────────────────────────────────────────────────────

Operand Decoder::make_reg(uint8_t idx, int size) {
    Operand o; o.type = OperandType::Reg; o.reg = idx; o.size = size; return o;
}
Operand Decoder::make_imm(int64_t val, int size) {
    Operand o; o.type = OperandType::Imm; o.imm = val; o.size = size; return o;
}
Operand Decoder::make_rel(int64_t rel, int size) {
    Operand o; o.type = OperandType::Rel; o.imm = rel; o.size = size; return o;
}

void Decoder::decode_prefixes(Ctx& c) {
    while (c.pos < c.max) {
        uint8_t b = c.base[c.pos];
        switch (b) {
            case 0xF0: c.pfx.lock   = true; c.pos++; break;
            case 0xF2: c.pfx.repne  = true; c.pos++; break;
            case 0xF3: c.pfx.rep    = true; c.pos++; break;
            case 0x2E: c.pfx.seg_cs = true; c.pos++; break;
            case 0x36: c.pfx.seg_ss = true; c.pos++; break;
            case 0x3E: c.pfx.seg_ds = true; c.pos++; break;
            case 0x26: c.pfx.seg_es = true; c.pos++; break;
            case 0x64: c.pfx.seg_fs = true; c.pos++; break;
            case 0x65: c.pfx.seg_gs = true; c.pos++; break;
            case 0x66: c.pfx.op66   = true; c.pos++; c.op_size = 2;  break;
            case 0x67: c.pfx.ad67   = true; c.pos++; c.addr_size = 4; break;
            default:
                // REX (40–4F)
                if ((b & 0xF0) == 0x40) {
                    c.pfx.rex   = true;
                    c.pfx.rex_w = !!(b & 0x08);
                    c.pfx.rex_r = !!(b & 0x04);
                    c.pfx.rex_x = !!(b & 0x02);
                    c.pfx.rex_b = !!(b & 0x01);
                    if (c.pfx.rex_w) c.op_size = 8;
                    c.pos++;
                    break;
                }
                goto done;
        }
    }
done:;
}

void Decoder::decode_vex2(Ctx& c) {
    // C5 [RvvvvLpp]
    uint8_t b = c.read8();
    c.pfx.vex      = true;
    c.pfx.rex_r    = !(b >> 7);
    c.pfx.vex_vvvv = (~b >> 3) & 0xF;
    c.pfx.vex_len  = (b >> 2) & 1;
    c.pfx.vex_pp   = b & 3;
    c.pfx.vex_map  = 1; // implied 0F
    c.pfx.vex_w    = false;
    c.pfx.rex_w    = false;
    if      (c.pfx.vex_pp == 1) c.pfx.op66  = true;
    else if (c.pfx.vex_pp == 2) c.pfx.rep   = true;
    else if (c.pfx.vex_pp == 3) c.pfx.repne = true;
}

void Decoder::decode_vex3(Ctx& c) {
    // C4 [RXBmmmmm] [WvvvvLpp]
    uint8_t b1 = c.read8();
    uint8_t b2 = c.read8();
    c.pfx.vex      = true;
    c.pfx.rex_r    = !(b1 >> 7);
    c.pfx.rex_x    = !((b1 >> 6) & 1);
    c.pfx.rex_b    = !((b1 >> 5) & 1);
    c.pfx.vex_map  = b1 & 0x1F;
    c.pfx.vex_w    = !!(b2 >> 7);
    c.pfx.rex_w    = c.pfx.vex_w;
    c.pfx.vex_vvvv = (~b2 >> 3) & 0xF;
    c.pfx.vex_len  = (b2 >> 2) & 1;
    c.pfx.vex_pp   = b2 & 3;
    if (c.pfx.vex_w) c.op_size = 8;
    if      (c.pfx.vex_pp == 1) c.pfx.op66  = true;
    else if (c.pfx.vex_pp == 2) c.pfx.rep   = true;
    else if (c.pfx.vex_pp == 3) c.pfx.repne = true;
}

ModRM Decoder::read_modrm(Ctx& c) {
    uint8_t b = c.read8();
    return { uint8_t(b >> 6), uint8_t((b >> 3) & 7), uint8_t(b & 7) };
}

SIB Decoder::read_sib(Ctx& c) {
    uint8_t b = c.read8();
    return { uint8_t(b >> 6), uint8_t((b >> 3) & 7), uint8_t(b & 7) };
}

Operand Decoder::decode_modrm_mem(Ctx& c, ModRM m, int op_size) {
    if (m.mod == 3) {
        // Register operand
        uint8_t idx = m.rm | (c.pfx.rex_b ? 8 : 0);
        return make_reg(idx, op_size);
    }

    Operand o;
    o.type = OperandType::Mem;
    o.size = op_size;

    int addr_size = c.addr_size;

    if (m.rm == 4 && addr_size == 8) {
        // SIB follows
        SIB sib = read_sib(c);
        uint8_t base_reg  = sib.base  | (c.pfx.rex_b ? 8 : 0);
        uint8_t index_reg = sib.index | (c.pfx.rex_x ? 8 : 0);

        if (index_reg != 4) { // RSP as index = no index
            o.index = index_reg;
            o.scale = 1 << sib.scale;
        }

        if (m.mod == 0 && (sib.base & 7) == 5) {
            // disp32, no base
            o.disp = c.reads32();
        } else {
            o.base = base_reg;
        }
    } else if (m.rm == 5 && m.mod == 0 && addr_size == 8) {
        // RIP-relative
        o.rip_rel = true;
        o.disp = c.reads32();
    } else {
        o.base = m.rm | (c.pfx.rex_b ? 8 : 0);
    }

    if      (m.mod == 1) o.disp = c.reads8();
    else if (m.mod == 2) o.disp = c.reads32();

    return o;
}

// ── Main decode entry ─────────────────────────────────────────────────────────

DecodedInsn Decoder::decode(const uint8_t* ip, int max_len) {
    Ctx c{ ip, 0, max_len, {}, 4, 8 }; // long mode default: 32-bit op, 64-bit addr
    decode_prefixes(c);

    if (c.pos >= c.max) return {};
    uint8_t b = c.base[c.pos]; // peek without consuming

    // VEX / EVEX escape
    if ((b == 0xC5 || b == 0xC4) && !c.pfx.rex) {
        c.pos++;
        if (b == 0xC5) decode_vex2(c);
        else           decode_vex3(c);
        return decode_vex_insn(c);
    }

    if (b == 0x0F) { c.pos++; return decode_two_byte(c); }
    return decode_one_byte(c);
}

// ── One-byte table ────────────────────────────────────────────────────────────
DecodedInsn Decoder::decode_one_byte(Ctx& c) {
    uint8_t op = c.read8();
    DecodedInsn insn;
    insn.prefixes  = c.pfx;
    insn.op_size   = c.pfx.rex_w ? 8 : (c.pfx.op66 ? 2 : 4);
    insn.addr_size = c.addr_size;

    int osz = insn.op_size;

    auto modrm = [&]() { return read_modrm(c); };
    auto mem   = [&](ModRM m) { return decode_modrm_mem(c, m, osz); };
    auto reg   = [&](uint8_t r) { return make_reg(r | (c.pfx.rex_r ? 8:0), osz); };
    auto rm_reg= [&](ModRM m) { return make_reg(m.rm |(c.pfx.rex_b?8:0), osz); };
    auto imm8  = [&]() { return make_imm((int8_t)c.read8(), 1); };
    auto imm16 = [&]() { return make_imm(c.read16(), 2); };
    auto imm32 = [&]() { return make_imm(c.reads32(), 4); };
    auto immZ  = [&]() { // sign-extend 32→64 or 16
        if (osz == 2) return make_imm(c.read16(), 2);
        return make_imm(c.reads32(), 4);
    };
    auto rel8  = [&]() { return make_rel((int8_t)c.read8(), 1); };
    auto rel32 = [&]() { return make_rel(c.reads32(), 4); };

    switch (op) {
        // ── ADD ──────────────────────────────────────────────────────────────
        case 0x00: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::ADD; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0x01: { auto m=modrm(); insn.mnemonic=Mnemonic::ADD; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0x02: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::ADD; insn.dst=make_reg(m.reg|(c.pfx.rex_r?8:0),1); insn.src=decode_modrm_mem(c,m,1); break; }
        case 0x03: { auto m=modrm(); insn.mnemonic=Mnemonic::ADD; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        case 0x04: insn.op_size=1; insn.mnemonic=Mnemonic::ADD; insn.dst=make_reg(0,1); insn.src=imm8(); break; // ADD AL,imm8
        case 0x05: insn.mnemonic=Mnemonic::ADD; insn.dst=make_reg(0,osz); insn.src=immZ(); break;
        // ── OR ───────────────────────────────────────────────────────────────
        case 0x08: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::OR; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0x09: { auto m=modrm(); insn.mnemonic=Mnemonic::OR; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0x0A: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::OR; insn.dst=make_reg(m.reg|(c.pfx.rex_r?8:0),1); insn.src=decode_modrm_mem(c,m,1); break; }
        case 0x0B: { auto m=modrm(); insn.mnemonic=Mnemonic::OR; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        case 0x0C: insn.op_size=1; insn.mnemonic=Mnemonic::OR; insn.dst=make_reg(0,1); insn.src=imm8(); break;
        case 0x0D: insn.mnemonic=Mnemonic::OR; insn.dst=make_reg(0,osz); insn.src=immZ(); break;
        // ── ADC ──────────────────────────────────────────────────────────────
        case 0x10: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::ADC; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0x11: { auto m=modrm(); insn.mnemonic=Mnemonic::ADC; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0x12: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::ADC; insn.dst=make_reg(m.reg|(c.pfx.rex_r?8:0),1); insn.src=decode_modrm_mem(c,m,1); break; }
        case 0x13: { auto m=modrm(); insn.mnemonic=Mnemonic::ADC; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        case 0x14: insn.op_size=1; insn.mnemonic=Mnemonic::ADC; insn.dst=make_reg(0,1); insn.src=imm8(); break;
        case 0x15: insn.mnemonic=Mnemonic::ADC; insn.dst=make_reg(0,osz); insn.src=immZ(); break;
        // ── SBB ──────────────────────────────────────────────────────────────
        case 0x18: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::SBB; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0x19: { auto m=modrm(); insn.mnemonic=Mnemonic::SBB; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0x1A: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::SBB; insn.dst=make_reg(m.reg|(c.pfx.rex_r?8:0),1); insn.src=decode_modrm_mem(c,m,1); break; }
        case 0x1B: { auto m=modrm(); insn.mnemonic=Mnemonic::SBB; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        case 0x1C: insn.op_size=1; insn.mnemonic=Mnemonic::SBB; insn.dst=make_reg(0,1); insn.src=imm8(); break;
        case 0x1D: insn.mnemonic=Mnemonic::SBB; insn.dst=make_reg(0,osz); insn.src=immZ(); break;
        // ── AND ──────────────────────────────────────────────────────────────
        case 0x20: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::AND; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0x21: { auto m=modrm(); insn.mnemonic=Mnemonic::AND; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0x22: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::AND; insn.dst=make_reg(m.reg|(c.pfx.rex_r?8:0),1); insn.src=decode_modrm_mem(c,m,1); break; }
        case 0x23: { auto m=modrm(); insn.mnemonic=Mnemonic::AND; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        case 0x24: insn.op_size=1; insn.mnemonic=Mnemonic::AND; insn.dst=make_reg(0,1); insn.src=imm8(); break;
        case 0x25: insn.mnemonic=Mnemonic::AND; insn.dst=make_reg(0,osz); insn.src=immZ(); break;
        // ── SUB ──────────────────────────────────────────────────────────────
        case 0x28: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::SUB; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0x29: { auto m=modrm(); insn.mnemonic=Mnemonic::SUB; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0x2A: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::SUB; insn.dst=make_reg(m.reg|(c.pfx.rex_r?8:0),1); insn.src=decode_modrm_mem(c,m,1); break; }
        case 0x2B: { auto m=modrm(); insn.mnemonic=Mnemonic::SUB; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        case 0x2C: insn.op_size=1; insn.mnemonic=Mnemonic::SUB; insn.dst=make_reg(0,1); insn.src=imm8(); break;
        case 0x2D: insn.mnemonic=Mnemonic::SUB; insn.dst=make_reg(0,osz); insn.src=immZ(); break;
        // ── XOR ──────────────────────────────────────────────────────────────
        case 0x30: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::XOR; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0x31: { auto m=modrm(); insn.mnemonic=Mnemonic::XOR; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0x32: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::XOR; insn.dst=make_reg(m.reg|(c.pfx.rex_r?8:0),1); insn.src=decode_modrm_mem(c,m,1); break; }
        case 0x33: { auto m=modrm(); insn.mnemonic=Mnemonic::XOR; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        case 0x34: insn.op_size=1; insn.mnemonic=Mnemonic::XOR; insn.dst=make_reg(0,1); insn.src=imm8(); break;
        case 0x35: insn.mnemonic=Mnemonic::XOR; insn.dst=make_reg(0,osz); insn.src=immZ(); break;
        // ── CMP ──────────────────────────────────────────────────────────────
        case 0x38: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::CMP; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0x39: { auto m=modrm(); insn.mnemonic=Mnemonic::CMP; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0x3A: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::CMP; insn.dst=make_reg(m.reg|(c.pfx.rex_r?8:0),1); insn.src=decode_modrm_mem(c,m,1); break; }
        case 0x3B: { auto m=modrm(); insn.mnemonic=Mnemonic::CMP; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        case 0x3C: insn.op_size=1; insn.mnemonic=Mnemonic::CMP; insn.dst=make_reg(0,1); insn.src=imm8(); break;
        case 0x3D: insn.mnemonic=Mnemonic::CMP; insn.dst=make_reg(0,osz); insn.src=immZ(); break;
        // ── PUSH/POP r64 (40-5F) ─────────────────────────────────────────────
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
            insn.mnemonic=Mnemonic::PUSH;
            insn.dst=make_reg((op-0x50)|(c.pfx.rex_b?8:0), 8);
            break;
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            insn.mnemonic=Mnemonic::POP;
            insn.dst=make_reg((op-0x58)|(c.pfx.rex_b?8:0), 8);
            break;
        // ── MOVSXD ───────────────────────────────────────────────────────────
        case 0x63: { auto m=modrm(); insn.mnemonic=Mnemonic::MOVSXD; insn.dst=reg(m.reg); insn.src=mem(m); insn.src.size=4; break; }
        // ── PUSH imm ─────────────────────────────────────────────────────────
        case 0x68: insn.mnemonic=Mnemonic::PUSH; insn.dst=immZ(); break;
        case 0x6A: insn.mnemonic=Mnemonic::PUSH; insn.dst=imm8(); break;
        // ── IMUL reg,rm,imm ──────────────────────────────────────────────────
        case 0x69: { auto m=modrm(); insn.mnemonic=Mnemonic::IMUL; insn.dst=reg(m.reg); insn.src=mem(m); insn.src2=immZ(); break; }
        case 0x6B: { auto m=modrm(); insn.mnemonic=Mnemonic::IMUL; insn.dst=reg(m.reg); insn.src=mem(m); insn.src2=imm8(); break; }
        // ── Jcc short ────────────────────────────────────────────────────────
        case 0x70: insn.mnemonic=Mnemonic::JO;   insn.dst=rel8(); break;
        case 0x71: insn.mnemonic=Mnemonic::JNO;  insn.dst=rel8(); break;
        case 0x72: insn.mnemonic=Mnemonic::JB;   insn.dst=rel8(); break;
        case 0x73: insn.mnemonic=Mnemonic::JNB;  insn.dst=rel8(); break;
        case 0x74: insn.mnemonic=Mnemonic::JZ;   insn.dst=rel8(); break;
        case 0x75: insn.mnemonic=Mnemonic::JNZ;  insn.dst=rel8(); break;
        case 0x76: insn.mnemonic=Mnemonic::JBE;  insn.dst=rel8(); break;
        case 0x77: insn.mnemonic=Mnemonic::JA;   insn.dst=rel8(); break;
        case 0x78: insn.mnemonic=Mnemonic::JS;   insn.dst=rel8(); break;
        case 0x79: insn.mnemonic=Mnemonic::JNS;  insn.dst=rel8(); break;
        case 0x7A: insn.mnemonic=Mnemonic::JP;   insn.dst=rel8(); break;
        case 0x7B: insn.mnemonic=Mnemonic::JNP;  insn.dst=rel8(); break;
        case 0x7C: insn.mnemonic=Mnemonic::JL;   insn.dst=rel8(); break;
        case 0x7D: insn.mnemonic=Mnemonic::JGE;  insn.dst=rel8(); break;
        case 0x7E: insn.mnemonic=Mnemonic::JLE;  insn.dst=rel8(); break;
        case 0x7F: insn.mnemonic=Mnemonic::JG;   insn.dst=rel8(); break;
        // ── Group 1: 80/81/83 ────────────────────────────────────────────────
        case 0x80: {
            auto m=modrm();
            static const Mnemonic g1[]={Mnemonic::ADD,Mnemonic::OR,Mnemonic::ADC,Mnemonic::SBB,
                                        Mnemonic::AND,Mnemonic::SUB,Mnemonic::XOR,Mnemonic::CMP};
            insn.op_size=1; insn.mnemonic=g1[m.reg]; insn.dst=decode_modrm_mem(c,m,1); insn.src=imm8();
            break;
        }
        case 0x81: {
            auto m=modrm();
            static const Mnemonic g1[]={Mnemonic::ADD,Mnemonic::OR,Mnemonic::ADC,Mnemonic::SBB,
                                        Mnemonic::AND,Mnemonic::SUB,Mnemonic::XOR,Mnemonic::CMP};
            insn.mnemonic=g1[m.reg]; insn.dst=mem(m); insn.src=immZ();
            break;
        }
        case 0x83: {
            auto m=modrm();
            static const Mnemonic g1[]={Mnemonic::ADD,Mnemonic::OR,Mnemonic::ADC,Mnemonic::SBB,
                                        Mnemonic::AND,Mnemonic::SUB,Mnemonic::XOR,Mnemonic::CMP};
            insn.mnemonic=g1[m.reg]; insn.dst=mem(m); insn.src=imm8(); // sign-extend
            break;
        }
        // ── TEST ─────────────────────────────────────────────────────────────
        case 0x84: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::TEST; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0x85: { auto m=modrm(); insn.mnemonic=Mnemonic::TEST; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0xA8: insn.op_size=1; insn.mnemonic=Mnemonic::TEST; insn.dst=make_reg(0,1); insn.src=imm8(); break;
        case 0xA9: insn.mnemonic=Mnemonic::TEST; insn.dst=make_reg(0,osz); insn.src=immZ(); break;
        // ── XCHG ─────────────────────────────────────────────────────────────
        case 0x86: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::XCHG; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0x87: { auto m=modrm(); insn.mnemonic=Mnemonic::XCHG; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0x90: insn.mnemonic=Mnemonic::NOP; break; // also XCHG EAX,EAX
        case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
            insn.mnemonic=Mnemonic::XCHG;
            insn.dst=make_reg(0,osz);
            insn.src=make_reg((op-0x90)|(c.pfx.rex_b?8:0), osz);
            break;
        // ── MOV ──────────────────────────────────────────────────────────────
        case 0x88: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::MOV; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0x89: { auto m=modrm(); insn.mnemonic=Mnemonic::MOV; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0x8A: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::MOV; insn.dst=make_reg(m.reg|(c.pfx.rex_r?8:0),1); insn.src=decode_modrm_mem(c,m,1); break; }
        case 0x8B: { auto m=modrm(); insn.mnemonic=Mnemonic::MOV; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        case 0x8C: { auto m=modrm(); insn.mnemonic=Mnemonic::MOV; insn.dst=mem(m); insn.src.type=OperandType::Reg; insn.src.reg=m.reg; insn.src.size=2; break; } // MOV rm,Sreg
        case 0x8E: { auto m=modrm(); insn.mnemonic=Mnemonic::MOV; insn.dst.type=OperandType::Reg; insn.dst.reg=m.reg; insn.dst.size=2; insn.src=mem(m); break; } // MOV Sreg,rm
        // MOV r64,imm64
        case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
            insn.mnemonic=Mnemonic::MOV;
            insn.dst=make_reg((op-0xB8)|(c.pfx.rex_b?8:0), osz);
            if (osz == 8) insn.src=make_imm((int64_t)c.read64(), 8);
            else if (osz == 4) insn.src=make_imm(c.read32(), 4);
            else insn.src=make_imm(c.read16(), 2);
            break;
        }
        // MOV r8,imm8
        case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            insn.op_size=1;
            insn.mnemonic=Mnemonic::MOV;
            insn.dst=make_reg((op-0xB0)|(c.pfx.rex_b?8:0), 1);
            insn.src=imm8();
            break;
        // MOV rm,imm (C6/C7)
        case 0xC6: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::MOV; insn.dst=decode_modrm_mem(c,m,1); insn.src=imm8(); break; }
        case 0xC7: { auto m=modrm(); insn.mnemonic=Mnemonic::MOV; insn.dst=mem(m); insn.src=immZ(); break; }
        // ── LEA ──────────────────────────────────────────────────────────────
        case 0x8D: { auto m=modrm(); insn.mnemonic=Mnemonic::LEA; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        // ── CALL/JMP ─────────────────────────────────────────────────────────
        case 0xE8: insn.mnemonic=Mnemonic::CALL; insn.dst=rel32(); break;
        case 0xE9: insn.mnemonic=Mnemonic::JMP;  insn.dst=rel32(); break;
        case 0xEB: insn.mnemonic=Mnemonic::JMP;  insn.dst=rel8();  break;
        // Group 5: FF /2 CALL, /4 JMP, /0 INC, /1 DEC, /6 PUSH
        case 0xFF: {
            auto m=modrm();
            switch (m.reg) {
                case 0: insn.mnemonic=Mnemonic::INC;  insn.dst=mem(m); break;
                case 1: insn.mnemonic=Mnemonic::DEC;  insn.dst=mem(m); break;
                // near CALL/JMP/PUSH r/m default to 64-bit operands in long mode
                case 2: insn.mnemonic=Mnemonic::CALL; insn.op_size=8; insn.dst=decode_modrm_mem(c,m,8); break;
                case 4: insn.mnemonic=Mnemonic::JMP;  insn.op_size=8; insn.dst=decode_modrm_mem(c,m,8); break;
                case 6: insn.mnemonic=Mnemonic::PUSH; insn.op_size=8; insn.src=decode_modrm_mem(c,m,8); break;
                default: break;
            }
            break;
        }
        // ── RET ──────────────────────────────────────────────────────────────
        case 0xC2: insn.mnemonic=Mnemonic::RET; insn.dst=make_imm(c.read16(),2); break;
        case 0xC3: insn.mnemonic=Mnemonic::RET; break;
        // ── INC/DEC r64 (40-47/48-4F removed in 64-bit, now REX) ────────────
        // Group 4: FE /0 INC r/m8, /1 DEC r/m8
        case 0xFE: {
            auto m=modrm();
            insn.op_size = 1;
            insn.mnemonic = (m.reg==0) ? Mnemonic::INC : Mnemonic::DEC;
            insn.dst = decode_modrm_mem(c, m, 1);
            break;
        }
        // ── Sign-extend RAX/RDX: CBW/CWDE/CDQE (98), CWD/CDQ/CQO (99) ────────
        case 0x98: insn.mnemonic=Mnemonic::CDQE; break;
        case 0x99: insn.mnemonic=Mnemonic::CQO;  break;
        // ── PUSH/POP FS/GS ───────────────────────────────────────────────────
        case 0x9C: insn.mnemonic=Mnemonic::PUSHF; break;
        case 0x9D: insn.mnemonic=Mnemonic::POPF; break;
        // ── String ops ───────────────────────────────────────────────────────
        case 0xA4: insn.mnemonic=Mnemonic::MOVS; insn.op_size=1; break;
        case 0xA5: insn.mnemonic=Mnemonic::MOVS; break;
        case 0xAA: insn.mnemonic=Mnemonic::STOS; insn.op_size=1; break;
        case 0xAB: insn.mnemonic=Mnemonic::STOS; break;
        case 0xAC: insn.mnemonic=Mnemonic::LODS; insn.op_size=1; break;
        case 0xAD: insn.mnemonic=Mnemonic::LODS; break;
        case 0xAE: insn.mnemonic=Mnemonic::SCAS; insn.op_size=1; break;
        case 0xAF: insn.mnemonic=Mnemonic::SCAS; break;
        // ── Flags ────────────────────────────────────────────────────────────
        case 0xF4: insn.mnemonic=Mnemonic::HLT; break;
        case 0xF5: insn.mnemonic=Mnemonic::CMC; break;
        case 0xF8: insn.mnemonic=Mnemonic::CLC; break;
        case 0xF9: insn.mnemonic=Mnemonic::STC; break;
        case 0xFA: insn.mnemonic=Mnemonic::CLI; break;
        case 0xFB: insn.mnemonic=Mnemonic::STI; break;
        case 0xFC: insn.mnemonic=Mnemonic::CLD; break;
        case 0xFD: insn.mnemonic=Mnemonic::STD; break;
        // ── INT ──────────────────────────────────────────────────────────────
        case 0xCC: insn.mnemonic=Mnemonic::INT3; break;
        case 0xCD: insn.mnemonic=Mnemonic::INT; insn.dst=imm8(); break;
        // ── MUL/DIV group F6/F7 ──────────────────────────────────────────────
        case 0xF6: {
            auto m=modrm();
            insn.op_size = 1;
            switch(m.reg) {
                case 0: case 1: insn.mnemonic=Mnemonic::TEST; insn.dst=decode_modrm_mem(c,m,1); insn.src=imm8(); break;
                case 2: insn.mnemonic=Mnemonic::NOT;  insn.dst=decode_modrm_mem(c,m,1); break;
                case 3: insn.mnemonic=Mnemonic::NEG;  insn.dst=decode_modrm_mem(c,m,1); break;
                case 4: insn.mnemonic=Mnemonic::MUL;  insn.dst=decode_modrm_mem(c,m,1); break;
                case 5: insn.mnemonic=Mnemonic::IMUL; insn.dst=decode_modrm_mem(c,m,1); break;
                case 6: insn.mnemonic=Mnemonic::DIV;  insn.dst=decode_modrm_mem(c,m,1); break;
                case 7: insn.mnemonic=Mnemonic::IDIV; insn.dst=decode_modrm_mem(c,m,1); break;
            }
            break;
        }
        case 0xF7: {
            auto m=modrm();
            switch(m.reg) {
                case 0: case 1: insn.mnemonic=Mnemonic::TEST; insn.dst=mem(m); insn.src=immZ(); break;
                case 2: insn.mnemonic=Mnemonic::NOT;  insn.dst=mem(m); break;
                case 3: insn.mnemonic=Mnemonic::NEG;  insn.dst=mem(m); break;
                case 4: insn.mnemonic=Mnemonic::MUL;  insn.dst=mem(m); break;
                case 5: insn.mnemonic=Mnemonic::IMUL; insn.dst=mem(m); break;
                case 6: insn.mnemonic=Mnemonic::DIV;  insn.dst=mem(m); break;
                case 7: insn.mnemonic=Mnemonic::IDIV; insn.dst=mem(m); break;
            }
            break;
        }
        // ── Shift group D0-D3 ────────────────────────────────────────────────
        case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
            auto m=modrm();
            static const Mnemonic sh[]={Mnemonic::ROL,Mnemonic::ROR,Mnemonic::RCL,Mnemonic::RCR,
                                        Mnemonic::SHL,Mnemonic::SHR,Mnemonic::SAL,Mnemonic::SAR};
            insn.mnemonic = sh[m.reg];
            if (op == 0xD0 || op == 0xD2) {
                insn.op_size = 1;
                insn.dst = decode_modrm_mem(c, m, 1);
            } else {
                insn.dst = mem(m);
            }
            if (op == 0xD0 || op == 0xD1) insn.src = make_imm(1, 1);
            else                          insn.src = make_reg(1, 1); // CL
            break;
        }
        case 0xC0: { auto m=modrm(); static const Mnemonic sh[]={Mnemonic::ROL,Mnemonic::ROR,Mnemonic::RCL,Mnemonic::RCR,Mnemonic::SHL,Mnemonic::SHR,Mnemonic::SAL,Mnemonic::SAR}; insn.op_size=1; insn.mnemonic=sh[m.reg]; insn.dst=decode_modrm_mem(c,m,1); insn.src=imm8(); break; }
        case 0xC1: { auto m=modrm(); static const Mnemonic sh[]={Mnemonic::ROL,Mnemonic::ROR,Mnemonic::RCL,Mnemonic::RCR,Mnemonic::SHL,Mnemonic::SHR,Mnemonic::SAL,Mnemonic::SAR}; insn.mnemonic=sh[m.reg]; insn.dst=mem(m); insn.src=imm8(); break; }
        // ── MOVSX/MOVZX (8E/8F overlap — handled via 0F) ─────────────────────
        // ── SYSCALL (via 0F 05) — see two-byte ───────────────────────────────
        // ── CPUID (via 0F A2) — see two-byte ─────────────────────────────────
        // ── LOOP ─────────────────────────────────────────────────────────────
        case 0xE0: insn.mnemonic=Mnemonic::LOOPNE; insn.dst=rel8(); break;
        case 0xE1: insn.mnemonic=Mnemonic::LOOPE;  insn.dst=rel8(); break;
        case 0xE2: insn.mnemonic=Mnemonic::LOOP;   insn.dst=rel8(); break;
        case 0xE3: insn.mnemonic=Mnemonic::JRCXZ;  insn.dst=rel8(); break;
        // ── LEAVE ────────────────────────────────────────────────────────────
        case 0xC9: insn.mnemonic=Mnemonic::POP; insn.dst=make_reg(5,8); break; // POP RBP
        default:
            insn.mnemonic = Mnemonic::INVALID;
            break;
    }

    insn.length = (uint8_t)c.pos;
    return insn;
}

// ── Two-byte (0F xx) ─────────────────────────────────────────────────────────
DecodedInsn Decoder::decode_two_byte(Ctx& c) {
    DecodedInsn insn;
    insn.prefixes  = c.pfx;
    insn.op_size   = c.pfx.rex_w ? 8 : (c.pfx.op66 ? 2 : 4);
    insn.addr_size = c.addr_size;

    uint8_t op2 = c.read8();
    int osz = insn.op_size;
    int vsz = (c.pfx.vex && c.pfx.vex_len) ? 32 : 16;
    int gsz = c.pfx.rex_w ? 8 : 4;

    auto modrm = [&]() { return read_modrm(c); };
    auto mem   = [&](ModRM m) { return decode_modrm_mem(c, m, osz); };
    auto reg   = [&](uint8_t r) { return make_reg(r|(c.pfx.rex_r?8:0), osz); };
    auto xreg  = [&](uint8_t r) { return make_reg(r|(c.pfx.rex_r?8:0), vsz); };
    auto rel32 = [&]() { return make_rel(c.reads32(), 4); };

    // Three-byte escapes (legacy only; VEX uses vex_map 2/3)
    if (!c.pfx.vex) {
        if (op2 == 0x38) return decode_three_byte(c, 0x38);
        if (op2 == 0x3A) return decode_three_byte(c, 0x3A);
    }

    switch (op2) {
        // ── Jcc near ─────────────────────────────────────────────────────────
        case 0x80: insn.mnemonic=Mnemonic::JO;  insn.dst=rel32(); break;
        case 0x81: insn.mnemonic=Mnemonic::JNO; insn.dst=rel32(); break;
        case 0x82: insn.mnemonic=Mnemonic::JB;  insn.dst=rel32(); break;
        case 0x83: insn.mnemonic=Mnemonic::JNB; insn.dst=rel32(); break;
        case 0x84: insn.mnemonic=Mnemonic::JZ;  insn.dst=rel32(); break;
        case 0x85: insn.mnemonic=Mnemonic::JNZ; insn.dst=rel32(); break;
        case 0x86: insn.mnemonic=Mnemonic::JBE; insn.dst=rel32(); break;
        case 0x87: insn.mnemonic=Mnemonic::JA;  insn.dst=rel32(); break;
        case 0x88: insn.mnemonic=Mnemonic::JS;  insn.dst=rel32(); break;
        case 0x89: insn.mnemonic=Mnemonic::JNS; insn.dst=rel32(); break;
        case 0x8A: insn.mnemonic=Mnemonic::JP;  insn.dst=rel32(); break;
        case 0x8B: insn.mnemonic=Mnemonic::JNP; insn.dst=rel32(); break;
        case 0x8C: insn.mnemonic=Mnemonic::JL;  insn.dst=rel32(); break;
        case 0x8D: insn.mnemonic=Mnemonic::JGE; insn.dst=rel32(); break;
        case 0x8E: insn.mnemonic=Mnemonic::JLE; insn.dst=rel32(); break;
        case 0x8F: insn.mnemonic=Mnemonic::JG;  insn.dst=rel32(); break;
        // ── SETcc (0F 90..9F) ────────────────────────────────────────────────
        case 0x90: case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9A: case 0x9B:
        case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
            static const Mnemonic setcc[16] = {
                Mnemonic::SETO,  Mnemonic::SETNO, Mnemonic::SETB,  Mnemonic::SETNB,
                Mnemonic::SETZ,  Mnemonic::SETNZ, Mnemonic::SETBE, Mnemonic::SETA,
                Mnemonic::SETS,  Mnemonic::SETNS, Mnemonic::SETP,  Mnemonic::SETNP,
                Mnemonic::SETL,  Mnemonic::SETGE, Mnemonic::SETLE, Mnemonic::SETG,
            };
            auto m = modrm();
            insn.mnemonic = setcc[op2 - 0x90];
            insn.dst = decode_modrm_mem(c, m, 1);
            break;
        }
        // ── CMOVcc (0F 40..4F) ───────────────────────────────────────────────
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
            static const Mnemonic cmovcc[16] = {
                Mnemonic::CMOVO,  Mnemonic::CMOVNO, Mnemonic::CMOVB,  Mnemonic::CMOVNB,
                Mnemonic::CMOVZ,  Mnemonic::CMOVNZ, Mnemonic::CMOVBE, Mnemonic::CMOVA,
                Mnemonic::CMOVS,  Mnemonic::CMOVNS, Mnemonic::CMOVP,  Mnemonic::CMOVNP,
                Mnemonic::CMOVL,  Mnemonic::CMOVGE, Mnemonic::CMOVLE, Mnemonic::CMOVG,
            };
            auto m = modrm();
            insn.mnemonic = cmovcc[op2 - 0x40];
            insn.dst = reg(m.reg);
            insn.src = mem(m);
            break;
        }
        // ── Prefetch / Long NOP ──────────────────────────────────────────────
        case 0x18: {
            auto m = modrm();
            insn.dst = decode_modrm_mem(c, m, 1);
            switch (m.reg) {
                case 0: insn.mnemonic = Mnemonic::PREFETCHNTA; break;
                case 1: insn.mnemonic = Mnemonic::PREFETCHT0;  break;
                case 2: insn.mnemonic = Mnemonic::PREFETCHT1;  break;
                case 3: insn.mnemonic = Mnemonic::PREFETCHT2;  break;
                default: insn.mnemonic = Mnemonic::NOP;        break;
            }
            break;
        }
        case 0x19: case 0x1A: case 0x1B: case 0x1C:
        case 0x1D: case 0x1E: case 0x1F: {
            auto m = modrm();
            (void)decode_modrm_mem(c, m, osz);
            insn.mnemonic = Mnemonic::NOP;
            break;
        }
        // ── IMUL r,rm ────────────────────────────────────────────────────────
        case 0xAF: { auto m=modrm(); insn.mnemonic=Mnemonic::IMUL; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        // ── MOVSX/MOVZX ──────────────────────────────────────────────────────
        case 0xB6: { auto m=modrm(); insn.mnemonic=Mnemonic::MOVZX; insn.dst=reg(m.reg); insn.src=decode_modrm_mem(c,m,1); break; }
        case 0xB7: { auto m=modrm(); insn.mnemonic=Mnemonic::MOVZX; insn.dst=reg(m.reg); insn.src=decode_modrm_mem(c,m,2); break; }
        case 0xBE: { auto m=modrm(); insn.mnemonic=Mnemonic::MOVSX; insn.dst=reg(m.reg); insn.src=decode_modrm_mem(c,m,1); break; }
        case 0xBF: { auto m=modrm(); insn.mnemonic=Mnemonic::MOVSX; insn.dst=reg(m.reg); insn.src=decode_modrm_mem(c,m,2); break; }
        // ── Bit ops ───────────────────────────────────────────────────────────
        // Group 8: 0F BA /4 BT, /5 BTS, /6 BTR, /7 BTC r/m, imm8
        case 0xBA: {
            auto m=modrm();
            static const Mnemonic g8[4]={Mnemonic::BT,Mnemonic::BTS,Mnemonic::BTR,Mnemonic::BTC};
            if (m.reg < 4) break;
            insn.mnemonic=g8[m.reg-4]; insn.dst=mem(m); insn.src=make_imm(c.read8(),1);
            break;
        }
        case 0xA3: { auto m=modrm(); insn.mnemonic=Mnemonic::BT;  insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0xAB: { auto m=modrm(); insn.mnemonic=Mnemonic::BTS; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0xB3: { auto m=modrm(); insn.mnemonic=Mnemonic::BTR; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0xBB: { auto m=modrm(); insn.mnemonic=Mnemonic::BTC; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0xB8: {
            if (c.pfx.rep) { auto m=modrm(); insn.mnemonic=Mnemonic::POPCNT; insn.dst=reg(m.reg); insn.src=mem(m); }
            break;
        }
        case 0xBC: { auto m=modrm(); insn.mnemonic=c.pfx.rep?Mnemonic::TZCNT:Mnemonic::BSF; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        case 0xBD: { auto m=modrm(); insn.mnemonic=c.pfx.rep?Mnemonic::LZCNT:Mnemonic::BSR; insn.dst=reg(m.reg); insn.src=mem(m); break; }
        // ── XADD / CMPXCHG ───────────────────────────────────────────────────
        case 0xC0: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::XADD; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0xC1: { auto m=modrm(); insn.mnemonic=Mnemonic::XADD; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        case 0xB0: { auto m=modrm(); insn.op_size=1; insn.mnemonic=Mnemonic::CMPXCHG; insn.dst=decode_modrm_mem(c,m,1); insn.src=make_reg(m.reg|(c.pfx.rex_r?8:0),1); break; }
        case 0xB1: { auto m=modrm(); insn.mnemonic=Mnemonic::CMPXCHG; insn.dst=mem(m); insn.src=reg(m.reg); break; }
        // ── System ───────────────────────────────────────────────────────────
        case 0x05: insn.mnemonic=Mnemonic::SYSCALL;  break;
        case 0x07: insn.mnemonic=Mnemonic::SYSRET;   break;
        case 0x34: insn.mnemonic=Mnemonic::SYSENTER; break;
        case 0x35: insn.mnemonic=Mnemonic::SYSEXIT;  break;
        case 0xA2: insn.mnemonic=Mnemonic::CPUID;    break;
        case 0x31: insn.mnemonic=Mnemonic::RDTSC;    break;
        case 0x32: insn.mnemonic=Mnemonic::RDMSR;    break;
        case 0x30: insn.mnemonic=Mnemonic::WRMSR;    break;
        case 0x01: {
            uint8_t modrm_b = c.base[c.pos];
            if (modrm_b == 0xD0) { c.read8(); insn.mnemonic=Mnemonic::XGETBV; break; }
            if (modrm_b == 0xFC) { c.read8(); insn.mnemonic=Mnemonic::CLZERO; break; } // AMD: zero the 64-byte line at RAX
            if (modrm_b == 0xF8) { c.read8(); insn.mnemonic=Mnemonic::SWAPGS; break; }
            if (modrm_b == 0xF9) { c.read8(); insn.mnemonic=Mnemonic::RDTSCP; break; }
            auto m=modrm();
            switch (m.reg) {
                case 2: insn.mnemonic=Mnemonic::LGDT; insn.dst=mem(m); break;
                case 3: insn.mnemonic=Mnemonic::LIDT; insn.dst=mem(m); break;
                default: break;
            }
            break;
        }
        // ── SHLD / SHRD ──────────────────────────────────────────────────────
        case 0xA4: { auto m=modrm(); insn.mnemonic=Mnemonic::SHLD; insn.dst=mem(m); insn.src=reg(m.reg); insn.src2=make_imm(c.read8(),1); break; }
        case 0xA5: { auto m=modrm(); insn.mnemonic=Mnemonic::SHLD; insn.dst=mem(m); insn.src=reg(m.reg); insn.src2=make_reg(1,1); break; }
        case 0xAC: { auto m=modrm(); insn.mnemonic=Mnemonic::SHRD; insn.dst=mem(m); insn.src=reg(m.reg); insn.src2=make_imm(c.read8(),1); break; }
        case 0xAD: { auto m=modrm(); insn.mnemonic=Mnemonic::SHRD; insn.dst=mem(m); insn.src=reg(m.reg); insn.src2=make_reg(1,1); break; }
        // ── BSWAP r32/r64 (0F C8..CF) ────────────────────────────────────────
        case 0xC8: case 0xC9: case 0xCA: case 0xCB:
        case 0xCC: case 0xCD: case 0xCE: case 0xCF: {
            int bsz = c.pfx.rex_w ? 8 : 4;
            insn.op_size = bsz;
            insn.mnemonic = Mnemonic::BSWAP;
            insn.dst = make_reg((op2 - 0xC8) | (c.pfx.rex_b ? 8 : 0), bsz);
            break;
        }
        // ── CMPXCHG8B / CMPXCHG16B (0F C7 /1) ────────────────────────────────
        case 0xC7: {
            auto m = modrm();
            if (m.reg == 1 && m.mod != 3) {
                insn.mnemonic = c.pfx.rex_w ? Mnemonic::CMPXCHG16B : Mnemonic::CMPXCHG8B;
                insn.op_size  = c.pfx.rex_w ? 16 : 8;
                insn.dst      = decode_modrm_mem(c, m, insn.op_size);
            }
            break;
        }
        // ── SSE / AVX moves & unpacks (0F 10..17, 28, 29, 6F, 7F) ────────────
        case 0x10: case 0x11: {
            auto m = modrm();
            Mnemonic mn = c.pfx.rep ? Mnemonic::MOVSS : c.pfx.repne ? Mnemonic::MOVSD
                        : c.pfx.op66 ? Mnemonic::MOVUPD : Mnemonic::MOVUPS;
            int rmsz = c.pfx.rep ? 4 : c.pfx.repne ? 8 : vsz;
            insn.mnemonic = mn;
            Operand x = xreg(m.reg), rm = decode_modrm_mem(c, m, rmsz);
            if (op2 == 0x10) { insn.dst = x; insn.src = rm; }
            else             { insn.dst = rm; insn.src = x; }
            break;
        }
        case 0x12: {
            auto m = modrm();
            insn.dst = xreg(m.reg);
            if (c.pfx.rep) {
                insn.mnemonic = Mnemonic::MOVSLDUP;
                insn.src = decode_modrm_mem(c, m, vsz);
            } else if (c.pfx.repne) {
                insn.mnemonic = Mnemonic::MOVDDUP;
                insn.src = decode_modrm_mem(c, m, (c.pfx.vex && c.pfx.vex_len) ? 32 : 8);
            } else if (c.pfx.op66) {
                insn.mnemonic = Mnemonic::MOVLPD;
                insn.src = decode_modrm_mem(c, m, 8);
            } else {
                insn.mnemonic = (m.mod == 3) ? Mnemonic::MOVHLPS : Mnemonic::MOVLPS;
                insn.src = decode_modrm_mem(c, m, (m.mod == 3) ? 16 : 8);
            }
            break;
        }
        case 0x13: {
            auto m = modrm();
            insn.mnemonic = c.pfx.op66 ? Mnemonic::MOVLPD : Mnemonic::MOVLPS;
            insn.dst = decode_modrm_mem(c, m, 8);
            insn.src = xreg(m.reg);
            break;
        }
        case 0x14: {
            auto m = modrm();
            insn.mnemonic = c.pfx.op66 ? Mnemonic::UNPCKLPD : Mnemonic::UNPCKLPS;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, vsz);
            break;
        }
        case 0x15: {
            auto m = modrm();
            insn.mnemonic = c.pfx.op66 ? Mnemonic::UNPCKHPD : Mnemonic::UNPCKHPS;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, vsz);
            break;
        }
        case 0x16: {
            auto m = modrm();
            insn.dst = xreg(m.reg);
            if (c.pfx.rep) {
                insn.mnemonic = Mnemonic::MOVSHDUP;
                insn.src = decode_modrm_mem(c, m, vsz);
            } else if (c.pfx.op66) {
                insn.mnemonic = Mnemonic::MOVHPD;
                insn.src = decode_modrm_mem(c, m, 8);
            } else {
                insn.mnemonic = (m.mod == 3) ? Mnemonic::MOVLHPS : Mnemonic::MOVHPS;
                insn.src = decode_modrm_mem(c, m, (m.mod == 3) ? 16 : 8);
            }
            break;
        }
        case 0x17: {
            auto m = modrm();
            insn.mnemonic = c.pfx.op66 ? Mnemonic::MOVHPD : Mnemonic::MOVHPS;
            insn.dst = decode_modrm_mem(c, m, 8);
            insn.src = xreg(m.reg);
            break;
        }
        case 0x28: {
            auto m = modrm();
            insn.mnemonic = c.pfx.op66 ? Mnemonic::MOVAPD : Mnemonic::MOVAPS;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, vsz);
            break;
        }
        case 0x29:
        case 0x2B: { // MOVAPS/MOVAPD store, MOVNTPS/MOVNTPD store
            auto m = modrm();
            insn.mnemonic = c.pfx.op66 ? Mnemonic::MOVAPD : Mnemonic::MOVAPS;
            insn.dst = decode_modrm_mem(c, m, vsz);
            insn.src = xreg(m.reg);
            break;
        }
        // ── SSE / AVX conversions & scalar compares (0F 2A, 2C, 2D, 2E, 2F) ──
        case 0x2A: {
            auto m = modrm();
            insn.op_size = gsz;
            if (c.pfx.rep)        insn.mnemonic = Mnemonic::CVTSI2SS;
            else if (c.pfx.repne) insn.mnemonic = Mnemonic::CVTSI2SD;
            else                  insn.mnemonic = Mnemonic::INVALID;
            insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), 16);
            insn.src = decode_modrm_mem(c, m, gsz);
            break;
        }
        case 0x2C: {
            auto m = modrm();
            insn.op_size = gsz;
            if (c.pfx.rep)        insn.mnemonic = Mnemonic::CVTTSS2SI;
            else if (c.pfx.repne) insn.mnemonic = Mnemonic::CVTTSD2SI;
            else                  insn.mnemonic = Mnemonic::INVALID;
            insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), gsz);
            insn.src = decode_modrm_mem(c, m, c.pfx.rep ? 4 : 8);
            break;
        }
        case 0x2D: {
            auto m = modrm();
            insn.op_size = gsz;
            if (c.pfx.rep)        insn.mnemonic = Mnemonic::CVTSS2SI;
            else if (c.pfx.repne) insn.mnemonic = Mnemonic::CVTSD2SI;
            else                  insn.mnemonic = Mnemonic::INVALID;
            insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), gsz);
            insn.src = decode_modrm_mem(c, m, c.pfx.rep ? 4 : 8);
            break;
        }
        case 0x2E: {
            auto m = modrm();
            insn.mnemonic = c.pfx.op66 ? Mnemonic::UCOMISD : Mnemonic::UCOMISS;
            insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), 16);
            insn.src = decode_modrm_mem(c, m, c.pfx.op66 ? 8 : 4);
            break;
        }
        case 0x2F: {
            auto m = modrm();
            insn.mnemonic = c.pfx.op66 ? Mnemonic::COMISD : Mnemonic::COMISS;
            insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), 16);
            insn.src = decode_modrm_mem(c, m, c.pfx.op66 ? 8 : 4);
            break;
        }
        // ── SSE / AVX arithmetic, logic, sqrt, rsqrt, rcp, cvt (0F 50..5F) ───
        case 0x50: {
            auto m = modrm();
            insn.mnemonic = c.pfx.op66 ? Mnemonic::MOVMSKPD : Mnemonic::MOVMSKPS;
            insn.op_size = 4;
            insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), 4);
            insn.src = make_reg(m.rm  | (c.pfx.rex_b ? 8 : 0), vsz);
            break;
        }
        case 0x51: {
            auto m = modrm();
            insn.mnemonic = c.pfx.rep ? Mnemonic::SQRTSS : c.pfx.repne ? Mnemonic::SQRTSD
                          : c.pfx.op66 ? Mnemonic::SQRTPD : Mnemonic::SQRTPS;
            int rmsz = c.pfx.rep ? 4 : c.pfx.repne ? 8 : vsz;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, rmsz);
            break;
        }
        case 0x52: {
            auto m = modrm();
            if (c.pfx.rep)        insn.mnemonic = Mnemonic::RSQRTSS;
            else if (!c.pfx.op66 && !c.pfx.repne) insn.mnemonic = Mnemonic::RSQRTPS;
            else                  insn.mnemonic = Mnemonic::INVALID;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, c.pfx.rep ? 4 : vsz);
            break;
        }
        case 0x53: {
            auto m = modrm();
            if (c.pfx.rep)        insn.mnemonic = Mnemonic::RCPSS;
            else if (!c.pfx.op66 && !c.pfx.repne) insn.mnemonic = Mnemonic::RCPPS;
            else                  insn.mnemonic = Mnemonic::INVALID;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, c.pfx.rep ? 4 : vsz);
            break;
        }
        case 0x54: { auto m=modrm(); insn.mnemonic=c.pfx.op66?Mnemonic::ANDPD:Mnemonic::ANDPS;   insn.dst=xreg(m.reg); insn.src=decode_modrm_mem(c,m,vsz); break; }
        case 0x55: { auto m=modrm(); insn.mnemonic=c.pfx.op66?Mnemonic::ANDNPD:Mnemonic::ANDNPS; insn.dst=xreg(m.reg); insn.src=decode_modrm_mem(c,m,vsz); break; }
        case 0x56: { auto m=modrm(); insn.mnemonic=c.pfx.op66?Mnemonic::ORPD:Mnemonic::ORPS;     insn.dst=xreg(m.reg); insn.src=decode_modrm_mem(c,m,vsz); break; }
        case 0x57: { auto m=modrm(); insn.mnemonic=c.pfx.op66?Mnemonic::XORPD:Mnemonic::XORPS;   insn.dst=xreg(m.reg); insn.src=decode_modrm_mem(c,m,vsz); break; }
        case 0x58: {
            auto m = modrm();
            insn.mnemonic = c.pfx.rep ? Mnemonic::ADDSS : c.pfx.repne ? Mnemonic::ADDSD
                          : c.pfx.op66 ? Mnemonic::ADDPD : Mnemonic::ADDPS;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, c.pfx.rep ? 4 : c.pfx.repne ? 8 : vsz);
            break;
        }
        case 0x59: {
            auto m = modrm();
            insn.mnemonic = c.pfx.rep ? Mnemonic::MULSS : c.pfx.repne ? Mnemonic::MULSD
                          : c.pfx.op66 ? Mnemonic::MULPD : Mnemonic::MULPS;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, c.pfx.rep ? 4 : c.pfx.repne ? 8 : vsz);
            break;
        }
        case 0x5A: {
            auto m = modrm();
            insn.mnemonic = c.pfx.rep ? Mnemonic::CVTSS2SD : c.pfx.repne ? Mnemonic::CVTSD2SS
                          : c.pfx.op66 ? Mnemonic::CVTPD2PS : Mnemonic::CVTPS2PD;
            int rmsz = c.pfx.rep ? 4 : c.pfx.repne ? 8
                     : c.pfx.op66 ? vsz : (vsz == 32 ? 16 : 8);
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, rmsz);
            break;
        }
        case 0x5B: {
            auto m = modrm();
            insn.mnemonic = c.pfx.rep ? Mnemonic::CVTTPS2DQ : c.pfx.op66 ? Mnemonic::CVTPS2DQ
                          : !c.pfx.repne ? Mnemonic::CVTDQ2PS : Mnemonic::INVALID;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, vsz);
            break;
        }
        case 0x5C: {
            auto m = modrm();
            insn.mnemonic = c.pfx.rep ? Mnemonic::SUBSS : c.pfx.repne ? Mnemonic::SUBSD
                          : c.pfx.op66 ? Mnemonic::SUBPD : Mnemonic::SUBPS;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, c.pfx.rep ? 4 : c.pfx.repne ? 8 : vsz);
            break;
        }
        case 0x5D: {
            auto m = modrm();
            insn.mnemonic = c.pfx.rep ? Mnemonic::MINSS : c.pfx.repne ? Mnemonic::MINSD
                          : c.pfx.op66 ? Mnemonic::MINPD : Mnemonic::MINPS;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, c.pfx.rep ? 4 : c.pfx.repne ? 8 : vsz);
            break;
        }
        case 0x5E: {
            auto m = modrm();
            insn.mnemonic = c.pfx.rep ? Mnemonic::DIVSS : c.pfx.repne ? Mnemonic::DIVSD
                          : c.pfx.op66 ? Mnemonic::DIVPD : Mnemonic::DIVPS;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, c.pfx.rep ? 4 : c.pfx.repne ? 8 : vsz);
            break;
        }
        case 0x5F: {
            auto m = modrm();
            insn.mnemonic = c.pfx.rep ? Mnemonic::MAXSS : c.pfx.repne ? Mnemonic::MAXSD
                          : c.pfx.op66 ? Mnemonic::MAXPD : Mnemonic::MAXPS;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, c.pfx.rep ? 4 : c.pfx.repne ? 8 : vsz);
            break;
        }
        // ── CMPcc / SHUF (0F C2, 0F C6) ──────────────────────────────────────
        case 0xC2: {
            auto m = modrm();
            insn.mnemonic = c.pfx.rep ? Mnemonic::CMPSS : c.pfx.repne ? Mnemonic::CMPSD
                          : c.pfx.op66 ? Mnemonic::CMPPD : Mnemonic::CMPPS;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, c.pfx.rep ? 4 : c.pfx.repne ? 8 : vsz);
            insn.src2 = make_imm(c.read8(), 1);
            break;
        }
        case 0xC4: {
            if (c.pfx.op66) {
                auto m = modrm();
                insn.mnemonic = Mnemonic::PINSRW;
                insn.dst  = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), 16);
                insn.src  = decode_modrm_mem(c, m, 2);
                insn.src2 = make_imm(c.read8(), 1);
            }
            break;
        }
        case 0xC5: {
            if (c.pfx.op66) {
                auto m = modrm();
                insn.mnemonic = Mnemonic::PEXTRW;
                insn.op_size = 4;
                insn.dst  = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), 4);
                insn.src  = make_reg(m.rm  | (c.pfx.rex_b ? 8 : 0), 16);
                insn.src2 = make_imm(c.read8(), 1);
            }
            break;
        }
        case 0xC6: {
            auto m = modrm();
            insn.mnemonic = c.pfx.op66 ? Mnemonic::SHUFPD : Mnemonic::SHUFPS;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, vsz);
            insn.src2 = make_imm(c.read8(), 1);
            break;
        }
        // ── SSE2 / AVX2 integer / moves ──────────────────────────────────────
        case 0x6F: {
            auto m = modrm();
            insn.mnemonic = c.pfx.rep ? Mnemonic::MOVDQU : c.pfx.op66 ? Mnemonic::MOVDQA : Mnemonic::MOVQ;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, vsz);
            break;
        }
        case 0x7F:
        case 0xE7: { // MOVDQA/MOVDQU/MOVQ store, MOVNTDQ store (66 0F E7)
            auto m = modrm();
            if (op2 == 0xE7 && !c.pfx.op66) break;
            insn.mnemonic = c.pfx.rep ? Mnemonic::MOVDQU : c.pfx.op66 ? Mnemonic::MOVDQA : Mnemonic::MOVQ;
            insn.dst = decode_modrm_mem(c, m, vsz);
            insn.src = xreg(m.reg);
            break;
        }
        case 0x6E: case 0x7E: {
            auto m = modrm();
            Operand x = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), 16);
            if (op2 == 0x7E && c.pfx.rep) { // F3 0F 7E: movq xmm, xmm/m64
                insn.mnemonic = Mnemonic::MOVQ;
                insn.dst = x;
                insn.src = decode_modrm_mem(c, m, 8);
                break;
            }
            insn.op_size = gsz;
            insn.mnemonic = Mnemonic::MOVD;
            Operand rm = decode_modrm_mem(c, m, gsz);
            if (op2 == 0x6E) { insn.dst = x; insn.src = rm; }
            else             { insn.dst = rm; insn.src = x; }
            break;
        }
        case 0xD6: {
            auto m = modrm();
            insn.mnemonic = Mnemonic::MOVQ;
            insn.dst = decode_modrm_mem(c, m, 8);
            insn.src = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), 16);
            break;
        }
        case 0x70: {
            auto m = modrm();
            insn.mnemonic = c.pfx.repne ? Mnemonic::PSHUFLW : c.pfx.rep ? Mnemonic::PSHUFHW
                          : c.pfx.op66 ? Mnemonic::PSHUFD : Mnemonic::INVALID;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, vsz);
            insn.src2 = make_imm(c.read8(), 1);
            break;
        }
        case 0x71: case 0x72: case 0x73: {
            auto m = modrm();
            if (c.pfx.op66 && m.mod == 3) {
                uint8_t rm_r = m.rm | (c.pfx.rex_b ? 8 : 0);
                insn.dst  = c.pfx.vex ? make_reg(c.pfx.vex_vvvv, vsz) : make_reg(rm_r, vsz);
                insn.src  = make_reg(rm_r, vsz);
                insn.src2 = make_imm(c.read8(), 1);
                if (op2 == 0x71) {
                    if      (m.reg == 2) insn.mnemonic = Mnemonic::PSRLW;
                    else if (m.reg == 4) insn.mnemonic = Mnemonic::PSRAW;
                    else if (m.reg == 6) insn.mnemonic = Mnemonic::PSLLW;
                } else if (op2 == 0x72) {
                    if      (m.reg == 2) insn.mnemonic = Mnemonic::PSRLD;
                    else if (m.reg == 4) insn.mnemonic = Mnemonic::PSRAD;
                    else if (m.reg == 6) insn.mnemonic = Mnemonic::PSLLD;
                } else {
                    if      (m.reg == 2) insn.mnemonic = Mnemonic::PSRLQ;
                    else if (m.reg == 3) insn.mnemonic = Mnemonic::PSRLDQ;
                    else if (m.reg == 6) insn.mnemonic = Mnemonic::PSLLQ;
                    else if (m.reg == 7) insn.mnemonic = Mnemonic::PSLLDQ;
                }
            }
            break;
        }
        case 0x7C: {
            auto m = modrm();
            insn.mnemonic = c.pfx.repne ? Mnemonic::HADDPS : c.pfx.op66 ? Mnemonic::HADDPD : Mnemonic::INVALID;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, vsz);
            break;
        }
        case 0x7D: {
            auto m = modrm();
            insn.mnemonic = c.pfx.repne ? Mnemonic::HSUBPS : c.pfx.op66 ? Mnemonic::HSUBPD : Mnemonic::INVALID;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, vsz);
            break;
        }
        case 0xD0: {
            auto m = modrm();
            insn.mnemonic = c.pfx.repne ? Mnemonic::ADDSUBPS : c.pfx.op66 ? Mnemonic::ADDSUBPD : Mnemonic::INVALID;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, vsz);
            break;
        }
        case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: case 0x67:
        case 0x68: case 0x69: case 0x6A: case 0x6B: case 0x6C: case 0x6D:
        case 0x74: case 0x75: case 0x76:
        case 0xD1: case 0xD2: case 0xD3: case 0xD4: case 0xD5:
        case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5:
        case 0xE8: case 0xE9: case 0xEA: case 0xEB: case 0xEC: case 0xED: case 0xEE: case 0xEF:
        case 0xF1: case 0xF2: case 0xF3: case 0xF4: case 0xF5: case 0xF6:
        case 0xF8: case 0xF9: case 0xFA: case 0xFB: case 0xFC: case 0xFD: case 0xFE: {
            auto m = modrm();
            switch (op2) {
                case 0x60: insn.mnemonic=Mnemonic::PUNPCKLBW; break;
                case 0x61: insn.mnemonic=Mnemonic::PUNPCKLWD; break;
                case 0x62: insn.mnemonic=Mnemonic::PUNPCKLDQ; break;
                case 0x63: insn.mnemonic=Mnemonic::PACKSSWB; break;
                case 0x64: insn.mnemonic=Mnemonic::PCMPGTB; break;
                case 0x65: insn.mnemonic=Mnemonic::PCMPGTW; break;
                case 0x66: insn.mnemonic=Mnemonic::PCMPGTD; break;
                case 0x67: insn.mnemonic=Mnemonic::PACKUSWB; break;
                case 0x68: insn.mnemonic=Mnemonic::PUNPCKHBW; break;
                case 0x69: insn.mnemonic=Mnemonic::PUNPCKHWD; break;
                case 0x6A: insn.mnemonic=Mnemonic::PUNPCKHDQ; break;
                case 0x6B: insn.mnemonic=Mnemonic::PACKSSDW; break;
                case 0x6C: insn.mnemonic=Mnemonic::PUNPCKLQDQ; break;
                case 0x6D: insn.mnemonic=Mnemonic::PUNPCKHQDQ; break;
                case 0x74: insn.mnemonic=Mnemonic::PCMPEQB; break;
                case 0x75: insn.mnemonic=Mnemonic::PCMPEQW; break;
                case 0x76: insn.mnemonic=Mnemonic::PCMPEQD; break;
                case 0xD1: insn.mnemonic=Mnemonic::PSRLW_R; break;
                case 0xD2: insn.mnemonic=Mnemonic::PSRLD_R; break;
                case 0xD3: insn.mnemonic=Mnemonic::PSRLQ_R; break;
                case 0xD4: insn.mnemonic=Mnemonic::PADDQ; break;
                case 0xD5: insn.mnemonic=Mnemonic::PMULLW; break;
                case 0xD8: insn.mnemonic=Mnemonic::PSUBUSB; break;
                case 0xD9: insn.mnemonic=Mnemonic::PSUBUSW; break;
                case 0xDA: insn.mnemonic=Mnemonic::PMINUB; break;
                case 0xDB: insn.mnemonic=Mnemonic::PAND; break;
                case 0xDC: insn.mnemonic=Mnemonic::PADDUSB; break;
                case 0xDD: insn.mnemonic=Mnemonic::PADDUSW; break;
                case 0xDE: insn.mnemonic=Mnemonic::PMAXUB; break;
                case 0xDF: insn.mnemonic=Mnemonic::PANDN; break;
                case 0xE0: insn.mnemonic=Mnemonic::PAVGB; break;
                case 0xE1: insn.mnemonic=Mnemonic::PSRAW_R; break;
                case 0xE2: insn.mnemonic=Mnemonic::PSRAD_R; break;
                case 0xE3: insn.mnemonic=Mnemonic::PAVGW; break;
                case 0xE4: insn.mnemonic=Mnemonic::PMULHUW; break;
                case 0xE5: insn.mnemonic=Mnemonic::PMULHW; break;
                case 0xE8: insn.mnemonic=Mnemonic::PSUBSB; break;
                case 0xE9: insn.mnemonic=Mnemonic::PSUBSW; break;
                case 0xEA: insn.mnemonic=Mnemonic::PMINSW; break;
                case 0xEB: insn.mnemonic=Mnemonic::POR; break;
                case 0xEC: insn.mnemonic=Mnemonic::PADDSB; break;
                case 0xED: insn.mnemonic=Mnemonic::PADDSW; break;
                case 0xEE: insn.mnemonic=Mnemonic::PMAXSW; break;
                case 0xEF: insn.mnemonic=Mnemonic::PXOR; break;
                case 0xF1: insn.mnemonic=Mnemonic::PSLLW_R; break;
                case 0xF2: insn.mnemonic=Mnemonic::PSLLD_R; break;
                case 0xF3: insn.mnemonic=Mnemonic::PSLLQ_R; break;
                case 0xF4: insn.mnemonic=Mnemonic::PMULUDQ; break;
                case 0xF5: insn.mnemonic=Mnemonic::PMADDWD; break;
                case 0xF6: insn.mnemonic=Mnemonic::PSADBW; break;
                case 0xF8: insn.mnemonic=Mnemonic::PSUBB; break;
                case 0xF9: insn.mnemonic=Mnemonic::PSUBW; break;
                case 0xFA: insn.mnemonic=Mnemonic::PSUBD; break;
                case 0xFB: insn.mnemonic=Mnemonic::PSUBQ; break;
                case 0xFC: insn.mnemonic=Mnemonic::PADDB; break;
                case 0xFD: insn.mnemonic=Mnemonic::PADDW; break;
                case 0xFE: insn.mnemonic=Mnemonic::PADDD; break;
            }
            if (!c.pfx.op66) insn.mnemonic = Mnemonic::INVALID; // MMX forms unsupported
            bool shift_r = (op2==0xD1||op2==0xD2||op2==0xD3||op2==0xE1||op2==0xE2||op2==0xF1||op2==0xF2||op2==0xF3);
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, shift_r ? 16 : vsz);
            break;
        }
        case 0xE6: {
            auto m = modrm();
            insn.mnemonic = c.pfx.rep ? Mnemonic::CVTDQ2PD : c.pfx.repne ? Mnemonic::CVTPD2DQ
                          : c.pfx.op66 ? Mnemonic::CVTTPD2DQ : Mnemonic::INVALID;
            int rmsz = c.pfx.rep ? (vsz == 32 ? 16 : 8) : vsz;
            insn.dst = xreg(m.reg);
            insn.src = decode_modrm_mem(c, m, rmsz);
            break;
        }
        case 0xD7: {
            auto m = modrm();
            insn.mnemonic = Mnemonic::PMOVMSKB;
            insn.op_size = 4;
            insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), 4);
            insn.src = make_reg(m.rm  | (c.pfx.rex_b ? 8 : 0), vsz);
            break;
        }
        // ── Fences ───────────────────────────────────────────────────────────
        case 0xAE: {
            uint8_t mb = c.base[c.pos];
            if (mb == 0xE8) { c.read8(); insn.mnemonic=Mnemonic::LFENCE; break; }
            if (mb == 0xF0) { c.read8(); insn.mnemonic=Mnemonic::MFENCE; break; }
            if (mb == 0xF8) { c.read8(); insn.mnemonic=Mnemonic::SFENCE; break; }
            auto m=modrm();
            // 0F AE /3 = (v)stmxcsr m32, /2 = (v)ldmxcsr m32 (legacy and VEX share this path)
            if (m.mod != 3 && m.reg == 3) { insn.mnemonic=Mnemonic::STMXCSR; insn.dst=decode_modrm_mem(c, m, 4); insn.op_size=4; }
            else if (m.mod != 3 && m.reg == 2) { insn.mnemonic=Mnemonic::LDMXCSR; insn.src=decode_modrm_mem(c, m, 4); insn.op_size=4; }
            // 0F AE /7 = clflush (66: clflushopt), 66 0F AE /6 = clwb: cache hints, executed as no-ops
            else if (m.mod != 3 && (m.reg == 7 || (m.reg == 6 && c.pfx.op66))) {
                insn.mnemonic = (m.reg == 7 && !c.pfx.op66) ? Mnemonic::CLFLUSH : Mnemonic::CLFLUSHOPT;
                insn.src = decode_modrm_mem(c, m, 1); insn.op_size = 1;
            }
            break;
        }
        case 0x0B: insn.mnemonic=Mnemonic::UD2; break;
        default:
            insn.mnemonic=Mnemonic::INVALID;
            break;
    }

    insn.length = (uint8_t)c.pos;
    return insn;
}

DecodedInsn Decoder::decode_three_byte(Ctx& c, uint8_t map) {
    DecodedInsn insn;
    insn.prefixes  = c.pfx;
    insn.addr_size = c.addr_size;
    uint8_t op = c.read8();
    insn.op_size = c.pfx.rex_w ? 8 : (c.pfx.op66 ? 2 : 4);
    int vsz = (c.pfx.vex && c.pfx.vex_len) ? 32 : 16;
    int gsz = c.pfx.rex_w ? 8 : 4;

    if (map == 0x38) {
        auto m = read_modrm(c);
        switch (op) {
            case 0x00:
                if (c.pfx.op66) {
                    insn.mnemonic = Mnemonic::PSHUFB;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, vsz);
                }
                break;
            case 0x01: case 0x02: case 0x05: case 0x06:
            case 0x08: case 0x09: case 0x0A:
                if (c.pfx.op66) {
                    switch (op) {
                        case 0x01: insn.mnemonic = Mnemonic::PHADDW; break;
                        case 0x02: insn.mnemonic = Mnemonic::PHADDD; break;
                        case 0x05: insn.mnemonic = Mnemonic::PHSUBW; break;
                        case 0x06: insn.mnemonic = Mnemonic::PHSUBD; break;
                        case 0x08: insn.mnemonic = Mnemonic::PSIGNB; break;
                        case 0x09: insn.mnemonic = Mnemonic::PSIGNW; break;
                        case 0x0A: insn.mnemonic = Mnemonic::PSIGND; break;
                    }
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, vsz);
                }
                break;
            case 0x0E: case 0x0F: // VTESTPS / VTESTPD
                if (c.pfx.vex && c.pfx.op66) {
                    insn.mnemonic = (op == 0x0E) ? Mnemonic::VTESTPS : Mnemonic::VTESTPD;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, vsz);
                }
                break;
            case 0x13: // VCVTPH2PS (VEX.66.0F38.W0)
                if (c.pfx.vex && c.pfx.op66 && !c.pfx.vex_w) {
                    insn.mnemonic = Mnemonic::VCVTPH2PS;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, c.pfx.vex_len ? 16 : 8);
                }
                break;
            case 0x16: case 0x36: // VPERMPS / VPERMD (VEX.256.66.W0)
                if (c.pfx.vex && c.pfx.op66 && c.pfx.vex_len && !c.pfx.vex_w) {
                    insn.mnemonic = Mnemonic::VPERMD;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), 32);
                    insn.src = decode_modrm_mem(c, m, 32);
                }
                break;
            case 0x45: case 0x46: case 0x47: // VPSRLVD/Q, VPSRAVD, VPSLLVD/Q
                if (c.pfx.vex && c.pfx.op66) {
                    insn.mnemonic = (op == 0x45) ? Mnemonic::VPSRLV : (op == 0x46) ? Mnemonic::VPSRAV : Mnemonic::VPSLLV;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, vsz);
                }
                break;
            case 0x17:
                if (c.pfx.op66) {
                    insn.mnemonic = Mnemonic::PTEST;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, vsz);
                }
                break;
            case 0x18: case 0x58: // VBROADCASTSS / VPBROADCASTD
                if (c.pfx.vex && c.pfx.op66) {
                    insn.mnemonic = Mnemonic::VBROADCASTSS;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, 4);
                }
                break;
            case 0x19: case 0x59: // VBROADCASTSD / VPBROADCASTQ
                if (c.pfx.vex && c.pfx.op66) {
                    insn.mnemonic = Mnemonic::VBROADCASTSD;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, 8);
                }
                break;
            case 0x1A: case 0x5A: // VBROADCASTF128 / VBROADCASTI128
                if (c.pfx.vex && c.pfx.op66) {
                    insn.mnemonic = Mnemonic::VBROADCASTF128;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), 32);
                    insn.src = decode_modrm_mem(c, m, 16);
                }
                break;
            case 0x1C: case 0x1D: case 0x1E: // PABSB / PABSW / PABSD
                if (c.pfx.op66) {
                    static const Mnemonic amn[3] = {Mnemonic::PABSB, Mnemonic::PABSW, Mnemonic::PABSD};
                    insn.mnemonic = amn[op - 0x1C];
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, vsz);
                }
                break;
            case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25:
            case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35:
                if (c.pfx.op66) {
                    static const Mnemonic sx[6] = {Mnemonic::PMOVSXBW, Mnemonic::PMOVSXBD, Mnemonic::PMOVSXBQ, Mnemonic::PMOVSXWD, Mnemonic::PMOVSXWQ, Mnemonic::PMOVSXDQ};
                    static const Mnemonic zx[6] = {Mnemonic::PMOVZXBW, Mnemonic::PMOVZXBD, Mnemonic::PMOVZXBQ, Mnemonic::PMOVZXWD, Mnemonic::PMOVZXWQ, Mnemonic::PMOVZXDQ};
                    static const int msz128[6]  = {8, 4, 2, 8, 4, 8};
                    int idx = op & 0x0F;
                    insn.mnemonic = (op < 0x30) ? sx[idx] : zx[idx];
                    int rmsz = (vsz == 32) ? (msz128[idx] * 2) : msz128[idx];
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, rmsz);
                }
                break;
            case 0x2A: // MOVNTDQA / VMOVNTDQA
                if (c.pfx.op66) {
                    insn.mnemonic = Mnemonic::MOVDQA;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, vsz);
                }
                break;
            case 0x2C: case 0x2D: case 0x8C: // VMASKMOVPS/PD / VPMASKMOVD/Q load
                if (c.pfx.vex && c.pfx.op66) {
                    bool is_q = (op == 0x2D) || (op == 0x8C && c.pfx.vex_w);
                    insn.mnemonic = is_q ? Mnemonic::VMASKMOVQ : Mnemonic::VMASKMOVD;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, vsz);
                }
                break;
            case 0x2E: case 0x2F: case 0x8E: // VMASKMOVPS/PD / VPMASKMOVD/Q store
                if (c.pfx.vex && c.pfx.op66) {
                    bool is_q = (op == 0x2F) || (op == 0x8E && c.pfx.vex_w);
                    insn.mnemonic = is_q ? Mnemonic::VMASKMOVQ : Mnemonic::VMASKMOVD;
                    insn.dst = decode_modrm_mem(c, m, vsz);
                    insn.src = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                }
                break;
            case 0x29: case 0x2B: case 0x37:
            case 0x38: case 0x39: case 0x3A: case 0x3B:
            case 0x3C: case 0x3D: case 0x3E: case 0x3F:
            case 0x40:
                if (c.pfx.op66) {
                    switch (op) {
                        case 0x29: insn.mnemonic = Mnemonic::PCMPEQQ; break;
                        case 0x2B: insn.mnemonic = Mnemonic::PACKUSDW; break;
                        case 0x37: insn.mnemonic = Mnemonic::PCMPGTQ; break;
                        case 0x38: insn.mnemonic = Mnemonic::PMINSB; break;
                        case 0x39: insn.mnemonic = Mnemonic::PMINSD; break;
                        case 0x3A: insn.mnemonic = Mnemonic::PMINUW; break;
                        case 0x3B: insn.mnemonic = Mnemonic::PMINUD; break;
                        case 0x3C: insn.mnemonic = Mnemonic::PMAXSB; break;
                        case 0x3D: insn.mnemonic = Mnemonic::PMAXSD; break;
                        case 0x3E: insn.mnemonic = Mnemonic::PMAXUW; break;
                        case 0x3F: insn.mnemonic = Mnemonic::PMAXUD; break;
                        case 0x40: insn.mnemonic = Mnemonic::PMULLD; break;
                    }
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, vsz);
                }
                break;
            case 0x78: // VPBROADCASTB
                if (c.pfx.vex && c.pfx.op66) {
                    insn.mnemonic = Mnemonic::VPBROADCASTB;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, 1);
                }
                break;
            case 0x79: // VPBROADCASTW
                if (c.pfx.vex && c.pfx.op66) {
                    insn.mnemonic = Mnemonic::VPBROADCASTW;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), vsz);
                    insn.src = decode_modrm_mem(c, m, 2);
                }
                break;
            // ── FMA3 (VEX.66.0F38 0x96..0xBF) ────────────────────────────────
            case 0x96: case 0x97: case 0x98: case 0x99: case 0x9A: case 0x9B:
            case 0x9C: case 0x9D: case 0x9E: case 0x9F:
            case 0xA6: case 0xA7: case 0xA8: case 0xA9: case 0xAA: case 0xAB:
            case 0xAC: case 0xAD: case 0xAE: case 0xAF:
            case 0xB6: case 0xB7: case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                if (c.pfx.vex && c.pfx.op66) {
                    bool scalar = ((op & 0x0F) >= 8) && ((op & 1) != 0);
                    int rmsz = scalar ? (c.pfx.vex_w ? 8 : 4) : vsz;
                    insn.mnemonic = Mnemonic::FMA3;
                    insn.dst  = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), scalar ? 16 : vsz);
                    insn.src  = decode_modrm_mem(c, m, rmsz);
                    insn.src2 = make_imm(op, 1);
                }
                break;
            case 0xF0:
                insn.mnemonic = Mnemonic::MOVBE;
                insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), insn.op_size);
                insn.src = decode_modrm_mem(c, m, insn.op_size);
                break;
            case 0xF1:
                insn.mnemonic = Mnemonic::MOVBE;
                insn.dst = decode_modrm_mem(c, m, insn.op_size);
                insn.src = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), insn.op_size);
                break;
            case 0xF2:
                if (c.pfx.vex && c.pfx.vex_pp == 0) {
                    insn.op_size = gsz;
                    insn.mnemonic = Mnemonic::ANDN;
                    insn.dst  = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), gsz);
                    insn.src  = make_reg(c.pfx.vex_vvvv, gsz);
                    insn.src2 = decode_modrm_mem(c, m, gsz);
                }
                break;
            case 0xF3:
                if (c.pfx.vex && c.pfx.vex_pp == 0) {
                    insn.op_size = gsz;
                    insn.dst = make_reg(c.pfx.vex_vvvv, gsz);
                    insn.src = decode_modrm_mem(c, m, gsz);
                    if      (m.reg == 1) insn.mnemonic = Mnemonic::BLSR;
                    else if (m.reg == 2) insn.mnemonic = Mnemonic::BLSMSK;
                    else if (m.reg == 3) insn.mnemonic = Mnemonic::BLSI;
                }
                break;
            case 0xF5:
                if (c.pfx.vex) {
                    insn.op_size = gsz;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), gsz);
                    if (c.pfx.vex_pp == 0) {
                        insn.mnemonic = Mnemonic::BZHI;
                        insn.src  = decode_modrm_mem(c, m, gsz);
                        insn.src2 = make_reg(c.pfx.vex_vvvv, gsz);
                    } else if (c.pfx.vex_pp == 2) {
                        insn.mnemonic = Mnemonic::PEXT;
                        insn.src  = make_reg(c.pfx.vex_vvvv, gsz);
                        insn.src2 = decode_modrm_mem(c, m, gsz);
                    } else if (c.pfx.vex_pp == 3) {
                        insn.mnemonic = Mnemonic::PDEP;
                        insn.src  = make_reg(c.pfx.vex_vvvv, gsz);
                        insn.src2 = decode_modrm_mem(c, m, gsz);
                    }
                }
                break;
            case 0xF6:
                if (c.pfx.vex && c.pfx.vex_pp == 3) {
                    insn.op_size = gsz;
                    insn.mnemonic = Mnemonic::MULX;
                    insn.dst  = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), gsz);
                    insn.src  = make_reg(c.pfx.vex_vvvv, gsz);
                    insn.src2 = decode_modrm_mem(c, m, gsz);
                } else if (!c.pfx.vex && (c.pfx.op66 || c.pfx.rep)) {
                    // ADCX (66) / ADOX (F3): r, r/m ; carry via CF / OF only
                    insn.op_size = gsz;
                    insn.mnemonic = c.pfx.rep ? Mnemonic::ADOX : Mnemonic::ADCX;
                    insn.dst = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), gsz);
                    insn.src = decode_modrm_mem(c, m, gsz);
                }
                break;
            case 0xF7:
                if (c.pfx.vex) {
                    insn.op_size = gsz;
                    insn.dst  = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), gsz);
                    insn.src  = decode_modrm_mem(c, m, gsz);
                    insn.src2 = make_reg(c.pfx.vex_vvvv, gsz);
                    if      (c.pfx.vex_pp == 0) insn.mnemonic = Mnemonic::BEXTR;
                    else if (c.pfx.vex_pp == 1) insn.mnemonic = Mnemonic::SHLX;
                    else if (c.pfx.vex_pp == 2) insn.mnemonic = Mnemonic::SARX;
                    else if (c.pfx.vex_pp == 3) insn.mnemonic = Mnemonic::SHRX;
                }
                break;
            default:
                insn.mnemonic = Mnemonic::INVALID;
                break;
        }
    } else { // 0x3A
        if (c.pfx.vex && op == 0xF0 && c.pfx.vex_pp == 3) {
            auto m = read_modrm(c);
            insn.op_size = gsz;
            insn.mnemonic = Mnemonic::RORX;
            insn.dst  = make_reg(m.reg | (c.pfx.rex_r ? 8 : 0), gsz);
            insn.src  = decode_modrm_mem(c, m, gsz);
            insn.src2 = make_imm(c.read8(), 1);
        } else if (c.pfx.op66) {
            auto m = read_modrm(c);
            uint8_t xidx = m.reg | (c.pfx.rex_r ? 8 : 0);
            switch (op) {
                case 0x00: case 0x01: // VPERMQ / VPERMPD (VEX.256.66.W1)
                    if (c.pfx.vex && c.pfx.vex_len && c.pfx.vex_w) {
                        insn.mnemonic = Mnemonic::VPERMQ;
                        insn.dst  = make_reg(xidx, 32);
                        insn.src  = decode_modrm_mem(c, m, 32);
                        insn.src2 = make_imm(c.read8(), 1);
                    }
                    break;
                case 0x04: // VPERMILPS
                    if (c.pfx.vex) {
                        insn.mnemonic = Mnemonic::VPERMILPS;
                        insn.dst  = make_reg(xidx, vsz);
                        insn.src  = decode_modrm_mem(c, m, vsz);
                        insn.src2 = make_imm(c.read8(), 1);
                    }
                    break;
                case 0x05: // VPERMILPD
                    if (c.pfx.vex) {
                        insn.mnemonic = Mnemonic::VPERMILPD;
                        insn.dst  = make_reg(xidx, vsz);
                        insn.src  = decode_modrm_mem(c, m, vsz);
                        insn.src2 = make_imm(c.read8(), 1);
                    }
                    break;
                case 0x06: case 0x46: // VPERM2F128 / VPERM2I128
                    if (c.pfx.vex && c.pfx.vex_len) {
                        insn.mnemonic = Mnemonic::VPERM2F128;
                        insn.dst  = make_reg(xidx, 32);
                        insn.src  = decode_modrm_mem(c, m, 32);
                        insn.src2 = make_imm(c.read8(), 1);
                    }
                    break;
                case 0x08: case 0x09: case 0x0A: case 0x0B: {
                    static const Mnemonic rmn[4] = {Mnemonic::ROUNDPS, Mnemonic::ROUNDPD, Mnemonic::ROUNDSS, Mnemonic::ROUNDSD};
                    insn.mnemonic = rmn[op - 0x08];
                    int rmsz = (op == 0x0A) ? 4 : (op == 0x0B) ? 8 : vsz;
                    insn.dst  = make_reg(xidx, vsz);
                    insn.src  = decode_modrm_mem(c, m, rmsz);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                }
                case 0x02: // VPBLENDD (VEX only): same dword-mask semantics as BLENDPS
                    if (!c.pfx.vex) return insn;
                    insn.mnemonic = Mnemonic::BLENDPS;
                    insn.dst  = make_reg(xidx, vsz);
                    insn.src  = decode_modrm_mem(c, m, vsz);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                case 0x0C: case 0x0D: case 0x0E: {
                    static const Mnemonic bmn[3] = {Mnemonic::BLENDPS, Mnemonic::BLENDPD, Mnemonic::PBLENDW};
                    insn.mnemonic = bmn[op - 0x0C];
                    insn.dst  = make_reg(xidx, vsz);
                    insn.src  = decode_modrm_mem(c, m, vsz);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                }
                case 0x0F: // PALIGNR
                    insn.mnemonic = Mnemonic::PALIGNR;
                    insn.dst  = make_reg(xidx, vsz);
                    insn.src  = decode_modrm_mem(c, m, vsz);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                case 0x14: // PEXTRB r/m8, xmm, imm8
                    insn.mnemonic = Mnemonic::PEXTRB;
                    insn.op_size  = (m.mod == 3) ? 4 : 1;
                    insn.dst  = decode_modrm_mem(c, m, (m.mod == 3) ? 4 : 1);
                    insn.src  = make_reg(xidx, 16);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                case 0x15: // PEXTRW r/m16, xmm, imm8
                    insn.mnemonic = Mnemonic::PEXTRW;
                    insn.op_size  = (m.mod == 3) ? 4 : 2;
                    insn.dst  = decode_modrm_mem(c, m, (m.mod == 3) ? 4 : 2);
                    insn.src  = make_reg(xidx, 16);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                case 0x16: // PEXTRD (W=0) / PEXTRQ (W=1) r/m32|64, xmm, imm8
                    insn.mnemonic = c.pfx.rex_w ? Mnemonic::PEXTRQ : Mnemonic::PEXTRD;
                    insn.op_size  = gsz;
                    insn.dst  = decode_modrm_mem(c, m, gsz);
                    insn.src  = make_reg(xidx, 16);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                case 0x17: // EXTRACTPS r/m32, xmm, imm8
                    insn.mnemonic = Mnemonic::PEXTRD;
                    insn.op_size  = 4;
                    insn.dst  = decode_modrm_mem(c, m, 4);
                    insn.src  = make_reg(xidx, 16);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                case 0x18: case 0x38: // VINSERTF128 / VINSERTI128
                    if (c.pfx.vex && c.pfx.vex_len) {
                        insn.mnemonic = Mnemonic::VINSERTF128;
                        insn.dst  = make_reg(xidx, 32);
                        insn.src  = decode_modrm_mem(c, m, 16);
                        insn.src2 = make_imm(c.read8(), 1);
                    }
                    break;
                case 0x19: case 0x39: // VEXTRACTF128 / VEXTRACTI128
                    if (c.pfx.vex && c.pfx.vex_len) {
                        insn.mnemonic = Mnemonic::VEXTRACTF128;
                        insn.dst  = decode_modrm_mem(c, m, 16);
                        insn.src  = make_reg(xidx, 32);
                        insn.src2 = make_imm(c.read8(), 1);
                    }
                    break;
                case 0x1D: // VCVTPS2PH (VEX.66.0F3A.W0)
                    if (c.pfx.vex && !c.pfx.vex_w) {
                        insn.mnemonic = Mnemonic::VCVTPS2PH;
                        insn.dst  = decode_modrm_mem(c, m, c.pfx.vex_len ? 16 : 8);
                        insn.src  = make_reg(xidx, vsz);
                        insn.src2 = make_imm(c.read8(), 1);
                    }
                    break;
                case 0x20: // PINSRB
                    insn.mnemonic = Mnemonic::PINSRB;
                    insn.dst  = make_reg(xidx, 16);
                    insn.src  = decode_modrm_mem(c, m, 1);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                case 0x21: // INSERTPS
                    insn.mnemonic = Mnemonic::INSERTPS;
                    insn.dst  = make_reg(xidx, 16);
                    insn.src  = decode_modrm_mem(c, m, 4);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                case 0x22: // PINSRD (W=0) / PINSRQ (W=1)
                    insn.mnemonic = c.pfx.rex_w ? Mnemonic::PINSRQ : Mnemonic::PINSRD;
                    insn.op_size  = gsz;
                    insn.dst  = make_reg(xidx, 16);
                    insn.src  = decode_modrm_mem(c, m, gsz);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                case 0x40: // DPPS
                    insn.mnemonic = Mnemonic::DPPS;
                    insn.dst  = make_reg(xidx, vsz);
                    insn.src  = decode_modrm_mem(c, m, vsz);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                case 0x41: // DPPD
                    insn.mnemonic = Mnemonic::DPPD;
                    insn.dst  = make_reg(xidx, 16);
                    insn.src  = decode_modrm_mem(c, m, 16);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                case 0x4A: case 0x4B: case 0x4C:
                    if (c.pfx.vex) {
                        static const Mnemonic vbmn[3] = {Mnemonic::VBLENDVPS, Mnemonic::VBLENDVPD, Mnemonic::VPBLENDVB};
                        insn.mnemonic = vbmn[op - 0x4A];
                        insn.dst  = make_reg(xidx, vsz);
                        insn.src  = decode_modrm_mem(c, m, vsz);
                        insn.src2 = make_imm(c.read8(), 1);
                    }
                    break;
                case 0x60: case 0x61: case 0x62: case 0x63: {
                    static const Mnemonic smn[4] = {Mnemonic::PCMPESTRM, Mnemonic::PCMPESTRI, Mnemonic::PCMPISTRM, Mnemonic::PCMPISTRI};
                    insn.mnemonic = smn[op - 0x60];
                    insn.dst  = make_reg(xidx, 16);
                    insn.src  = decode_modrm_mem(c, m, 16);
                    insn.src2 = make_imm(c.read8(), 1);
                    break;
                }
                default:
                    insn.mnemonic = Mnemonic::INVALID;
                    break;
            }
        } else {
            insn.mnemonic = Mnemonic::INVALID;
        }
    }

    insn.length = (uint8_t)c.pos;
    return insn;
}

DecodedInsn Decoder::decode_vex_insn(Ctx& c) {
    if (c.pos >= c.max) return {};
    uint8_t op = c.base[c.pos];

    // VZEROUPPER (L=0) / VZEROALL (L=1): VEX.0F 77 (no ModRM byte)
    if (c.pfx.vex_map == 1 && op == 0x77 && c.pfx.vex_pp == 0) {
        c.read8();
        DecodedInsn insn;
        insn.prefixes  = c.pfx;
        insn.op_size   = c.pfx.vex_len ? 32 : 16;
        insn.addr_size = c.addr_size;
        insn.mnemonic  = c.pfx.vex_len ? Mnemonic::VZEROALL : Mnemonic::VZEROUPPER;
        insn.length    = (uint8_t)c.pos;
        return insn;
    }

    switch (c.pfx.vex_map) {
        case 1: return decode_two_byte(c);
        case 2: return decode_three_byte(c, 0x38);
        case 3: return decode_three_byte(c, 0x3A);
        default: return {};
    }
}


} // namespace emu::cpu
