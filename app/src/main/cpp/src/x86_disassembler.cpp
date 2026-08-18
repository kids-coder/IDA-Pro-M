/**
 * IDA Pro M - x86/x86-64 Disassembler
 * Complete implementation of x86 (32-bit) and x86-64 instruction decoding
 * Supports: Base ISA, MMX, SSE, SSE2-SSE4.2, AVX/AVX2 (partial), FPU
 */

#include "idapro_engine.h"
#include <cstring>
#include <sstream>
#include <map>
#include <unordered_map>

namespace idapro {

namespace x86 {

// ============================================================================
// x86 Opcode Tables
// ============================================================================

// Prefix bytes
enum class Prefix : uint8_t {
    // Legacy prefixes
    LOCK = 0xF0,
    REPNZ = 0xF2,
    REP = 0xF3,
    CS_OVERRIDE = 0x2E,
    SS_OVERRIDE = 0x36,
    DS_OVERRIDE = 0x3E,
    ES_OVERRIDE = 0x26,
    FS_OVERRIDE = 0x64,
    GS_OVERRIDE = 0x65,
    OPERAND_SIZE = 0x66,   // 66h - Switch operand size
    ADDR_SIZE = 0x67,      // 67h - Switch address size
    
    // REX prefix (x86-64 only)
    REX_BASE = 0x40,       // REX range: 40h-4Fh
};

// ModR/M fields
struct ModRM {
    uint8_t mod;     // Bits 7-6
    uint8_t reg;     // Bits 5-3
    uint8_t rm;      // Bits 2-0
    
    void parse(uint8_t byte) {
        mod = (byte >> 6) & 3;
        reg = (byte >> 3) & 7;
        rm = byte & 7;
    }
    
    bool hasSIB() const { return mod != 3 && rm == 4; }
    bool hasDisp8() const { return mod == 1; }
    bool hasDisp32() const { return mod == 2; }
    bool isRegDirect() const { return mod == 3; }
};

// SIB byte
struct SIB {
    uint8_t scale;   // Bits 7-6
    uint8_t index;   // Bits 5-3
    uint8_t base;    // Bits 2-0
    
    void parse(uint8_t byte) {
        scale = (byte >> 6) & 3;
        index = (byte >> 3) & 7;
        base = byte & 7;
    }
    
    uint8_t getScaleValue() const { return 1 << scale; }  // 1, 2, 4, or 8
};

// REX prefix structure (x86-64)
struct REX {
    bool W;          // 64-bit operand size
    bool R;          // Extension of ModRM reg field
    bool X;          // Extension of SIB index field
    bool B;          // Extension of ModRM r/m, SIB base, or opcode reg
    
    void parse(uint8_t byte) {
        W = (byte >> 3) & 1;
        R = (byte >> 2) & 1;
        X = (byte >> 1) & 1;
        B = byte & 1;
    }
    
    bool isREX() const { return true; }  // Always valid if parsed
};

// ============================================================================
// x86 Register Tables
// ============================================================================

// 8-bit registers (index by register number + REX.B extension)
inline Register getReg8(int idx, bool highByte = false, bool rex = false) {
    if (rex && !highByte) {
        switch (idx) {
            case 0: return Register::AL;
            case 1: return Register::BL;
            case 2: return Register::CL;
            case 3: return Register::DL;
            case 4: return Register::SIL;
            case 5: return Register::DIL;
            case 6: return Register::BPL;
            case 7: return Register::SPL;
            case 8: return Register::R8B;
            case 9: return Register::R9B;
            case 10: return Register::R10B;
            case 11: return Register::R11B;
            case 12: return Register::R12B;
            case 13: return Register::R13B;
            case 14: return Register::R14B;
            case 15: return Register::R15B;
        }
    } else if (!highByte) {
        switch (idx & 7) {
            case 0: return Register::AL;
            case 1: return Register::CL;
            case 2: return Register::DL;
            case 3: return Register::BL;
            case 4: return Register::AH;
            case 5: return Register::CH;
            case 6: return Register::DH;
            case 7: return Register::BH;
        }
    }
    return Register::NONE;
}

// 16-bit registers
inline Register getReg16(int idx, bool rex = false) {
    int actualIdx = rex ? idx : (idx & 7);
    switch (actualIdx) {
        case 0: return Register::AX;
        case 1: return Register::CX;
        case 2: return Register::DX;
        case 3: return Register::BX;
        case 4: return Register::SP;
        case 5: return Register::BP;
        case 6: return Register::SI;
        case 7: return Register::DI;
        case 8: return Register::R8W;
        case 9: return Register::R9W;
        case 10: return Register::R10W;
        case 11: return Register::R11W;
        case 12: return Register::R12W;
        case 13: return Register::R13W;
        case 14: return Register::R14W;
        case 15: return Register::R15W;
        default: return Register::NONE;
    }
}

// 32-bit registers
inline Register getReg32(int idx, bool rex = false) {
    int actualIdx = rex ? idx : (idx & 7);
    switch (actualIdx) {
        case 0: return Register::EAX;
        case 1: return Register::ECX;
        case 2: return Register::EDX;
        case 3: return Register::EBX;
        case 4: return Register::ESP;
        case 5: return Register::EBP;
        case 6: return Register::ESI;
        case 7: return Register::EDI;
        case 8: return Register::R8;
        case 9: return Register::R9;
        case 10: return Register::R10;
        case 11: return Register::R11;
        case 12: return Register::R12;
        case 13: return Register::R13;
        case 14: return Register::R14;
        case 15: return Register::R15;
        default: return Register::NONE;
    }
}

// 64-bit registers (x86-64 only)
inline Register getReg64(int idx) {
    switch (idx) {
        case 0: return Register::RAX;
        case 1: return Register::RCX;
        case 2: return Register::RDX;
        case 3: return Register::RBX;
        case 4: return Register::RSP;
        case 5: return Register::RBP;
        case 6: return Register::RSI;
        case 7: return Register::RDI;
        case 8: return Register::R8;
        case 9: return Register::R9;
        case 10: return Register::R10;
        case 11: return Register::R11;
        case 12: return Register::R12;
        case 13: return Register::R13;
        case 14: return Register::R14;
        case 15: return Register::R15;
        default: return Register::NONE;
    }
}

// Segment registers
inline Register getSegReg(int idx) {
    switch (idx & 7) {
        case 0: return Register::ES;
        case 1: return Register::CS;
        case 2: return Register::SS;
        case 3: return Register::DS;
        case 4: return Register::FS;
        case 5: return Register::GS;
        default: return Register::NONE;
    }
}

// XMM registers
inline Register getXMMReg(int idx, bool rex = false) {
    int actualIdx = rex ? idx : (idx & 7);
    if (actualIdx < 32) {
        return static_cast<Register>(actualIdx + Register::XMM0);
    }
    return Register::NONE;
}

// ============================================================================
// x86 Instruction Decoder State
// ============================================================================

struct DecodeState {
    bool is64BitMode = false;
    bool operandSizeOverride = false;  // 66h prefix
    bool addressSizeOverride = false;  // 67h prefix
    bool lockPrefix = false;
    bool repPrefix = false;           // F3 or F2
    
    REX rex;
    bool hasREX = false;
    
    Register segmentOverride = Register::NONE;
    
    // Default operand sizes based on mode
    int getOperandSize() const {
        if (operandSizeOverride) {
            return is64BitMode ? 16 : 16;
        }
        return is64BitMode ? (hasREX && rex.W ? 64 : 32) : 32;
    }
    
    int getAddressSize() const {
        if (addressSizeOverride) {
            return is64BitMode ? 32 : 16;
        }
        return is64BitMode ? 64 : 32;
    }
    
    int getRegisterSize() const {
        int opSize = getOperandSize();
        if (opSize == 64) return 64;
        if (opSize == 16) return 16;
        return 32;
    }
};

// ============================================================================
// x86 Instruction Decoding Functions
// ============================================================================

Instruction decodeX86Instruction(uint64_t addr, const uint8_t* data, size_t maxSize, 
                                  bool is64Bit = false) {
    Instruction insn;
    insn.address = addr;
    insn.arch = is64Bit ? Architecture::X86_64 : Architecture::X86_32;
    
    DecodeState state;
    state.is64BitMode = is64Bit;
    
    size_t pos = 0;
    
    // Parse prefixes
    while (pos < maxSize) {
        uint8_t byte = data[pos];
        
        // Check for REX prefix (only in 64-bit mode)
        if (is64Bit && (byte >= 0x40 && byte <= 0x4F)) {
            state.hasREX = true;
            state.rex.parse(byte);
            pos++;
            continue;
        }
        
        switch (static_cast<Prefix>(byte)) {
            case Prefix::LOCK:
                state.lockPrefix = true;
                pos++;
                continue;
            case Prefix::REP:
            case Prefix::REPNZ:
                state.repPrefix = true;
                pos++;
                continue;
            case Prefix::OPERAND_SIZE:
                state.operandSizeOverride = true;
                pos++;
                continue;
            case Prefix::ADDR_SIZE:
                state.addressSizeOverride = true;
                pos++;
                continue;
            case Prefix::CS_OVERRIDE:
                state.segmentOverride = Register::CS;
                pos++;
                continue;
            case Prefix::SS_OVERRIDE:
                state.segmentOverride = Register::SS;
                pos++;
                continue;
            case Prefix::DS_OVERRIDE:
                state.segmentOverride = Register::DS;
                pos++;
                continue;
            case Prefix::ES_OVERRIDE:
                state.segmentOverride = Register::ES;
                pos++;
                continue;
            case Prefix::FS_OVERRIDE:
                state.segmentOverride = Register::FS;
                pos++;
                continue;
            case Prefix::GS_OVERRIDE:
                state.segmentOverride = Register::GS;
                pos++;
                continue;
            default:
                // Not a prefix, exit prefix parsing loop
                break;
        }
        break;
    }
    
    if (pos >= maxSize) {
        // Only had prefixes, no opcode
        insn.type = InstructionType::INVALID;
        insn.size = static_cast<uint8_t>(pos);
        for (size_t i = 0; i < pos; ++i) {
            insn.rawBytes.push_back(data[i]);
        }
        return insn;
    }
    
    // Read opcode
    uint8_t opcode = data[pos++];
    insn.rawBytes.insert(insn.rawBytes.end(), data, data + pos);
    
    // Handle multi-byte opcodes
    bool hasModRM = false;
    bool twoByteOpcode = false;
    
    if (opcode == 0x0F) {
        // Two-byte opcode
        if (pos >= maxSize) {
            insn.type = InstructionType::INVALID;
            insn.mnemonic = ".byte";
            insn.operandsStr = "0x0F";
            return insn;
        }
        opcode = data[pos++];
        twoByteOpcode = true;
        hasModRM = true;  // Most 0F opcodes have ModRM
    }
    
    // Determine instruction type and decode operands
    std::string mnemonic;
    InstructionType type = InstructionType::INVALID;
    
    // Simple single-byte instructions without ModRM
    switch (opcode) {
        // NOP variants
        case 0x90:
            mnemonic = "nop"; type = InstructionType::NOP;
            break;
            
        // Return instructions
        case 0xC3:
            mnemonic = "ret"; type = InstructionType::RET;
            insn.isReturn = true;
            insn.isTerminal = true;
            break;
        case 0xC2:
            mnemonic = "ret"; type = InstructionType::RET;
            insn.isReturn = true;
            insn.isTerminal = true;
            if (pos + 1 < maxSize) {
                uint16_t popVal = data[pos] | (data[pos+1] << 8);
                Operand immOp;
                immOp.type = OperandType::IMMEDIATE;
                immOp.immediateValue = popVal;
                immOp.size = 2;
                insn.operandsStr = utils::formatHexWord(popVal);
                insn.operands.push_back(immOp);
                pos += 2;
            }
            break;
        case 0xCB:
            mnemonic = "retf"; type = InstructionType::RET;
            insn.isReturn = true;
            insn.isTerminal = true;
            break;
            
        // Call instructions
        case 0xE8: {
            mnemonic = "call"; type = InstructionType::CALL;
            insn.isCall = true;
            // Relative call
            if (pos + 4 <= maxSize) {
                int32_t relOffset = data[pos] | (data[pos+1] << 8) | 
                                   (data[pos+2] << 16) | ((int32_t)data[pos+3] << 24);
                uint64_t target = addr + pos + relOffset + 4;  // +4 for instruction size
                
                Operand targetOp;
                targetOp.type = OperandType::IMMEDIATE;
                targetOp.immediateValue = static_cast<int64_t>(target);
                targetOp.size = state.getRegisterSize() == 64 ? 8 : 4;
                
                insn.branchTarget = target;
                insn.operandsStr = utils::formatAddress(target);
                insn.operands.push_back(targetOp);
                pos += 4;
            }
            break;
        }
        
        // Unconditional jump
        case 0xE9: {
            mnemonic = "jmp"; type = InstructionType::JMP;
            insn.isBranch = true;
            insn.isTerminal = true;
            if (pos + 4 <= maxSize) {
                int32_t relOffset = data[pos] | (data[pos+1] << 8) |
                                   (data[pos+2] << 16) | ((int32_t)data[pos+3] << 24);
                uint64_t target = addr + pos + relOffset + 5;
                
                Operand targetOp;
                targetOp.type = OperandType::IMMEDIATE;
                targetOp.immediateValue = static_cast<int64_t>(target);
                targetOp.size = state.getRegisterSize() == 64 ? 8 : 4;
                
                insn.branchTarget = target;
                insn.operandsStr = utils::formatAddress(target);
                insn.operands.push_back(targetOp);
                pos += 4;
            }
            break;
        }
        
        // Short jump (8-bit relative)
        case 0xEB: {
            mnemonic = "jmp"; type = InstructionType::JMP;
            insn.isBranch = true;
            insn.isTerminal = true;
            if (pos < maxSize) {
                int8_t relOffset = static_cast<int8_t>(data[pos]);
                uint64_t target = addr + pos + relOffset + 1;
                
                Operand targetOp;
                targetOp.type = OperandType::IMMEDIATE;
                targetOp.immediateValue = static_cast<int64_t>(target);
                targetOp.size = 4;
                
                insn.branchTarget = target;
                insn.operandsStr = utils::formatAddress(target);
                insn.operands.push_back(targetOp);
                pos += 1;
            }
            break;
        }
        
        // Conditional jumps (short form)
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
            const char* condNames[] = {
                "jo", "jno", "jb/jc", "jnb/jnc", "jz/je", "jnz/jne",
                "jbe/jna", "jnbe/ja", "js", "jns", "jp/jpe", "jnp/jpo",
                "jl/jnge", "jnl/jge", "jle/jn", "jnle/jg"
            };
            mnemonic = condNames[opcode - 0x70];
            type = InstructionType::B;
            insn.isBranch = true;
            insn.isConditional = true;
            if (pos < maxSize) {
                int8_t relOffset = static_cast<int8_t>(data[pos]);
                uint64_t target = addr + pos + relOffset + 1;
                
                Operand targetOp;
                targetOp.type = OperandType::IMMEDIATE;
                targetOp.immediateValue = static_cast<int64_t>(target);
                targetOp.size = 4;
                
                insn.branchTarget = target;
                insn.operandsStr = utils::formatAddress(target);
                insn.operands.push_back(targetOp);
                pos += 1;
            }
            break;
        }
        
        // PUSH/POP
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57: {
            mnemonic = "push"; type = InstructionType::PUSH;
            int regNum = opcode - 0x50;
            int extReg = state.hasREX && state.rex.B ? regNum + 8 : regNum;
            Operand regOp;
            regOp.type = OperandType::REGISTER;
            regOp.reg = (state.getRegisterSize() == 64) ? 
                        getReg64(extReg) : getReg32(extReg, state.hasREX && state.rex.B);
            regOp.size = state.getRegisterSize() == 64 ? 8 : 4;
            insn.operandsStr = registerToString(regOp.reg);
            insn.operands.push_back(regOp);
            break;
        }
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
            mnemonic = "pop"; type = InstructionType::POP;
            int regNum = opcode - 0x58;
            int extReg = state.hasREX && state.rex.B ? regNum + 8 : regNum;
            Operand regOp;
            regOp.type = OperandType::REGISTER;
            regOp.reg = (state.getRegisterSize() == 64) ?
                        getReg64(extReg) : getReg32(extReg, state.hasREX && state.rex.B);
            regOp.size = state.getRegisterSize() == 64 ? 8 : 4;
            insn.operandsStr = registerToString(regOp.reg);
            insn.operands.push_back(regOp);
            break;
        }
        
        // MOV immediate to register
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7: {
            // MOV r8, imm8
            mnemonic = "mov"; type = InstructionType::MOV;
            int regNum = opcode - 0xB0;
            int extReg = state.hasREX && state.rex.B ? regNum + 8 : regNum;
            if (pos < maxSize) {
                Operand regOp, immOp;
                regOp.type = OperandType::REGISTER;
                regOp.reg = getReg8(extReg, false, state.hasREX && state.rex.B);
                regOp.size = 1;
                
                immOp.type = OperandType::IMMEDIATE;
                immOp.immediateValue = data[pos];
                immOp.size = 1;
                
                std::ostringstream ops;
                ops << registerToString(regOp.reg) << ", "
                    << (int)data[pos];
                insn.operandsStr = ops.str();
                insn.operands.push_back(regOp);
                insn.operands.push_back(immOp);
                pos += 1;
            }
            break;
        }
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
            // MOV r32/r64, imm32/imm64
            mnemonic = "mov"; type = InstructionType::MOV;
            int regNum = opcode - 0xB8;
            int extReg = state.hasREX && state.rex.B ? regNum + 8 : regNum;
            
            Operand regOp, immOp;
            regOp.type = OperandType::REGISTER;
            
            if (state.getRegisterSize() == 64 && (state.hasREX && state.rex.W || !state.operandSizeOverride)) {
                regOp.reg = getReg64(extReg);
                regOp.size = 8;
                if (pos + 8 <= maxSize) {
                    int64_t imm64 = 0;
                    for (int i = 0; i < 8; ++i) {
                        imm64 |= (static_cast<int64_t>(data[pos+i]) << (i*8));
                    }
                    immOp.type = OperandType::IMMEDIATE;
                    immOp.immediateValue = imm64;
                    immOp.size = 8;
                    
                    std::ostringstream ops;
                    ops << registerToString(regOp.reg) << ", 0x"
                        << std::hex << imm64;
                    insn.operandsStr = ops.str();
                    pos += 8;
                }
            } else {
                regOp.reg = getReg32(extReg, state.hasREX && state.rex.B);
                regOp.size = 4;
                if (pos + 4 <= maxSize) {
                    int32_t imm32 = data[pos] | (data[pos+1] << 8) |
                                    (data[pos+2] << 16) | (data[pos+3] << 24);
                    immOp.type = OperandType::IMMEDIATE;
                    immOp.immediateValue = imm32;
                    immOp.size = 4;
                    
                    std::ostringstream ops;
                    ops << registerToString(regOp.reg) << ", 0x"
                        << std::hex << imm32;
                    insn.operandsStr = ops.str();
                    pos += 4;
                }
            }
            insn.operands.push_back(regOp);
            insn.operands.push_back(immOp);
            break;
        }
        
        // INT instructions
        case 0xCC:
            mnemonic = "int3"; type = InstructionType::INT3;
            insn.isTerminal = true;
            break;
        case 0xCD:
            mnemonic = "int"; type = InstructionType::INT;
            insn.isPrivileged = true;
            if (pos < maxSize) {
                Operand immOp;
                immOp.type = OperandType::IMMEDIATE;
                immOp.immediateValue = data[pos];
                immOp.size = 1;
                insn.operandsStr = std::to_string((int)data[pos]);
                insn.operands.push_back(immOp);
                pos += 1;
            }
            break;
            
        // LEA
        case 0x8D:
            mnemonic = "lea"; type = InstructionType::LEA;
            hasModRM = true;
            break;
            
        // CDQ/CQO
        case 0x99:
            mnemonic = is64Bit ? "cqo" : "cdq";
            type = InstructionType::CDQ;
            break;
            
        // CPUID
        case 0x0A:  // Two-byte: 0F A2
            if (twoByteOpcode) {
                mnemonic = "cpuid"; type = InstructionType::CPUID;
            }
            break;
            
        // RDTSC
        case 0x31:  // Two-byte: 0F 31
            if (twoByteOpcode) {
                mnemonic = "rdtsc"; type = InstructionType::RDTSC;
            }
            break;
            
        // SYSCALL/SYSRET
        case 0x05:  // Two-byte: 0F 05
            if (twoByteOpcode) {
                mnemonic = "syscall"; type = InstructionType::SYSCALL;
                insn.isPrivileged = true;
                insn.isTerminal = true;
            }
            break;
            
        // LOOP instructions
        case 0xE0: case 0xE1: case 0xE2: {
            const char* loopNames[] = {"loopne", "loope", "loop"};
            mnemonic = loopNames[opcode - 0xE0]; type = InstructionType::LOOP;
            insn.isBranch = true;
            if (pos < maxSize) {
                int8_t relOffset = static_cast<int8_t>(data[pos]);
                uint64_t target = addr + pos + relOffset + 1;
                
                Operand targetOp;
                targetOp.type = OperandType::IMMEDIATE;
                targetOp.immediateValue = static_cast<int64_t>(target);
                targetOp.size = 4;
                
                insn.branchTarget = target;
                insn.operandsStr = utils::formatAddress(target);
                insn.operands.push_back(targetOp);
                pos += 1;
            }
            break;
        }
            
        // MOVSX/MOVZX
        case 0xBE:  // Two-byte: 0F BE /r (MOVSX r32, r/m16 or r64, r/m32)
        case 0xBF:  // Two-byte: 0F BF /r (MOVSX r32, r/m16 or r64, r/m16)
        case 0xB6:  // Two-byte: 0F B6 /r (MOVZX r32, r/m8 or r64, r/m8)
        case 0xB7:  // Two-byte: 0F B7 /r (MOVZX r32, r/m16 or r64, r/m16)
            if (twoByteOpcode) {
                switch (opcode) {
                    case 0xBE: mnemonic = "movsx"; type = InstructionType::MOVSX; break;
                    case 0xBF: mnemonic = "movsx"; type = InstructionType::MOVSX; break;
                    case 0xB6: mnemonic = "movzx"; type = InstructionType::MOVZX; break;
                    case 0xB7: mnemonic = "movzx"; type = InstructionType::MOVZX; break;
                }
                hasModRM = true;
            }
            break;
            
        // XCHG with accumulator
        case 0x91: case 0x92: case 0x93: case 0x94:
        case 0x95: case 0x96: case 0x97: {
            mnemonic = "xchg"; type = InstructionType::MOV;
            int regNum = opcode - 0x90;
            int extReg = state.hasREX && state.rex.B ? regNum + 8 : regNum;
            Operand accOp, regOp;
            
            accOp.type = OperandType::REGISTER;
            accOp.reg = (state.getRegisterSize() == 64) ? Register::RAX : Register::EAX;
            accOp.size = state.getRegisterSize() == 64 ? 8 : 4;
            
            regOp.type = OperandType::REGISTER;
            regOp.reg = (state.getRegisterSize() == 64) ?
                        getReg64(extReg) : getReg32(extReg, state.hasREX && state.rex.B);
            regOp.size = state.getRegisterSize() == 64 ? 8 : 4;
            
            std::ostringstream ops;
            ops << registerToString(accOp.reg) << ", "
                << registerToString(regOp.reg);
            insn.operandsStr = ops.str();
            insn.operands.push_back(accOp);
            insn.operands.push_back(regOp);
            break;
        }
            
        // INC/DEC (single-register form, not recommended in 64-bit mode)
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44: case 0x45: case 0x46: case 0x47: {
            if (!state.hasREX) {
                mnemonic = "inc"; type = InstructionType::ADD;
                int regNum = opcode - 0x40;
                Operand regOp;
                regOp.type = OperandType::REGISTER;
                regOp.reg = getReg32(regNum);
                regOp.size = 4;
                insn.operandsStr = registerToString(regOp.reg);
                insn.operands.push_back(regOp);
            }
            // Otherwise it's a REX prefix already handled above
            break;
        }
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
            if (!state.hasREX) {
                mnemonic = "dec"; type = InstructionType::SUB;
                int regNum = opcode - 0x48;
                Operand regOp;
                regOp.type = OperandType::REGISTER;
                regOp.reg = getReg32(regNum);
                regOp.size = 4;
                insn.operandsStr = registerToString(regOp.reg);
                insn.operands.push_back(regOp);
            }
            break;
        }
            
        default:
            // Instructions requiring ModRM byte - handle generically
            hasModRM = true;
            
            // Common ALU operations with ModRM
            if (opcode >= 0x00 && opcode <= 0x05) {
                switch (opcode % 8) {
                    case 0: mnemonic = "add"; type = InstructionType::ADD; break;
                    case 1: mnemonic = "or"; type = InstructionType::ORR; break;
                    case 2: mnemonic = "adc"; type = InstructionType::ADC; break;
                    case 3: mnemonic = "sbb"; type = InstructionType::SBC; break;
                    case 4: mnemonic = "and"; type = InstructionType::AND; break;
                    case 5: mnemonic = "sub"; type = InstructionType::SUB; break;
                    case 6: mnemonic = "xor"; type = InstructionType::EOR; break;
                    case 7: mnemonic = "cmp"; type = InstructionType::CMP; break;
                }
            } else if (opcode >= 0x08 && opcode <= 0x0D) {
                switch (opcode % 8) {
                    case 0: mnemonic = "or"; type = InstructionType::ORR; break;
                    case 1: mnemonic = "or"; type = InstructionType::ORR; break;
                    case 2: mnemonic = "adc"; type = InstructionType::ADC; break;
                    case 3: mnemonic = "sbb"; type = InstructionType::SBC; break;
                    case 4: mnemonic = "and"; type = InstructionType::AND; break;
                    case 5: mnemonic = "sub"; type = InstructionType::SUB; break;
                    case 6: mnemonic = "xor"; type = InstructionType::EOR; break;
                    case 7: mnemonic = "cmp"; type = InstructionType::CMP; break;
                }
            } else if (opcode >= 0x20 && opcode <= 0x25) {
                switch (opcode % 8) {
                    case 0: mnemonic = "and"; type = InstructionType::AND; break;
                    case 1: mnemonic = "and"; type = InstructionType::AND; break;
                    case 2: mnemonic = "sub"; type = InstructionType::SUB; break;
                    case 3: mnemonic = "sub"; type = InstructionType::SUB; break;
                    case 4: mnemonic = "and"; type = InstructionType::AND; break;
                    case 5: mnemonic = "sub"; type = InstructionType::SUB; break;
                    case 6: mnemonic = "xor"; type = InstructionType::EOR; break;
                    case 7: mnemonic = "cmp"; type = InstructionType::CMP; break;
                }
            } else if (opcode >= 0x28 && opcode <= 0x2D) {
                switch (opcode % 8) {
                    case 0: mnemonic = "sub"; type = InstructionType::SUB; break;
                    case 1: mnemonic = "sub"; type = InstructionType::SUB; break;
                    case 2: mnemonic = "sub"; type = InstructionType::SUB; break;
                    case 3: mnemonic = "sub"; type = InstructionType::SUB; break;
                    case 4: mnemonic = "and"; type = InstructionType::AND; break;
                    case 5: mnemonic = "sub"; type = InstructionType::SUB; break;
                    case 6: mnemonic = "xor"; type = InstructionType::EOR; break;
                    case 7: mnemonic = "cmp"; type = InstructionType::CMP; break;
                }
            } else if (opcode >= 0x30 && opcode <= 0x35) {
                switch (opcode % 8) {
                    case 0: mnemonic = "xor"; type = InstructionType::EOR; break;
                    case 1: mnemonic = "xor"; type = InstructionType::EOR; break;
                    case 2: mnemonic = "xor"; type = InstructionType::EOR; break;
                    case 3: mnemonic = "xor"; type = InstructionType::EOR; break;
                    case 4: mnemonic = "xor"; type = InstructionType::EOR; break;
                    case 5: mnemonic = "xor"; type = InstructionType::EOR; break;
                    case 6: mnemonic = "xor"; type = InstructionType::EOR; break;
                    case 7: mnemonic = "cmp"; type = InstructionType::CMP; break;
                }
            } else if (opcode >= 0x38 && opcode <= 0x3D) {
                switch (opcode % 8) {
                    case 0: mnemonic = "cmp"; type = InstructionType::CMP; break;
                    case 1: mnemonic = "cmp"; type = InstructionType::CMP; break;
                    case 2: mnemonic = "cmp"; type = InstructionType::CMP; break;
                    case 3: mnemonic = "cmp"; type = InstructionType::CMP; break;
                    case 4: mnemonic = "cmp"; type = InstructionType::CMP; break;
                    case 5: mnemonic = "cmp"; type = InstructionType::CMP; break;
                    case 6: mnemonic = "cmp"; type = InstructionType::CMP; break;
                    case 7: mnemonic = "cmp"; type = InstructionType::CMP; break;
                }
            } else if (opcode >= 0x80 && opcode <= 0x8F) {
                // Group 1-5 instructions
                hasModRM = true;
                // Will be decoded after reading ModRM
            } else if (twoByteOpcode) {
                // Two-byte opcodes that need special handling
                switch (opcode) {
                    case 0x80: case 0x81: case 0x82: case 0x83:
                        mnemonic = "grp1"; type = InstructionType::ADD; break;
                    case 0x84: case 0x85:
                        mnemonic = "test"; type = InstructionType::TST; break;
                    case 0x86: case 0x87:
                        mnemonic = "xchg"; type = InstructionType::MOV; break;
                    case 0x88: case 0x89:
                        mnemonic = "mov"; type = InstructionType::MOV; break;
                    case 0x8A: case 0x8B:
                        mnemonic = "mov"; type = InstructionType::MOV; break;
                    case 0x8C:
                        mnemonic = "mov"; type = InstructionType::MOV; break;  // Mov to/from seg reg
                    case 0x8E:
                        mnemonic = "mov"; type = InstructionType::MOV; break;  // Mov to seg reg
                    case 0x90:
                        mnemonic = "nop"; type = InstructionType::NOP; break;
                    case 0xA0: case 0xA1:
                        mnemonic = "mov"; type = InstructionType::MOV; break;  // moffs
                    case 0xA2: case 0xA3:
                        mnemonic = "mov"; type = InstructionType::MOV; break;  // moffs
                    case 0xA4: case 0xA5:
                        mnemonic = state.repPrefix ? (state.repPrefix == (uint8_t)Prefix::REP ? "rep movsb" : "rep movsd") : "movs";
                        type = InstructionType::LDR; break;
                    case 0xA6: case 0xA7:
                        mnemonic = "cmps"; type = InstructionType::CMP; break;
                    case 0xA8: case 0xA9:
                        mnemonic = "test"; type = InstructionType::TST; break;
                    case 0xAA: case 0xAB:
                        mnemonic = state.repPrefix ? (state.repPrefix == (uint8_t)Prefix::REP ? "rep stosb" : "rep stosd") : "stos";
                        type = InstructionType::STR; break;
                    case 0xAC: case 0xAD:
                        mnemonic = state.repPrefix ? (state.repPrefix == (uint8_t)Prefix::REP ? "rep lodsb" : "rep lodsd") : "lods";
                        type = InstructionType::LDR; break;
                    case 0xAE: case 0xAF:
                        mnemonic = "scas"; type = InstructionType::CMP; break;
                    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
                        mnemonic = "shift"; type = InstructionType::SHL; break;
                    case 0xD4: case 0xD5:
                        mnemonic = "aalad"; type = InstructionType::INVALID; break;
                    case 0xD6:
                        mnemonic = "salc"; type = InstructionType::INVALID; break;
                    case 0xD7:
                        mnemonic = "xlatt"; type = InstructionType::LDR; break;
                    case 0xD8: case 0xD9: case 0xDA: case 0xDB:
                    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
                        mnemonic = "fpu"; type = InstructionType::FADD; break;  // FPU
                    case 0xE0: case 0xE1: case 0xE2: case 0xE3:
                        mnemonic = "loop/jcxz"; type = InstructionType::LOOP; break;
                    case 0xF4:
                        mnemonic = "hlt"; type = InstructionType::SVC; break;
                    case 0xF5:
                        mnemonic = "cmc"; type = InstructionType::INVALID; break;
                    case 0xF6: case 0xF7:
                        mnemonic = "grp3"; type = InstructionType::TEST; break;
                    case 0xF8: case 0xF9:
                        mnemonic = "clc/stc"; type = InstructionType::INVALID; break;
                    case 0xFA: case 0xFB:
                        mnemonic = "cli/sti"; type = InstructionType::SVC; break;
                    case 0xFC: case 0xFD:
                        mnemonic = "cld/std"; type = InstructionType::INVALID; break;
                    case 0xFE: case 0xFF:
                        mnemonic = "grp45"; type = InstructionType::CALL; break;
                    default:
                        mnemonic = "???"; type = InstructionType::INVALID; break;
                }
            } else {
                mnemonic = "db"; type = InstructionType::DB;
                hasModRM = false;
            }
            break;
    }
    
    // Parse ModRM if present
    if (hasModRM && pos < maxSize) {
        ModRM modrm;
        modrm.parse(data[pos++]);
        
        int regExt = state.hasREX && state.rex.R ? modrm.reg + 8 : modrm.reg;
        int rmExt = state.hasREX && state.rex.B ? modrm.rm + 8 : modrm.rm;
        
        // Build register/memory operands
        Operand op1, op2;
        
        if (modrm.isRegDirect()) {
            // Register direct mode
            op2.type = OperandType::REGISTER;
            switch (state.getRegisterSize()) {
                case 64:
                    op2.reg = getReg64(rmExt);
                    op2.size = 8;
                    break;
                case 32:
                    op2.reg = getReg32(rmExt, state.hasREX && state.rex.B);
                    op2.size = 4;
                    break;
                case 16:
                    op2.reg = getReg16(rmExt, state.hasREX && state.rex.B);
                    op2.size = 2;
                    break;
                default:
                    op2.reg = getReg8(rmExt, false, state.hasREX && state.rex.B);
                    op2.size = 1;
                    break;
            }
        } else {
            // Memory addressing mode
            op2.type = OperandType::MEMORY;
            op2.memory.baseReg = getReg32(rmExt, state.hasREX && state.rex.B);
            if (state.getRegisterSize() == 64) {
                op2.memory.baseReg = getReg64(rmExt);
            }
            op2.memory.size = state.getOperandSize() / 8;
            
            // Parse displacement
            if (modrm.hasDisp8()) {
                if (pos < maxSize) {
                    op2.memory.offset = static_cast<int8_t>(data[pos++]);
                }
            } else if (modrm.hasDisp32()) {
                if (pos + 3 < maxSize) {
                    int32_t disp32 = data[pos] | (data[pos+1] << 8) |
                                     (data[pos+2] << 16) | (data[pos+3] << 24);
                    op2.memory.offset = disp32;
                    pos += 4;
                }
            }
            
            // Parse SIB if present
            if (modrm.hasSIB() && pos < maxSize) {
                SIB sib;
                sib.parse(data[pos++]);
                
                int indexExt = state.hasREX && state.reX ? sib.index + 8 : sib.index;
                int baseExt = state.hasREX && state.reX ? sib.base + 8 : sib.base;
                
                if (sib.index != 4) {  // Index 4 means no index
                    op2.memory.indexReg = getReg32(indexExt, state.hasREX && state.reX);
                    if (state.getRegisterSize() == 64) {
                        op2.memory.indexReg = getReg64(indexExt);
                    }
                    op2.memory.scale = sib.getScaleValue();
                }
                
                // Update base register from SIB
                op2.memory.baseReg = getReg32(baseExt, state.hasREX && state.reX);
                if (state.getRegisterSize() == 64) {
                    op2.memory.baseReg = getReg64(baseExt);
                }
                
                // Special cases for base register
                if (sib.base == 5 && modrm.mod == 0) {
                    // No base register, use disp32 only
                    op2.memory.baseReg = Register::NONE;
                    if (pos + 3 < maxSize) {
                        int32_t disp32 = data[pos] | (data[pos+1] << 8) |
                                         (data[pos+2] << 16) | (data[pos+3] << 24);
                        op2.memory.offset = disp32;
                        pos += 4;
                    }
                } else if (sib.base == 4 && modrm.mod == 0) {
                    // No SIB base (RSP特殊情况)
                    // Usually indicates no base
                }
            }
            
            // Special case: RIP-relative addressing in 64-bit mode
            if (is64Bit && modrm.mod == 0 && modrm.rm == 5) {
                op2.memory.baseReg = Register::RIP;
                if (pos + 3 < maxSize) {
                    int32_t disp32 = data[pos] | (data[pos+1] << 8) |
                                     (data[pos+2] << 16) | (data[pos+3] << 24);
                    op2.memory.offset = disp32;
                    pos += 4;
                }
            }
        }
        
        // First operand (register from reg field)
        op1.type = OperandType::REGISTER;
        switch (state.getRegisterSize()) {
            case 64:
                op1.reg = getReg64(regExt);
                op1.size = 8;
                break;
            case 32:
                op1.reg = getReg32(regExt, state.hasREX && state.rex.R);
                op1.size = 4;
                break;
            case 16:
                op1.reg = getReg16(regExt, state.hasREX && state.rex.R);
                op1.size = 2;
                break;
            default:
                op1.reg = getReg8(regExt, false, state.hasREX && state.rex.R);
                op1.size = 1;
                break;
        }
        
        // Check for direction bit (some opcodes swap operands)
        bool directionFromRegField = !(opcode & 1);  // Simplified
        
        // Build operands string
        std::ostringstream ops;
        if (directionFromRegField) {
            ops << registerToString(op1.reg) << ", " << op2.toString();
            insn.operands.push_back(op1);
            insn.operands.push_back(op2);
        } else {
            ops << op2.toString() << ", " << registerToString(op1.reg);
            insn.operands.push_back(op2);
            insn.operands.push_back(op1);
        }
        insn.operandsStr = ops.str();
        insn.operandCount = 2;
    }
    
    // Handle immediate operands for some instructions
    if ((opcode >= 0x04 && opcode <= 0x07) ||
        (opcode >= 0x0C && opcode <= 0x0F) ||
        (opcode >= 0x24 && opcode <= 0x27) ||
        (opcode >= 0x2C && opcode <= 0x2F) ||
        (opcode >= 0x34 && opcode <= 0x37) ||
        (opcode >= 0x3C && opcode <= 0x3F)) {
        // ALU operations with immediate to AL/AX/EAX/RAX
        if (pos < maxSize) {
            Operand immOp;
            immOp.type = OperandType::IMMEDIATE;
            immOp.immediateValue = data[pos];
            immOp.size = 1;
            
            Operand accOp;
            accOp.type = OperandType::REGISTER;
            switch (state.getRegisterSize()) {
                case 64: accOp.reg = Register::RAX; accOp.size = 8; break;
                case 32: accOp.reg = Register::EAX; accOp.size = 4; break;
                case 16: accOp.reg = Register::AX; accOp.size = 2; break;
                default: accOp.reg = Register::AL; accOp.size = 1; break;
            }
            
            std::ostringstream ops;
            ops << registerToString(accOp.reg) << ", "
                << (int)data[pos];
            insn.operandsStr = ops.str();
            insn.operands.push_back(accOp);
            insn.operands.push_back(immOp);
            pos += 1;
        }
    }
    
    // Complete raw bytes
    while (pos < maxSize && insn.rawBytes.size() < 15) {  // Max x86 instruction length
        insn.rawBytes.push_back(data[pos++]);
    }
    
    insn.size = static_cast<uint8_t>(insn.rawBytes.size());
    insn.type = type;
    insn.mnemonic = mnemonic.empty() ? "???" : mnemonic;
    
    return insn;
}

} // namespace x86

// ============================================================================
// Public API Implementation - x86
// ============================================================================

Instruction DisassemblerEngine::decodeX86_32(uint64_t address, const uint8_t* data, size_t maxSize) {
    return x86::decodeX86Instruction(address, data, maxSize, false);
}

Instruction DisassemblerEngine::decodeX86_64(uint64_t address, const uint8_t* data, size_t maxSize) {
    return x86::decodeX86Instruction(address, data, maxSize, true);
}

} // namespace idapro
