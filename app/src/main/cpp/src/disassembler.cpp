/**
 * IDA Pro M - Native Disassembly Engine
 * Main Implementation
 * Version 3.0.0
 * 
 * Complete implementation of the disassembler engine supporting
 * ARM, ARM64, Thumb, x86, and x86-64 architectures.
 */

#include "idapro_engine.h"
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <chrono>
#include <regex>
#include <set>
#include <stack>
#include <queue>
#include <map>

#ifdef ANDROID
#include <android/log.h>
#define LOG_TAG "IDAProEngine"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) printf(__VA_ARGS__); printf("\n")
#define LOGE(...) printf(__VA_ARGS__); printf("\n")
#define LOGW(...) printf(__VA_ARGS__); printf("\n")
#endif

namespace idapro {

// ============================================================================
// String Conversion Functions
// ============================================================================

const char* architectureToString(Architecture arch) {
    switch (arch) {
        case Architecture::ARM32:    return "ARM32";
        case Architecture::ARM64:    return "AArch64";
        case Architecture::THUMB:    return "Thumb";
        case Architecture::X86_32:   return "x86";
        case Architecture::X86_64:   return "x86-64";
        case Architecture::MIPS:     return "MIPS";
        case Architecture::MIPS64:   return "MIPS64";
        default:                    return "Unknown";
    }
}

const char* instructionTypeToString(InstructionType type) {
    switch (type) {
        case InstructionType::NOP:       return "nop";
        case InstructionType::MOV:       return "mov";
        case InstructionType::MOVW:      return "movw";
        case InstructionType::MOVT:      return "movt";
        case InstructionType::MVN:       return "mvn";
        case InstructionType::ADD:       return "add";
        case InstructionType::SUB:       return "sub";
        case InstructionType::MUL:       return "mul";
        case InstructionType::DIV:       return "div";
        case InstructionType::MOD:       return "mod";
        case InstructionType::ADC:       return "adc";
        case InstructionType::SBC:       return "sbc";
        case InstructionType::RSB:       return "rsb";
        case InstructionType::RSC:       return "rsc";
        case InstructionType::NEG:       return "neg";
        case InstructionType::AND:       return "and";
        case InstructionType::ORR:       return "orr";
        case InstructionType::EOR:       return "eor";
        case InstructionType::BIC:       return "bic";
        case InstructionType::ORN:       return "orn";
        case InstructionType::NOT:       return "not";
        case InstructionType::SHL:       return "lsl";
        case InstructionType::SHR:       return "lsr";
        case InstructionType::SAR:       return "asr";
        case InstructionType::ROL:       return "rol";
        case InstructionType::ROR:       return "ror";
        case InstructionType::CMP:       return "cmp";
        case InstructionType::CMN:       return "cmn";
        case InstructionType::TST:       return "tst";
        case InstructionType::TEQ:       return "teq";
        case InstructionType::B:         return "b";
        case InstructionType::BL:        return "bl";
        case InstructionType::BX:        return "bx";
        case InstructionType::BLX:       return "blx";
        case InstructionType::CBZ:       return "cbz";
        case InstructionType::CBNZ:      return "cbnz";
        case InstructionType::TBZ:       return "tbz";
        case InstructionType::TBNZ:      return "tbnz";
        case InstructionType::RET:       return "ret";
        case InstructionType::CALL:      return "call";
        case InstructionType::JMP:       return "jmp";
        case InstructionType::LDR:       return "ldr";
        case InstructionType::STR:       return "str";
        case InstructionType::LDM:       return "ldm";
        case InstructionType::STM:       return "stm";
        case InstructionType::PUSH:      return "push";
        case InstructionType::POP:       return "pop";
        case InstructionType::LDRB:      return "ldrb";
        case InstructionType::STRB:      return "strb";
        case InstructionType::LDRH:      return "ldrh";
        case InstructionType::STRH:      return "strh";
        case InstructionType::SVC:       return "svc";
        case InstructionType::DMB:       return "dmb";
        case InstructionType::DSB:       return "dsb";
        case InstructionType::ISB:       return "isb";
        case InstructionType::LEA:       return "lea";
        case InstructionType::INT:       return "int";
        case InstructionType::INT3:      return "int3";
        case InstructionType::DB:        return "db";
        case InstructionType::DW:        return "dw";
        case InstructionType::DD:        return "dd";
        case InstructionType::DQ:        return "dq";
        default:                        return "???";
    }
}

bool isBranchInstruction(InstructionType type) {
    switch (type) {
        case InstructionType::B:
        case InstructionType::BX:
        case InstructionType::CBZ:
        case InstructionType::CBNZ:
        case InstructionType::TBZ:
        case InstructionType::TBNZ:
        case InstructionType::JMP:
            return true;
        default:
            return false;
    }
}

bool isCallInstruction(InstructionType type) {
    switch (type) {
        case InstructionType::BL:
        case InstructionType::BLX:
        case InstructionType::CALL:
            return true;
        default:
            return false;
    }
}

bool isReturnInstruction(InstructionType type) {
    switch (type) {
        case InstructionType::RET:
        case InstructionType::BX:  // Can be return when target is LR
            return true;
        default:
            return false;
    }
}

bool isConditionalBranch(InstructionType type) {
    // Most branches are conditional in ARM/Thumb mode
    // x86 conditional jumps are separate opcodes
    switch (type) {
        case InstructionType::CBZ:
        case InstructionType::CBNZ:
        case InstructionType::TBZ:
        case InstructionType::TBNZ:
            return true;
        default:
            return false;  // ARM B/BL can have condition codes
    }
}

const char* conditionCodeToString(ConditionCode cc) {
    switch (cc) {
        case ConditionCode::EQ:  return "eq";
        case ConditionCode::NE:  return "ne";
        case ConditionCode::CS:  return "cs";
        case ConditionCode::CC:  return "cc";
        case ConditionCode::MI:  return "mi";
        case ConditionCode::PL:  return "pl";
        case ConditionCode::VS:  return "vs";
        case ConditionCode::VC:  return "vc";
        case ConditionCode::HI:  return "hi";
        case ConditionCode::LS:  return "ls";
        case ConditionCode::GE:  return "ge";
        case ConditionCode::LT:  return "lt";
        case ConditionCode::GT:  return "gt";
        case ConditionCode::LE:  return "le";
        case ConditionCode::AL:  return "";
        case ConditionCode::NV:  return "nv";
        default:                 return "";
    }
}

const char* shiftTypeToString(ShiftType type) {
    switch (type) {
        case ShiftType::LSL: return "lsl";
        case ShiftType::LSR: return "lsr";
        case ShiftType::ASR: return "asr";
        case ShiftType::ROR: return "ror";
        case ShiftType::RRX: return "rrx";
        case ShiftType::MSL: return "msl";
        default:             return "";
    }
}

// ============================================================================
// Register Functions
// ============================================================================

const char* registerToString(Register reg, bool wide) {
    switch (reg) {
        // ARM 32-bit registers
        case Register::R0:  return "r0";   case Register::R1:  return "r1";
        case Register::R2:  return "r2";   case Register::R3:  return "r3";
        case Register::R4:  return "r4";   case Register::R5:  return "r5";
        case Register::R6:  return "r6";   case Register::R7:  return "r7";
        case Register::R8:  return "r8";   case Register::R9:  return "r9";
        case Register::R10: return "r10";  case Register::R11: return "r11";
        case Register::R12: return "r12";  case Register::SP:  return "sp";
        case Register::LR:  return "lr";   case Register::PC:  return "pc";
        
        // ARM64 registers
        case Register::X0:  return wide ? "x0" : "w0";
        case Register::X1:  return wide ? "x1" : "w1";
        case Register::X2:  return wide ? "x2" : "w2";
        case Register::X3:  return wide ? "x3" : "w3";
        case Register::X4:  return wide ? "x4" : "w4";
        case Register::X5:  return wide ? "x5" : "w5";
        case Register::X6:  return wide ? "x6" : "w6";
        case Register::X7:  return wide ? "x7" : "w7";
        case Register::X8:  return wide ? "x8" : "w8";
        case Register::X9:  return wide ? "x9" : "w9";
        case Register::X10: return wide ? "x10" : "w10";
        case Register::X11: return wide ? "x11" : "w11";
        case Register::X12: return wide ? "x12" : "w12";
        case Register::X13: return wide ? "x13" : "w13";
        case Register::X14: return wide ? "x14" : "w14";
        case Register::X15: return wide ? "x15" : "w15";
        case Register::X16: return wide ? "x16" : "w16";
        case Register::X17: return wide ? "x17" : "w17";
        case Register::X18: return wide ? "x18" : "w18";
        case Register::X19: return wide ? "x19" : "w19";
        case Register::X20: return wide ? "x20" : "w20";
        case Register::X21: return wide ? "x21" : "w21";
        case Register::X22: return wide ? "x22" : "w22";
        case Register::X23: return wide ? "x23" : "w23";
        case Register::X24: return wide ? "x24" : "w24";
        case Register::X25: return wide ? "x25" : "w25";
        case Register::X26: return wide ? "x26" : "w26";
        case Register::X27: return wide ? "x27" : "w27";
        case Register::X28: return wide ? "x28" : "w28";
        case Register::X29: return wide ? "x29" : "w29";
        case Register::X30: return wide ? "x30" : "w30";
        case Register::SP64: return "sp";
        case Register::PC64: return "pc";
        
        // Special registers
        case Register::NONE:     return "(none)";
        case Register::ZERO:     return "xzr";
        case Register::FLAGS:    return "flags";
        case Register::CPSR:     return "cpsr";
        case Register::APSR:     return "apsr";
        case Register::NZCV:     return "nzcv";
        case Register::FP:       return "fp";
        case Register::SP_GENERIC: return "sp";
        case Register::LR_GENERIC: return "lr";
        case Register::PC_GENERIC: return "pc";
        
        // x86 32-bit registers
        case Register::EAX: return "eax";  case Register::EBX: return "ebx";
        case Register::ECX: return "ecx";  case Register::EDX: return "edx";
        case Register::ESI: return "esi";  case Register::EDI: return "edi";
        case Register::EBP: return "ebp";  case Register::ESP: return "esp";
        case Register::EIP: return "eip";  case Register::EFLAGS: return "eflags";
        
        // x86-64 registers
        case Register::RAX: return "rax";  case Register::RBX: return "rbx";
        case Register::RCX: return "rcx";  case Register::RDX: return "rdx";
        case Register::RSI: return "rsi";  case Register::RDI: return "rdi";
        case Register::RBP: return "rbp";  case Register::RSP: return "rsp";
        case Register::R8:  return "r8";   case Register::R9:  return "r9";
        case Register::R10: return "r10";  case Register::R11: return "r11";
        case Register::R12: return "r12";  case Register::R13: return "r13";
        case Register::R14: return "r14";  case Register::R15: return "r15";
        case Register::RIP: return "rip";  case Register::RFLAGS: return "rflags";
        
        // x86 8-bit registers
        case Register::AL: return "al";   case Register::BL: return "bl";
        case Register::CL: return "cl";   case Register::DL: return "dl";
        case Register::AH: return "ah";   case Register::BH: return "bh";
        case Register::CH: return "ch";   case Register::DH: return "dh";
        
        // x86 16-bit registers
        case Register::AX: return "ax";   case Register::BX: return "bx";
        case Register::CX: return "cx";   case Register::DX: return "dx";
        case Register::SI: return "si";   case Register::DI: return "di";
        case Register::BP: return "bp";   case Register::SP: return "sp";
        
        // Segment registers
        case Register::ES: return "es";   case Register::CS: return "cs";
        case Register::SS: return "ss";   case Register::DS: return "ds";
        case Register::FS: return "fs";   case Register::GS: return "gs";
        
        // SIMD registers
        case Register::D0:  return "d0";  case Register::D1:  return "d1";
        case Register::D2:  return "d2";  case Register::D3:  return "d3";
        case Register::D4:  return "d4";  case Register::D5:  return "d5";
        case Register::D6:  return "d6";  case Register::D7:  return "d7";
        case Register::D8:  return "d8";  case Register::D9:  return "d9";
        case Register::D10: return "d10"; case Register::D11: return "d11";
        case Register::D12: return "d12"; case Register::D13: return "d13";
        case Register::D14: return "d14"; case Register::D15: return "d15";
        case Register::D16: return "d16"; case Register::D17: return "d17";
        case Register::D18: return "d18"; case Register::D19: return "d19";
        case Register::D20: return "d20"; case Register::D21: return "d21";
        case Register::D22: return "d22"; case Register::D23: return "d23";
        case Register::D24: return "d24"; case Register::D25: return "d25";
        case Register::D26: return "d26"; case Register::D27: return "d27";
        case Register::D28: return "d28"; case Register::D29: return "d29";
        case Register::D30: return "d30"; case Register::D31: return "d31";
        
        case Register::S0:  return "s0";  case Register::S1:  return "s1";
        case Register::S2:  return "s2";  case Register::S3:  return "s3";
        case Register::S4:  return "s4";  case Register::S5:  return "s5";
        case Register::S6:  return "s6";  case Register::S7:  return "s7";
        case Register::S8:  return "s8";  case Register::S9:  return "s9";
        case Register::S10: return "s10"; case Register::S11: return "s11";
        case Register::S12: return "s12"; case Register::S13: return "s13";
        case Register::S14: return "s14"; case Register::S15: return "s15";
        case Register::S16: return "s16"; case Register::S17: return "s17";
        case Register::S18: return "s18"; case Register::S19: return "s19";
        case Register::S20: return "s20"; case Register::S21: return "s21";
        case Register::S22: return "s22"; case Register::S23: return "s23";
        case Register::S24: return "s24"; case Register::S25: return "s25";
        case Register::S26: return "s26"; case Register::S27: return "s27";
        case Register::S28: return "s28"; case Register::S29: return "s29";
        case Register::S30: return "s30"; case Register::S31: return "s31";
        
        case Register::Q0:  return "q0";  case Register::Q1:  return "q1";
        case Register::Q2:  return "q2";  case Register::Q3:  return "q3";
        case Register::Q4:  return "q4";  case Register::Q5:  return "q5";
        case Register::Q6:  return "q6";  case Register::Q7:  return "q7";
        case Register::Q8:  return "q8";  case Register::Q9:  return "q9";
        case Register::Q10: return "q10"; case Register::Q11: return "q11";
        case Register::Q12: return "q12"; case Register::Q13: return "q13";
        case Register::Q14: return "q14"; case Register::Q15: return "q15";
        case Register::Q16: return "q16"; case Register::Q17: return "q17";
        case Register::Q18: return "q18"; case Register::Q19: return "q19";
        case Register::Q20: return "q20"; case Register::Q21: return "q21";
        case Register::Q22: return "q22"; case Register::Q23: return "q23";
        case Register::Q24: return "q24"; case Register::Q25: return "q25";
        case Register::Q26: return "q26"; case Register::Q27: return "q27";
        case Register::Q28: return "q28"; case Register::Q29: return "q29";
        case Register::Q30: return "q30"; case Register::Q31: return "q31";
        
        // x86 SIMD
        case Register::XMM0:  return "xmm0";  case Register::XMM1:  return "xmm1";
        case Register::XMM2:  return "xmm2";  case Register::XMM3:  return "xmm3";
        case Register::XMM4:  return "xmm4";  case Register::XMM5:  return "xmm5";
        case Register::XMM6:  return "xmm6";  case Register::XMM7:  return "xmm7";
        case Register::XMM8:  return "xmm8";  case Register::XMM9:  return "xmm9";
        case Register::XMM10: return "xmm10"; case Register::XMM11: return "xmm11";
        case Register::XMM12: return "xmm12"; case Register::XMM13: return "xmm13";
        case Register::XMM14: return "xmm14"; case Register::XMM15: return "xmm15";
        case Register::XMM16: return "xmm16"; case Register::XMM17: return "xmm17";
        case Register::XMM18: return "xmm18"; case Register::XMM19: return "xmm19";
        case Register::XMM20: return "xmm20"; case Register::XMM21: return "xmm21";
        case Register::XMM22: return "xmm22"; case Register::XMM23: return "xmm23";
        case Register::XMM24: return "xmm24"; case Register::XMM25: return "xmm25";
        case Register::XMM26: return "xmm26"; case Register::XMM27: return "xmm27";
        case Register::XMM28: return "xmm28"; case Register::XMM29: return "xmm29";
        case Register::XMM30: return "xmm30"; case Register::XMM31: return "xmm31";
        
        default: return "???";
    }
}

Register getStackPointer(Architecture arch) {
    switch (arch) {
        case Architecture::ARM32:
        case Architecture::THUMB:
            return Register::SP;
        case Architecture::ARM64:
            return Register::SP64;
        case Architecture::X86_32:
            return Register::ESP;
        case Architecture::X86_64:
            return Register::RSP;
        default:
            return Register::NONE;
    }
}

Register getLinkRegister(Architecture arch) {
    switch (arch) {
        case Architecture::ARM32:
        case Architecture::THUMB:
            return Register::LR;
        case Architecture::ARM64:
            return Register::X30;
        default:
            return Register::NONE;  // x86 uses stack for return address
    }
}

Register getProgramCounter(Architecture arch) {
    switch (arch) {
        case Architecture::ARM32:
        case Architecture::THUMB:
            return Register::PC;
        case Architecture::ARM64:
            return Register::PC64;
        case Architecture::X86_32:
            return Register::EIP;
        case Architecture::X86_64:
            return Register::RIP;
        default:
            return Register::NONE;
    }
}

Register getFramePointer(Architecture arch) {
    switch (arch) {
        case Architecture::ARM32:
        case Architecture::THUMB:
            return Register::R11;  // FP in AAPCS
        case Architecture::ARM64:
            return Register::X29;
        case Architecture::X86_32:
            return Register::EBP;
        case Architecture::X86_64:
            return Register::RBP;
        default:
            return Register::NONE;
    }
}

// ============================================================================
// Operand Methods
// ============================================================================

std::string Operand::toString() const {
    std::ostringstream oss;
    
    switch (type) {
        case OperandType::REGISTER:
            oss << registerToString(reg);
            break;
            
        case OperandType::IMMEDIATE:
            if (immediateValue >= -256 && immediateValue <= 255) {
                oss << "#" << immediateValue;
            } else {
                oss << "#0x" << std::hex << immediateValue;
            }
            break;
            
        case OperandType::FLOAT_IMMEDIATE:
            oss << floatValue;
            break;
            
        case OperandType::MEMORY:
            oss << "[";
            if (memory.baseReg != Register::NONE) {
                oss << registerToString(memory.baseReg);
                if (memory.offset != 0 || memory.indexReg != Register::NONE) {
                    oss << ", ";
                }
            }
            if (memory.indexReg != Register::NONE) {
                oss << registerToString(memory.indexReg);
                if (memory.scale > 1) {
                    oss << ", lsl #" << (int)memory.scale;
                }
            }
            if (memory.offset != 0 && memory.indexReg == Register::NONE) {
                if (memory.offset >= -256 && memory.offset <= 255) {
                    oss << (memory.offset >= 0 ? "" : "") << "#" << memory.offset;
                } else {
                    oss << "#0x" << std::hex << memory.offset;
                }
            } else if (memory.offset != 0 && memory.indexReg != Register::NONE) {
                oss << ", #" << std::hex << memory.offset;
            }
            oss << "]";
            if (memory.writeback) oss << "!";
            break;
            
        case OperandType::LABEL:
            oss << label;  // This would need to be stored separately
            break;
            
        case OperandType::SHIFTED_REGISTER: {
            oss << registerToString(shiftedReg.reg);
            if (shiftedReg.shiftType != ShiftType::LSL || shiftedReg.shiftAmount != 0) {
                oss << ", " << shiftTypeToString(shiftedReg.shiftType);
                if (shiftedReg.shiftAmount > 0) {
                    oss << " #" << (int)shiftedReg.shiftAmount;
                }
            }
            break;
        }
            
        case OperandType::CONDITION_CODE:
            oss << conditionCodeToString(static_cast<ConditionCode>(immediateValue));
            break;
            
        case OperandType::RELATIVE_OFFSET:
            oss << "0x" << std::hex << immediateValue;
            break;
            
        case OperandType::PC_RELATIVE:
            oss << "pc + 0x" << std::hex << immediateValue;
            break;
            
        default:
            oss << "?";
    }
    
    return oss.str();
}

std::string Operand::toHexString() const {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setfill('0');
    
    switch (size) {
        case 1: oss << std::setw(2) << (uint32_t)(immediateValue & 0xFF); break;
        case 2: oss << std::setw(4) << (uint32_t)(immediateValue & 0xFFFF); break;
        case 4: oss << std::setw(8) << (uint32_t)(immediateValue & 0xFFFFFFFF); break;
        case 8: oss << std::setw(16) << immediateValue; break;
        default: oss << immediateValue; break;
    }
    
    return oss.str();
}

// ============================================================================
// Instruction Methods
// ============================================================================

std::string Instruction::toString(bool hexAddresses) const {
    std::ostringstream oss;
    
    // Address
    if (hexAddresses) {
        oss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(address > 0xFFFFFFFFULL ? 16 : 8) << address;
    } else {
        oss << address;
    }
    oss << "    ";
    
    // Raw bytes
    oss << toHexBytes();
    for (int i = rawBytes.size(); i < 8; ++i) {
        oss << "   ";
    }
    oss << " ";
    
    // Mnemonic with condition code
    oss << mnemonic;
    if (conditionCode != ConditionCode::AL && conditionCode != ConditionCode::NV) {
        oss << conditionCodeToString(conditionCode);
    }
    
    // Operands
    if (!operandsStr.empty()) {
        oss << "\t" << operandsStr;
    }
    
    // Comment
    if (!comment.empty()) {
        oss << "\t; " << comment;
    }
    
    return oss.str();
}

std::string Instruction::toHexBytes() const {
    std::ostringstream oss;
    for (size_t i = 0; i < rawBytes.size(); ++i) {
        if (i > 0) oss << " ";
        oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) 
            << (uint32_t)rawBytes[i];
    }
    return oss.str();
}

std::string Instruction::toDisassemblyLine() const {
    std::ostringstream oss;
    
    // Address column (16 chars)
    oss << std::left << std::setfill(' ') << std::setw(16)
        << utils::formatAddress(address);
    
    // Bytes column (24 chars)
    std::string bytes = toHexBytes();
    oss << std::setw(24) << bytes.substr(0, 24);
    
    // Mnemonic column (10 chars)
    std::string mnem = mnemonic;
    if (conditionCode != ConditionCode::AL) {
        mnem += conditionCodeToString(conditionCode);
    }
    oss << std::setw(10) << mnem;
    
    // Operands
    if (!operandsStr.empty()) {
        oss << " " << operandsStr;
    }
    
    return oss.str();
}

// ============================================================================
// Basic Block Methods
// ============================================================================

std::string BasicBlock::label() const {
    if (!instructions.empty()) {
        auto& first = instructions.front();
        if (!first.label.empty()) {
            return first.label;
        }
    }
    return "block_" + std::to_string(id);
}

// ============================================================================
// Function Methods
// ============================================================================

std::string Function::getDisplayName() const {
    if (!demangledName.empty()) {
        return demangledName;
    }
    if (!name.empty()) {
        return name;
    }
    return "sub_" + utils::formatAddress(startAddress, false);
}

// ============================================================================
// StringEntry Methods
// ============================================================================

std::string StringEntry::toString() const {
    std::ostringstream oss;
    oss << utils::formatAddress(address) << ": \"";
    
    // Escape special characters
    for (char c : value) {
        switch (c) {
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            default:
                if (c >= 32 && c < 127) {
                    oss << c;
                } else {
                    oss << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                        << (unsigned)(unsigned char)c;
                }
        }
    }
    oss << "\" (" << length << " chars)";
    return oss.str();
}

// ============================================================================
// Xref Methods
// ============================================================================

std::string Xref::toString() const {
    std::ostringstream oss;
    oss << utils::formatAddress(from) << " -> " 
        << utils::formatAddress(to) << " [";
    
    switch (type) {
        case Type::DATA:    oss << "data"; break;
        case Type::CODE:    oss << "code"; break;
        case Type::CALL:    oss << "call"; break;
        case Type::STRING:  oss << "str"; break;
        case Type::IMPORT:  oss << "import"; break;
        case Type::EXPORT:  oss << "export"; break;
        case Type::READ:    oss << "read"; break;
        case Type::WRITE:   oss << "write"; break;
        default:           oss << "unknown"; break;
    }
    
    oss << "]";
    return oss.str();
}

// ============================================================================
// BinaryInfo Methods
// ============================================================================

std::string BinaryInfo::getFormatString() const {
    switch (format) {
        case Format::ELF:    return "ELF";
        case Format::PE:     return "PE (Windows)";
        case Format::MACH_O: return "Mach-O (macOS/iOS)";
        case Format::DEX:    return "DEX (Android)";
        case Format::RAW:    return "Raw Binary";
        case Format::COFF:   return "COFF";
        case Format::OLE:    return "OLE/COM";
        default:             return "Unknown";
    }
}

std::string BinaryInfo::getArchString() const {
    return architectureToString(arch) + std::string(is64Bit ? " 64-bit" : " 32-bit");
}

// ============================================================================
// PatternSignature Methods
// ============================================================================

bool PatternSignature::match(const uint8_t* data, size_t size) const {
    if (pattern.size() > size) return false;
    
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (mask[i] == 0xFF && data[i] != pattern[i]) {
            return false;
        }
    }
    return true;
}

std::string PatternSignature::toString() const {
    std::ostringstream oss;
    oss << name << " [" << category << "] confidence=" << confidence << "\n  Pattern: ";
    
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (i > 0) oss << " ";
        if (mask[i] == 0xFF) {
            oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
                << (uint32_t)pattern[i];
        } else {
            oss << "??";
        }
    }
    
    return oss.str();
}

// ============================================================================
// Utility Function Implementations
// ============================================================================

namespace utils {

std::string formatAddress(uint64_t addr, bool withPrefix) {
    std::ostringstream oss;
    if (withPrefix) oss << "0x";
    oss << std::hex << std::uppercase << std::setfill('0');
    
    if (addr <= 0xFFFFFFFFULL) {
        oss << std::setw(8) << addr;
    } else {
        oss << std::setw(16) << addr;
    }
    
    return oss.str();
}

std::string formatBytes(const uint8_t* data, size_t size, char separator) {
    std::ostringstream oss;
    for (size_t i = 0; i < size; ++i) {
        if (i > 0) oss << separator;
        oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
            << (uint32_t)data[i];
    }
    return oss.str();
}

std::string formatHexByte(uint8_t byte) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) 
        << (uint32_t)byte;
    return oss.str();
}

std::string formatHexWord(uint16_t word) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << word;
    return oss.str();
}

std::string formatHexDword(uint32_t dword) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << dword;
    return oss.str();
}

std::string formatHexQword(uint64_t qword) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << qword;
    return oss.str();
}

std::string computeMD5(const uint8_t* data, size_t size) {
    // Simplified MD5 placeholder - would use actual MD5 implementation
    // In production, use OpenSSL or a lightweight MD5 library
    (void)data; (void)size;
    return "md5_placeholder_" + std::to_string(size);
}

std::string computeSHA256(const uint8_t* data, size_t size) {
    // Simplified SHA256 placeholder
    (void)data; (void)size;
    return "sha256_placeholder_" + std::to_string(size);
}

std::string trimWhitespace(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

std::vector<std::string> splitString(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream iss(str);
    std::string token;
    while (std::getline(iss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

std::string toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string toUpper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

bool startsWith(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() &&
           str.compare(0, prefix.size(), prefix) == 0;
}

bool endsWith(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

template<typename T>
T swapEndian(T value) {
    union {
        T value;
        uint8_t bytes[sizeof(T)];
    } src, dst;
    
    src.value = value;
    for (size_t i = 0; i < sizeof(T); ++i) {
        dst.bytes[i] = src.bytes[sizeof(T) - 1 - i];
    }
    return dst.value;
}

uint16_t swapEndian16(uint16_t value) { return swapEndian(value); }
uint32_t swapEndian32(uint32_t value) { return swapEndian(value); }
uint64_t swapEndian64(uint64_t value) { return swapEndian(value); }

} // namespace utils

} // namespace idapro
