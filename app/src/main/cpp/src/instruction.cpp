/**
 * IDA Pro M - Instruction, Operand, Register Info, and Architecture
 * Supporting structures and utilities for the disassembly engine
 */

#include "idapro_engine.h"
#include <sstream>
#include <iomanip>
#include <map>

namespace idapro {

// ============================================================================
// Instruction Structure Implementation (additional methods)
// ============================================================================

Instruction::Instruction() : address(0), type(InstructionType::INVALID), 
    arch(Architecture::UNKNOWN), conditionCode(ConditionCode::AL),
    size(0), operandCount(0), isBranch(false), isCall(false), 
    isReturn(false), isConditional(false), isTerminal(false),
    hasDelaySlot(false), isThumb(false), modifiesFlags(false),
    readsFlags(false), isPrivileged(false), functionId(-1), basicBlockId(-1) {}

// ============================================================================
// Operand Structure Implementation (additional methods)
// ============================================================================

Operand::Operand() : type(OperandType::NONE), size(0), signExtended(false),
    negated(false) {
    memset(&immediateValue, 0, sizeof(immediateValue));
}

// ============================================================================
// Register Information Database
// ============================================================================

class RegisterInfoDatabase {
public:
    struct RegisterInfo {
        std::string name;
        int size;           // Size in bits
        int number;         // Register number
        enum class Category : uint8_t {
            GENERAL_PURPOSE,
            FLOATING_POINT,
            VECTOR,
            SPECIAL,
            SYSTEM,
            SEGMENT,
            DEBUG,
            CONTROL
        } category;
        
        // Aliases for this register
        std::vector<std::string> aliases;
        
        // Architecture availability
        bool availableInARM32 = false;
        bool availableInARM64 = false;
        bool availableInX86_32 = false;
        bool availableInX86_64 = false;
        
        // Special properties
        bool isStackPointer = false;
        bool isLinkRegister = false;
        bool isProgramCounter = false;
        bool isFramePointer = false;
        bool isZeroRegister = false;
        bool isConditionCodeRegister = false;
    };
    
    static const RegisterInfo& getRegisterInfo(Register reg) {
        static std::unordered_map<Register, RegisterInfo> database = initializeDatabase();
        auto it = database.find(reg);
        if (it != database.end()) {
            return it->second;
        }
        static RegisterInfo unknown = {"???", 0, 0, RegisterInfo::Category::GENERAL_PURPOSE};
        return unknown;
    }
    
private:
    static std::unordered_map<Register, RegisterInfo> initializeDatabase() {
        std::unordered_map<Register, RegisterInfo> db;
        
        // ARM 32-bit registers
        for (int i = 0; i < 16; ++i) {
            RegisterInfo info;
            info.name = "r" + std::to_string(i);
            info.size = 32;
            info.number = i;
            info.category = RegisterInfo::Category::GENERAL_PURPOSE;
            info.availableInARM32 = true;
            
            switch (i) {
                case 13: info.name = "sp"; info.isStackPointer = true; break;
                case 14: info.name = "lr"; info.isLinkRegister = true; break;
                case 15: info.name = "pc"; info.isProgramCounter = true; break;
                default: break;
            }
            
            db[static_cast<Register>(i)] = info;
        }
        
        // ARM64 registers
        for (int i = 0; i < 32; ++i) {
            RegisterInfo xInfo, wInfo;
            
            xInfo.name = "x" + std::to_string(i);
            xInfo.size = 64;
            xInfo.number = i;
            xInfo.category = RegisterInfo::Category::GENERAL_PURPOSE;
            xInfo.availableInARM64 = true;
            
            wInfo.name = "w" + std::to_string(i);
            wInfo.size = 32;
            wInfo.number = i;
            wInfo.category = RegisterInfo::Category::GENERAL_PURPOSE;
            wInfo.availableInARM64 = true;
            
            switch (i) {
                case 29: xInfo.name = "fp"; wInfo.name = "fp"; xInfo.isFramePointer = true; wInfo.isFramePointer = true; break;
                case 30: xInfo.name = "lr"; wInfo.name = "lr"; xInfo.isLinkRegister = true; wInfo.isLinkRegister = true; break;
                case 31: xInfo.name = "sp"; wInfo.name = "xzr"; xInfo.isStackPointer = true; wInfo.isZeroRegister = true; break;
                default: break;
            }
            
            db[static_cast<Register>(i + Register::X0)] = xInfo;
            db[static_cast<Register>(i + Register::W0)] = wInfo;
        }
        
        // ARM SIMD/Vector registers
        for (int i = 0; i < 32; ++i) {
            RegisterInfo qInfo, dInfo, sInfo, hInfo;
            
            qInfo.name = "q" + std::to_string(i); qInfo.size = 128;
            dInfo.name = "d" + std::to_string(i); dInfo.size = 64;
            sInfo.name = "s" + std::to_string(i); sInfo.size = 32;
            hInfo.name = "h" + std::to_string(i); hInfo.size = 16;
            
            qInfo.category = dInfo.category = sInfo.category = hInfo.category = 
                RegisterInfo::Category::VECTOR;
            qInfo.availableInARM64 = dInfo.availableInARM64 = sInfo.availableInARM64 = true;
            qInfo.availableInARM32 = dInfo.availableInARM32 = sInfo.availableInARM32 = true;
            
            db[static_cast<Register>(i + Register::Q0)] = qInfo;
            db[static_cast<Register>(i + Register::D0)] = dInfo;
            db[static_cast<Register>(i + Register::S0)] = sInfo;
            db[static_cast<Register>(i + Register::H0)] = hInfo;
        }
        
        // x86 registers
        struct { const char* name8; const char* name16; const char* name32; const char* name64; int num; } x86Regs[] = {
            {"al", "ax", "eax", "rax", 0},
            {"cl", "cx", "ecx", "rcx", 1},
            {"dl", "dx", "edx", "rdx", 2},
            {"bl", "bx", "ebx", "rbx", 3},
            {"spl", "sp", "esp", "rsp", 4},  // Stack pointer
            {"bpl", "bp", "ebp", "rbp", 5},  // Frame pointer
            {"sil", "si", "esi", "rsi", 6},
            {"dil", "di", "edi", "rdi", 7}
        };
        
        for (auto& reg : x86Regs) {
            RegisterInfo r8, r16, r32, r64;
            
            r8.name = reg.name8; r8.size = 8; r8.number = reg.num;
            r16.name = reg.name16; r16.size = 16; r16.number = reg.num;
            r32.name = reg.name32; r32.size = 32; r32.number = reg.num;
            r64.name = reg.name64; r64.size = 64; r64.number = reg.num;
            
            r8.category = r16.category = r32.category = r64.category = 
                RegisterInfo::Category::GENERAL_PURPOSE;
            r8.availableInX86_32 = r16.availableInX86_32 = r32.availableInX86_32 = true;
            r8.availableInX86_64 = r16.availableInX86_64 = r32.availableInX86_64 = r64.availableInX86_64 = true;
            
            if (reg.num == 4) {
                r8.isStackPointer = r16.isStackPointer = r32.isStackPointer = r64.isStackPointer = true;
            }
            if (reg.num == 5) {
                r8.isFramePointer = r16.isFramePointer = r32.isFramePointer = r64.isFramePointer = true;
            }
            
            db[static_cast<Register>(reg.num + Register::AL)] = r8;
            db[static_cast<Register>(reg.num + Register::AX)] = r16;
            db[static_cast<Register>(reg.num + Register::EAX)] = r32;
            db[static_cast<Register>(reg.num + Register::RAX)] = r64;
        }
        
        // x86 special registers
        RegisterInfo eip, rip, eflags, rflags;
        eip.name = "eip"; eip.size = 32; eip.category = RegisterInfo::Category::SPECIAL;
        eip.isProgramCounter = true; eip.availableInX86_32 = true;
        
        rip.name = "rip"; rip.size = 64; rip.category = RegisterInfo::Category::SPECIAL;
        rip.isProgramCounter = true; rip.availableInX86_64 = true;
        
        eflags.name = "eflags"; eflags.size = 32; eflags.category = RegisterInfo::Category::SPECIAL;
        eflags.isConditionCodeRegister = true; eflags.availableInX86_32 = true;
        
        rflags.name = "rflags"; rflags.size = 64; rflags.category = RegisterInfo::Category::SPECIAL;
        rflags.isConditionCodeRegister = true; rflags.availableInX86_64 = true;
        
        db[Register::EIP] = eip;
        db[Register::RIP] = rip;
        db[Register::EFLAGS] = eflags;
        db[Register::RFLAGS] = rflags;
        
        // Segment registers
        const char* segNames[] = {"es", "cs", "ss", "ds", "fs", "gs"};
        for (int i = 0; i < 6; ++i) {
            RegisterInfo seg;
            seg.name = segNames[i];
            seg.size = 16;
            seg.number = i;
            seg.category = RegisterInfo::Category::SEGMENT;
            seg.availableInX86_32 = seg.availableInX86_64 = true;
            db[static_cast<Register>(i + Register::ES)] = seg;
        }
        
        // XMM registers
        for (int i = 0; i < 32; ++i) {
            RegisterInfo xmm;
            xmm.name = "xmm" + std::to_string(i);
            xmm.size = 128;
            xmm.number = i;
            xmm.category = RegisterInfo::Category::VECTOR;
            xmm.availableInX86_32 = (i < 8);
            xmm.availableInX86_64 = true;
            db[static_cast<Register>(i + Register::XMM0)] = xmm;
        }
        
        // Special registers
        RegisterInfo none, zero, flags, cpsr, apsr, nzcv, fp, spGeneric, lrGeneric, pcGeneric;
        none.name = "(none)"; none.size = 0; none.category = RegisterInfo::Category::SPECIAL;
        zero.name = "zero/xzr"; zero.size = 64; zero.isZeroRegister = true; zero.category = RegisterInfo::Category::SPECIAL;
        flags.name = "flags"; flags.size = 32; flags.isConditionCodeRegister = true; flags.category = RegisterInfo::Category::SPECIAL;
        cpsr.name = "cpsr"; cpsr.size = 32; cpsr.isConditionCodeRegister = true; cpsr.category = RegisterInfo::Category::SYSTEM;
        apsr.name = "apsr"; apsr.size = 32; apsr.isConditionCodeRegister = true; apsr.category = RegisterInfo::Category::SYSTEM;
        nzcv.name = "nzcv"; nzcv.size = 4; nzcv.isConditionCodeRegister = true; nzcv.category = RegisterInfo::Category::SPECIAL;
        fp.name = "fp"; fp.size = 32; fp.isFramePointer = true; fp.category = RegisterInfo::Category::SPECIAL;
        spGeneric.name = "sp"; spGeneric.size = 0; spGeneric.isStackPointer = true; spGeneric.category = RegisterInfo::Category::SPECIAL;
        lrGeneric.name = "lr"; lrGeneric.size = 0; lrGeneric.isLinkRegister = true; lrGeneric.category = RegisterInfo::Category::SPECIAL;
        pcGeneric.name = "pc"; pcGeneric.size = 0; pcGeneric.isProgramCounter = true; pcGeneric.category = RegisterInfo::Category::SPECIAL;
        
        db[Register::NONE] = none;
        db[Register::ZERO] = zero;
        db[Register::FLAGS] = flags;
        db[Register::CPSR] = cpsr;
        db[Register::APSR] = apsr;
        db[Register::NZCV] = nzcv;
        db[Register::FP] = fp;
        db[Register::SP_GENERIC] = spGeneric;
        db[Register::LR_GENERIC] = lrGeneric;
        db[Register::PC_GENERIC] = pcGeneric;
        
        return db;
    }
};

// ============================================================================
// Architecture Information
// ============================================================================

struct ArchitectureInfo {
    Architecture arch;
    std::string name;
    std::string description;
    
    // Instruction characteristics
    uint8_t minInstructionSize;
    uint8_t maxInstructionSize;
    bool fixedInstructionSize;
    bool variableLengthEncoding;
    
    // Endianness
    bool defaultLittleEndian;
    bool supportsBigEndian;
    
    // Registers
    Register stackPointer;
    Register linkRegister;
    Register programCounter;
    Register framePointer;
    Register conditionFlags;
    
    // Address space
    uint64_t maxAddress;
    uint8_t addressSize;
    
    // Features
    bool hasConditionCodes;
    bool hasThumbMode;
    bool hasSIMD;
    bool hasVirtualizationSupport;
    
    static const ArchitectureInfo& getInfo(Architecture arch) {
        static std::unordered_map<Architecture, ArchitectureInfo> infos = initializeInfos();
        auto it = infos.find(arch);
        if (it != infos.end()) {
            return it->second;
        }
        static ArchitectureInfo unknown = {Architecture::UNKNOWN, "Unknown", "Unknown architecture",
            1, 1, true, false, true, false, Register::NONE, Register::NONE, 
            Register::NONE, Register::NONE, Register::NONE, 0xFFFFFFFFULL, 32,
            false, false, false, false};
        return unknown;
    }

private:
    static std::unordered_map<Architecture, ArchitectureInfo> initializeInfos() {
        std::unordered_map<Architecture, ArchitectureInfo> infos;
        
        // ARM32
        infos[Architecture::ARM32] = {
            Architecture::ARM32, "ARM32", "ARM 32-bit (AArch32)",
            4, 4, true, false,
            true, true,
            Register::SP, Register::LR, Register::PC, Register::R11, Register::CPSR,
            0xFFFFFFFFULL, 32,
            true, true, true, false
        };
        
        // ARM64
        infos[Architecture::ARM64] = {
            Architecture::ARM64, "AArch64", "ARM 64-bit (AArch64)",
            4, 4, true, false,
            true, true,
            Register::SP64, Register::X30, Register::PC64, Register::X29, Register::NONE,
            0xFFFFFFFFFFFFFFFFULL, 64,
            false, false, true, true
        };
        
        // Thumb
        infos[Architecture::THUMB] = {
            Architecture::THUMB, "Thumb", "Thumb/Thumb-2",
            2, 4, false, true,
            true, true,
            Register::SP, Register::LR, Register::PC, Register::R11, Register::CPSR,
            0xFFFFFFFFULL, 32,
            true, true, false, false
        };
        
        // x86-32
        infos[Architecture::X86_32] = {
            Architecture::X86_32, "x86-32", "Intel x86 32-bit",
            1, 15, false, true,
            true, false,
            Register::ESP, Register::NONE, Register::EIP, Register::EBP, Register::EFLAGS,
            0xFFFFFFFFULL, 32,
            false, false, true, true
        };
        
        // x86-64
        infos[Architecture::X86_64] = {
            Architecture::X86_64, "x86-64", "AMD64 / Intel 64",
            1, 15, false, true,
            true, false,
            Register::RSP, Register::NONE, Register::RIP, Register::RBP, Register::RFLAGS,
            0xFFFFFFFFFFFFFFFFULL, 64,
            false, false, true, true
        };
        
        // MIPS
        infos[Architecture::MIPS] = {
            Architecture::MIPS, "MIPS", "MIPS I-V",
            4, 4, true, false,
            true, true,
            Register(29), Register(31), Register(PC_GENERIC), Register(30), Register::NONE,
            0xFFFFFFFFULL, 32,
            false, false, false, false
        };
        
        return infos;
    }
};

} // namespace idapro
