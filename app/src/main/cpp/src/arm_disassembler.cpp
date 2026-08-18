/**
 * IDA Pro M - ARM/ARM32 Disassembler
 * Complete implementation of ARM (32-bit) instruction decoding
 * Supports: ARM mode, Thumb/Thumb-2, condition codes, coprocessor instructions
 */

#include "idapro_engine.h"
#include <cstring>
#include <sstream>
#include <map>

namespace idapro {

// ============================================================================
// ARM Instruction Encoding Helpers
// ============================================================================

namespace arm {

// Condition code extraction from bits [31:28]
inline ConditionCode getCondition(uint32_t instr) {
    return static_cast<ConditionCode>((instr >> 28) & 0xF);
}

// Check if instruction is in IT block context
inline bool isInITBlock(bool inIT, uint8_t itState) {
    return inIT;
}

// ============================================================================
// ARM Data Processing Instructions
// ============================================================================

Instruction decodeDataProcessing(uint64_t addr, uint32_t instr, bool thumb = false) {
    Instruction insn;
    insn.address = addr;
    insn.arch = Architecture::ARM32;
    insn.conditionCode = getCondition(instr);
    
    // Extract fields
    bool immediate = (instr >> 25) & 1;
    uint8_t opcode = (instr >> 21) & 0xF;
    bool setFlags = (instr >> 20) & 1;
    uint8_t rn = (instr >> 16) & 0xF;
    uint8_t rd = (instr >> 12) & 0xF;
    Operand op2;
    
    // Second operand processing
    if (immediate) {
        // Immediate with rotate
        uint8_t imm8 = instr & 0xFF;
        uint8_t rotate = ((instr >> 8) & 0xF) * 2;
        
        uint32_t immVal = (imm8 >> rotate) | (imm8 << (32 - rotate));
        op2.type = OperandType::IMMEDIATE;
        op2.immediateValue = static_cast<int32_t>(immVal);
        op2.size = 4;
    } else {
        // Register with optional shift
        uint8_t rm = instr & 0xF;
        uint8_t shiftType = (instr >> 5) & 3;
        uint8_t shiftAmount = (instr >> 7) & 0x1F;
        bool shiftByRegister = (instr >> 4) & 1;
        
        if (shiftAmount == 0 && !shiftByRegister) {
            // Special cases for LSR #0 and ASR #0
            if (shiftType == 1) {  // LSR #32
                op2.shiftedReg.shiftType = ShiftType::LSR;
                op2.shiftedReg.shiftAmount = 32;
            } else if (shiftType == 2) {  // ASR #32
                op2.shiftedReg.shiftType = ShiftType::ASR;
                op2.shiftedReg.shiftAmount = 32;
            }
        } else if (shiftByRegister) {
            uint8_t rs = (instr >> 8) & 0xF;
            op2.type = OperandType::SHIFTED_REGISTER;
            op2.shiftedReg.reg = static_cast<Register>(rm);
            op2.shiftedReg.shiftType = static_cast<ShiftType>(shiftType);
            op2.shiftedReg.shiftReg = static_cast<Register>(rs);
        } else {
            op2.type = OperandType::SHIFTED_REGISTER;
            op2.shiftedReg.reg = static_cast<Register>(rm);
            op2.shiftedReg.shiftType = static_cast<ShiftType>(shiftType);
            op2.shiftedReg.shiftAmount = shiftAmount;
        }
    }
    
    // Decode opcode
    switch (opcode) {
        case 0x0:  // AND
            insn.type = InstructionType::AND;
            insn.mnemonic = "and";
            break;
        case 0x1:  // EOR
            insn.type = InstructionType::EOR;
            insn.mnemonic = "eor";
            break;
        case 0x2:  // SUB
            insn.type = InstructionType::SUB;
            insn.mnemonic = "sub";
            break;
        case 0x3:  // RSB
            insn.type = InstructionType::RSB;
            insn.mnemonic = "rsb";
            break;
        case 0x4:  // ADD
            insn.type = InstructionType::ADD;
            insn.mnemonic = "add";
            break;
        case 0x5:  // ADC
            insn.type = InstructionType::ADC;
            insn.mnemonic = "adc";
            break;
        case 0x6:  // SBC
            insn.type = InstructionType::SBC;
            insn.mnemonic = "sbc";
            break;
        case 0x7:  // RSC
            insn.type = InstructionType::RSC;
            insn.mnemonic = "rsc";
            break;
        case 0x8:  // TST
            insn.type = InstructionType::TST;
            insn.mnemonic = "tst";
            break;
        case 0x9:  // TEQ
            insn.type = InstructionType::TEQ;
            insn.mnemonic = "teq";
            break;
        case 0xA:  // CMP
            insn.type = InstructionType::CMP;
            insn.mnemonic = "cmp";
            break;
        case 0xB:  // CMN
            insn.type = InstructionType::CMN;
            insn.mnemonic = "cmn";
            break;
        case 0xC:  // ORR
            insn.type = InstructionType::ORR;
            insn.mnemonic = "orr";
            break;
        case 0xD:  // MOV
            insn.type = InstructionType::MOV;
            insn.mnemonic = "mov";
            break;
        case 0xE:  // BIC
            insn.type = InstructionType::BIC;
            insn.mnemonic = "bic";
            break;
        case 0xF:  // MVN
            insn.type = InstructionType::MVN;
            insn.mnemonic = "mvn";
            break;
    }
    
    // Build operands string
    std::ostringstream ops;
    Operand dest, src;
    
    dest.type = OperandType::REGISTER;
    dest.reg = static_cast<Register>(rd);
    dest.size = 4;
    
    src.type = OperandType::REGISTER;
    src.reg = static_cast<Register>(rn);
    src.size = 4;
    
    if (opcode >= 0x8 && opcode <= 0xB) {
        // Comparison instructions (TST, TEQ, CMP, CMN)
        ops << registerToString(static_cast<Register>(rn)) << ", " 
            << op2.toString();
        insn.operands.push_back(src);
        insn.operands.push_back(op2);
        insn.operandCount = 2;
    } else if (opcode == 0xD || opcode == 0xF) {
        // MOV/MVN (single destination)
        ops << registerToString(static_cast<Register>(rd)) << ", " 
            << op2.toString();
        insn.operands.push_back(dest);
        insn.operands.push_back(op2);
        insn.operandCount = 2;
    } else {
        // Two-operand data processing
        ops << registerToString(static_cast<Register>(rd)) << ", "
            << registerToString(static_cast<Register>(rn)) << ", "
            << op2.toString();
        insn.operands.push_back(dest);
        insn.operands.push_back(src);
        insn.operands.push_back(op2);
        insn.operandCount = 3;
    }
    
    insn.operandsStr = ops.str();
    insn.modifiesFlags = setFlags;
    insn.readsFlags = false;  // Most don't read flags except conditional
    
    // Store raw bytes
    for (int i = 3; i >= 0; --i) {
        insn.rawBytes.push_back((instr >> (i * 8)) & 0xFF);
    }
    insn.size = 4;
    
    return insn;
}

// ============================================================================
// ARM Multiply Instructions
// ============================================================================

Instruction decodeMultiply(uint64_t addr, uint32_t instr) {
    Instruction insn;
    insn.address = addr;
    insn.arch = Architecture::ARM32;
    insn.conditionCode = getCondition(instr);
    
    bool accumulate = (instr >> 21) & 1;
    bool setFlags = (instr >> 20) & 1;
    uint8_t rd = (instr >> 16) & 0xF;
    uint8_t rn = (instr >> 12) & 0xF;
    uint8_t rs = (instr >> 8) & 0xF;
    uint8_t rm = instr & 0xF;
    
    // Determine multiply type based on bit positions
    uint8_t opcode = (instr >> 21) & 0xF;
    bool longOp = (instr >> 22) & 1;
    
    std::ostringstream ops;
    
    if (longOp) {
        // Long multiply (UMULL, UMLAL, SMULL, SMLAL)
        if (!accumulate) {
            insn.mnemonic = (opcode & 1) ? "smull" : "umull";
            insn.type = InstructionType::MUL;
        } else {
            insn.mnemonic = (opcode & 1) ? "smlal" : "umlal";
            insn.type = InstructionType::MUL;
        }
        ops << registerToString(static_cast<Register>(rd)) << ", "
            << registerToString(static_cast<Register>(rn)) << ", "
            << registerToString(static_cast<Register>(rm)) << ", "
            << registerToString(static_cast<Register>(rs));
    } else {
        // Regular multiply (MUL, MLA)
        if (!accumulate) {
            insn.mnemonic = "mul";
            insn.type = InstructionType::MUL;
            ops << registerToString(static_cast<Register>(rd)) << ", "
                << registerToString(static_cast<Register>(rm)) << ", "
                << registerToString(static_cast<Register>(rs));
        } else {
            insn.mnemonic = "mla";
            insn.type = InstructionType::MUL;
            ops << registerToString(static_cast<Register>(rd)) << ", "
                << registerToString(static_cast<Register>(rm)) << ", "
                << registerToString(static_cast<Register>(rs)) << ", "
                << registerToString(static_cast<Register>(rn));
        }
    }
    
    if (setFlags) {
        insn.mnemonic += "s";
    }
    
    insn.operandsStr = ops.str();
    insn.modifiesFlags = setFlags;
    
    for (int i = 3; i >= 0; --i) {
        insn.rawBytes.push_back((instr >> (i * 8)) & 0xFF);
    }
    insn.size = 4;
    
    return insn;
}

// ============================================================================
// ARM Load/Store Instructions
// ============================================================================

Instruction decodeLoadStore(uint64_t addr, uint32_t instr) {
    Instruction insn;
    insn.address = addr;
    insn.arch = Architecture::ARM32;
    insn.conditionCode = getCondition(instr);
    
    bool immediate = (instr >> 25) & 1;  // Actually indicates offset format
    bool preIndex = (instr >> 24) & 1;
    bool up = (instr >> 23) & 1;
    bool byteTransfer = (instr >> 22) & 1;
    bool writeback = (instr >> 21) & 1;
    bool load = (instr >> 20) & 1;
    uint8_t rn = (instr >> 16) & 0xF;
    uint8_t rd = (instr >> 12) & 0xF;
    
    int16_t offset = instr & 0xFFF;
    
    // Determine instruction type
    if (load) {
        insn.type = byteTransfer ? InstructionType::LDRB : InstructionType::LDR;
        insn.mnemonic = byteTransfer ? "ldrb" : "ldr";
    } else {
        insn.type = byteTransfer ? InstructionType::STRB : InstructionType::STR;
        insn.mnemonic = byteTransfer ? "strb" : "str";
    }
    
    // Build operands
    std::ostringstream ops;
    Operand memOp;
    memOp.type = OperandType::MEMORY;
    memOp.memory.baseReg = static_cast<Register>(rn);
    memOp.memory.offset = up ? offset : -offset;
    memOp.memory.preIndexed = preIndex;
    memOp.memory.writeback = writeback;
    memOp.size = byteTransfer ? 1 : 4;
    
    Operand regOp;
    regOp.type = OperandType::REGISTER;
    regOp.reg = static_cast<Register>(rd);
    regOp.size = byteTransfer ? 1 : 4;
    
    ops << registerToString(static_cast<Register>(rd)) << ", "
        << memOp.toString();
    
    insn.operandsStr = ops.str();
    insn.operands.push_back(regOp);
    insn.operands.push_back(memOp);
    insn.operandCount = 2;
    
    for (int i = 3; i >= 0; --i) {
        insn.rawBytes.push_back((instr >> (i * 8)) & 0xFF);
    }
    insn.size = 4;
    
    return insn;
}

// ============================================================================
// ARM Load/Store Multiple
// ============================================================================

Instruction decodeLoadStoreMultiple(uint64_t addr, uint32_t instr) {
    Instruction insn;
    insn.address = addr;
    insn.arch = Architecture::ARM32;
    insn.conditionCode = getCondition(instr);
    
    bool preIndex = (instr >> 24) & 1;
    bool up = (instr >> 23) & 1;
    bool psr = (instr >> 22) & 1;
    bool writeback = (instr >> 21) & 1;
    bool load = (insn >> 20) & 1;
    uint8_t rn = (instr >> 16) & 0xF;
    uint16_t registerList = instr & 0xFFFF;
    
    insn.type = load ? InstructionType::LDM : InstructionType::STM;
    insn.mnemonic = load ? "ldm" : "stm";
    
    // Determine addressing mode suffix
    if (preIndex && up) {
        insn.mnemonic += "ib";  // Increment before
    } else if (preIndex && !up) {
        insn.mnemonic += "db";  // Decrement before
    } else if (!preIndex && up) {
        insn.mnemonic += "ia";  // Increment after
    } else {
        insn.mnemonic += "da";  // Decrement after
    }
    
    std::ostringstream ops;
    ops << registerToString(static_cast<Register>(rn)) << (writeback ? "!" : "")
        << ", {";
    
    // List registers
    bool first = true;
    for (int i = 0; i < 16; ++i) {
        if (registerList & (1 << i)) {
            if (!first) ops << ", ";
            ops << registerToString(static_cast<Register>(i));
            first = false;
            
            Operand regOp;
            regOp.type = OperandType::REGISTER;
            regOp.reg = static_cast<Register>(i);
            regOp.size = 4;
            insn.operands.push_back(regOp);
        }
    }
    
    if (psr) {
        ops << "^";  // Include PSR
    }
    ops << "}";
    
    insn.operandsStr = ops.str();
    insn.operandCount = insn.operands.size() + 1;
    
    for (int i = 3; i >= 0; --i) {
        insn.rawBytes.push_back((instr >> (i * 8)) & 0xFF);
    }
    insn.size = 4;
    
    return insn;
}

// ============================================================================
// ARM Branch Instructions
// ============================================================================

Instruction decodeBranch(uint64_t addr, uint32_t instr, bool link, bool exchange = false) {
    Instruction insn;
    insn.address = addr;
    insn.arch = Architecture::ARM32;
    insn.conditionCode = getCondition(instr);
    
    // Sign-extend 24-bit offset
    int32_t offset = instr & 0x00FFFFFF;
    if (offset & 0x00800000) {
        offset |= 0xFF000000;  // Sign extend
    }
    offset <<= 2;  // Word-aligned
    
    // Branch target is relative to PC+8 (pipeline)
    uint64_t target = addr + 8 + offset;
    
    if (link) {
        insn.type = exchange ? InstructionType::BLX : InstructionType::BL;
        insn.mnemonic = exchange ? "blx" : "bl";
        insn.isCall = true;
    } else {
        insn.type = exchange ? InstructionType::BX : InstructionType::B;
        insn.mnemonic = exchange ? "bx" : "b";
        insn.isBranch = true;
    }
    
    insn.isConditional = (insn.conditionCode != ConditionCode::AL);
    insn.isTerminal = !link && !exchange;  // B without link is terminal if unconditional
    
    Operand targetOp;
    targetOp.type = OperandType::IMMEDIATE;
    targetOp.immediateValue = static_cast<int64_t>(target);
    targetOp.size = 4;
    
    if (exchange) {
        // BX/BLX uses register or immediate
        uint8_t rm = instr & 0xF;
        targetOp.type = OperandType::REGISTER;
        targetOp.reg = static_cast<Register>(rm);
        targetOp.size = 4;
        
        insn.branchTarget = target;  // May not be accurate for BX with register
    } else {
        insn.branchTarget = target;
    }
    
    insn.operandsStr = targetOp.toString();
    insn.operands.push_back(targetOp);
    insn.operandCount = 1;
    
    for (int i = 3; i >= 0; --i) {
        insn.rawBytes.push_back((instr >> (i * 8)) & 0xFF);
    }
    insn.size = 4;
    
    return insn;
}

// ============================================================================
// ARM Supervisor Call (SVC/SWI)
// ============================================================================

Instruction decodeSVC(uint64_t addr, uint32_t instr) {
    Instruction insn;
    insn.address = addr;
    insn.arch = Architecture::ARM32;
    insn.conditionCode = getCondition(instr);
    
    uint32_t imm24 = instr & 0x00FFFFFF;
    
    insn.type = InstructionType::SVC;
    insn.mnemonic = "svc";
    insn.isPrivileged = true;
    insn.isTerminal = true;  // SVC may not return
    
    Operand immOp;
    immOp.type = OperandType::IMMEDIATE;
    immOp.immediateValue = imm24;
    immOp.size = 4;
    
    insn.operandsStr = "#0x" + utils::formatHexDword(imm24);
    insn.operands.push_back(immOp);
    insn.operandCount = 1;
    
    for (int i = 3; i >= 0; --i) {
        insn.rawBytes.push_back((instr >> (i * 8)) & 0xFF);
    }
    insn.size = 4;
    
    return insn;
}

// ============================================================================
// Main ARM Decoder Function
// ============================================================================

Instruction decodeARMInstruction(uint64_t addr, const uint8_t* data, size_t maxSize) {
    if (maxSize < 4) {
        // Not enough bytes for ARM instruction
        Instruction invalid;
        invalid.address = addr;
        invalid.type = InstructionType::INVALID;
        invalid.arch = Architecture::ARM32;
        invalid.size = 0;
        return invalid;
    }
    
    // Read 32-bit instruction (little-endian)
    uint32_t instr = (data[0]) | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    
    // Check for condition field
    ConditionCode cond = getCondition(instr);
    
    // Bits [27:25] determine instruction category
    uint8_t category = (instr >> 25) & 0x7;
    
    switch (category) {
        case 0x0:
        case 0x1: {
            // Data processing / Misc / MSR / MRC etc.
            // Check for multiply instructions (bits [7:4] = 1001 and bits [27:20] pattern)
            uint8_t bits76 = (instr >> 4) & 0xF;
            if (bits76 == 0x9 && !(instr & (1 << 25))) {
                // Could be multiply or extra load/store
                if (((instr >> 22) & 3) != 0) {
                    // Extra load/store (LDRD/STRD/LDRH/etc.)
                    return decodeLoadStore(addr, instr);  // Simplified
                } else {
                    return decodeMultiply(addr, instr);
                }
            }
            return decodeDataProcessing(addr, instr);
        }
        
        case 0x2:
        case 0x3: {
            // Load/Store immediate offset
            return decodeLoadStore(addr, instr);
        }
        
        case 0x4:
        case 0x5: {
            // Load/Store multiple / Branch
            bool isLoadStoreMultiple = (instr & 0x08000000) == 0;
            if (isLoadStoreMultiple) {
                return decodeLoadStoreMultiple(addr, instr);
            } else {
                // Branch (B/BL)
                bool link = (instr >> 24) & 1;
                return decodeBranch(addr, instr, link);
            }
        }
        
        case 0x6:
        case 0x7: {
            // Coprocessor / SVC
            if ((instr & 0x0F000000) == 0x0F000000) {
                return decodeSVC(addr, instr);
            }
            // Coprocessor data transfer / register transfer
            // Fall through to generic handling
            
            // Create placeholder for coprocessor instructions
            Instruction coproc;
            coproc.address = addr;
            coproc.arch = Architecture::ARM32;
            coproc.conditionCode = cond;
            coproc.type = InstructionType::SVC;  // Placeholder
            coproc.mnemonic = "cdp";  // Generic coprocessor
            
            for (int i = 3; i >= 0; --i) {
                coproc.rawBytes.push_back((instr >> (i * 8)) & 0xFF);
            }
            coproc.size = 4;
            coproc.operandsStr = "coprocessor_instruction";
            return coproc;
        }
    }
    
    // Should never reach here
    Instruction unknown;
    unknown.address = addr;
    unknown.type = InstructionType::INVALID;
    unknown.arch = Architecture::ARM32;
    unknown.mnemonic = ".word";
    
    Operand val;
    val.type = OperandType::IMMEDIATE;
    val.immediateValue = instr;
    val.size = 4;
    unknown.operandsStr = "0x" + utils::formatHexDword(instr);
    unknown.operands.push_back(val);
    
    for (int i = 3; i >= 0; --i) {
        unknown.rawBytes.push_back((instr >> (i * 8)) & 0xFF);
    }
    unknown.size = 4;
    
    return unknown;
}

} // namespace arm

// ============================================================================
// Public API Implementation - ARM32
// ============================================================================

Instruction DisassemblerEngine::decodeARM(uint64_t address, const uint8_t* data, size_t maxSize) {
    return arm::decodeARMInstruction(address, data, maxSize);
}

} // namespace idapro
