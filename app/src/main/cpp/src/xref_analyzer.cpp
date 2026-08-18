/**
 * IDA Pro M - Cross-Reference Analyzer
 * Resolves and tracks cross-references between instructions, data, and symbols
 */

#include "idapro_engine.h"
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <set>

namespace idapro {

// ============================================================================
// Xref Analyzer Implementation
// ============================================================================

class XrefAnalyzerImpl {
public:
    explicit XrefAnalyzerImpl(const std::unordered_map<uint64_t, Instruction>& instructions,
                               const std::vector<Function>& functions,
                               const BinaryInfo& binaryInfo)
        : instructions_(instructions), functions_(functions), binaryInfo_(binaryInfo) {}
    
    // Build all cross-references
    std::vector<Xref> analyze() {
        std::vector<Xref> xrefs;
        
        analyzeCodeReferences(xrefs);
        analyzeDataReferences(xrefs);
        analyzeStringReferences(xrefs);
        analyzeFunctionCallReferences(xrefs);
        
        return xrefs;
    }
    
    // Get xrefs TO a specific address
    std::vector<Xref*> getXrefsTo(uint64_t address) {
        auto it = xrefsToMap_.find(address);
        if (it != xrefsToMap_.end()) {
            std::vector<Xref*> result;
            for (auto& xref : it->second) {
                result.push_back(&xref);
            }
            return result;
        }
        return {};
    }
    
    // Get xrefs FROM a specific address
    std::vector<Xref*> getXrefsFrom(uint64_t address) {
        auto it = xrefsFromMap_.find(address);
        if (it != xrefsFromMap_.end()) {
            std::vector<Xref*> result;
            for (auto& xref : it->second) {
                result.push_back(&xref);
            }
            return result;
        }
        return {};
    }

private:
    const std::unordered_map<uint64_t, Instruction>& instructions_;
    const std::vector<Function>& functions_;
    const BinaryInfo& binaryInfo_;
    
    std::unordered_map<uint64_t, std::vector<Xref>> xrefsToMap_;
    std::unordered_map<uint64_t, std::vector<Xref>> xrefsFromMap_;
    
    void analyzeCodeReferences(std::vector<Xref>& xrefs) {
        for (const auto& [addr, insn] : instructions_) {
            // Check branch targets
            if (insn.branchTarget.has_value()) {
                Xref xref;
                xref.type = isBranchInstruction(insn.type) ? Xref::Type::CODE : Xref::Type::CALL;
                xref.from = addr;
                xref.to = *insn.branchTarget;
                
                xrefs.push_back(xref);
                xrefsToMap_[xref.to].push_back(xref);
                xrefsFromMap_[xref.from].push_back(xref);
            }
            
            // Analyze operands for potential code references
            for (const auto& op : insn.operands) {
                if (op.type == OperandType::IMMEDIATE && op.immediateValue > 0x1000) {
                    uint64_t potentialAddr = static_cast<uint64_t>(op.immediateValue);
                    
                    // Check if this address points to known code
                    if (instructions_.find(potentialAddr) != instructions_.end()) {
                        Xref xref;
                        xref.type = Xref::Type::CODE;
                        xref.from = addr;
                        xref.to = potentialAddr;
                        
                        xrefs.push_back(xref);
                        xrefsToMap_[xref.to].push_back(xref);
                        xrefsFromMap_[xref.from].push_back(xref);
                    }
                }
            }
        }
    }
    
    void analyzeDataReferences(std::vector<Xref>& xrefs) {
        for (const auto& [addr, insn] : instructions_) {
            // Look for load/store instructions that reference data addresses
            switch (insn.type) {
                case InstructionType::LDR:
                case InstructionType::STR:
                case InstructionType::LDRB:
                case InstructionType::STRB:
                case InstructionType::LDRH:
                case InstructionType::STRH: {
                    for (const auto& op : insn.operands) {
                        if (op.type == OperandType::MEMORY && 
                            op.memory.baseReg == Register::PC) {
                            // PC-relative data reference
                            Xref xref;
                            xref.type = Xref::Type::DATA;
                            xref.from = addr;
                            xref.to = static_cast<uint64_t>(op.memory.offset) + addr + 4;  // Approximate
                            
                            xrefs.push_back(xref);
                            xrefsToMap_[xref.to].push_back(xref);
                            xrefsFromMap_[xref.from].push_back(xref);
                        } else if (op.type == OperandType::MEMORY &&
                                   op.memory.baseReg != Register::NONE) {
                            // Memory access - could be data read/write
                            Xref xref;
                            xref.type = (isLoadInstruction(insn.type)) ? 
                                        Xref::Type::READ : Xref::Type::WRITE;
                            xref.from = addr;
                            xref.to = 0;  // Unknown target without full analysis
                            
                            xrefs.push_back(xref);
                            xrefsFromMap_[xref.from].push_back(xref);
                        }
                    }
                    break;
                }
                    
                default:
                    break;
            }
        }
    }
    
    void analyzeStringReferences(std::vector<Xref>& xrefs) {
        // This would require string table information
        // For now, we identify string references from load instructions with PC-relative addressing
        
        for (const auto& [addr, insn] : instructions_) {
            if (insn.type == InstructionType::LDR || insn.type == InstructionType::LEA) {
                for (const auto& op : insn.operands) {
                    if (op.type == OperandType::MEMORY && 
                        op.memory.baseReg == Register::PC) {
                        // Likely a string or constant pool reference
                        Xref xref;
                        xref.type = Xref::Type::STRING;
                        xref.from = addr;
                        xref.to = static_cast<uint64_t>(op.memory.offset) + addr + 4;
                        
                        xrefs.push_back(xref);
                        xrefsToMap_[xref.to].push_back(xref);
                        xrefsFromMap_[xref.from].push_back(xref);
                    }
                }
            }
        }
    }
    
    void analyzeFunctionCallReferences(std::vector<Xref>& xrefs) {
        for (const auto& func : functions_) {
            // Record callers
            for (uint64_t callerAddr : func.callers) {
                Xref xref;
                xref.type = Xref::Type::CALL;
                xref.from = callerAddr;
                xref.to = func.startAddress;
                
                xrefs.push_back(xref);
                xrefsToMap_[xref.to].push_back(xref);
                xrefsFromMap_[xref.from].push_back(xref);
            }
            
            // Record callees
            for (uint64_t calleeAddr : func.callees) {
                Xref xref;
                xref.type = Xref::Type::CALL;
                xref.from = func.startAddress;
                xref.to = calleeAddr;
                
                xrefs.push_back(xref);
                xrefsToMap_[xref.to].push_back(xref);
                xrefsFromMap_[xref.from].push_back(xref);
            }
            
            // Record non-call references to function entry points
            for (uint64_t xrefAddr : func.xrefsTo) {
                Xref xref;
                xref.type = Xref::Type::DATA;  // Taking address of function
                xref.from = xrefAddr;
                xref.to = func.startAddress;
                
                xrefs.push_back(xref);
                xrefsToMap_[xref.to].push_back(xref);
                xrefsFromMap_[xref.from].push_back(xref);
            }
        }
    }
    
    bool isLoadInstruction(InstructionType type) const {
        switch (type) {
            case InstructionType::LDR:
            case InstructionType::LDRB:
            case InstructionType::LDRH:
            case InstructionType::LDRD:
            case InstructionType::LDREX:
                return true;
            default:
                return false;
        }
    }

};

} // namespace idapro
