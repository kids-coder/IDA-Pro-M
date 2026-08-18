/**
 * IDA Pro M - Function Analyzer
 * Identifies and analyzes functions in binary code
 */

#include "idapro_engine.h"
#include <vector>
#include <unordered_map>
#include <set>
#include <stack>
#include <algorithm>

namespace idapro {

// ============================================================================
// Function Analyzer Implementation
// ============================================================================

class FunctionAnalyzerImpl {
public:
    explicit FunctionAnalyzerImpl(const std::unordered_map<uint64_t, Instruction>& instructions,
                                   const BinaryInfo& binaryInfo)
        : instructions_(instructions), binaryInfo_(binaryInfo) {}
    
    // Identify all functions in the instruction set
    std::vector<Function> identifyFunctions() {
        std::vector<Function> functions;
        std::set<uint64_t> functionEntryPoints;
        std::set<uint64_t> processedAddresses;
        
        // Step 1: Find function entry points
        findEntryPoints(functionEntryPoints);
        
        // Add entry point from binary info if available
        if (binaryInfo_.entryPoint > 0) {
            functionEntryPoints.insert(binaryInfo_.entryPoint);
        }
        
        // Step 2: Analyze each function
        int functionId = 0;
        for (uint64_t entryPoint : functionEntryPoints) {
            if (processedAddresses.count(entryPoint)) continue;
            
            Function func = analyzeFunction(entryPoint, functionId++);
            if (func.instructionCount > 0) {
                functions.push_back(func);
                
                // Mark addresses as processed
                for (const auto& bb : func.basicBlocks) {
                    for (const auto& insn : bb.instructions) {
                        processedAddresses.insert(insn.address);
                    }
                }
            }
        }
        
        // Step 3: Build call graph information
        buildCallGraph(functions);
        
        return functions;
    }
    
    // Analyze a single function starting at the given address
    Function analyzeFunction(uint64_t startAddress, int id = -1) {
        Function func;
        func.id = id;
        func.startAddress = startAddress;
        func.name = generateFunctionName(startAddress);
        
        // Recursive descent analysis to find function boundaries
        std::set<uint64_t> visited;
        std::stack<uint64_t> worklist;
        std::vector<Instruction> funcInstructions;
        
        worklist.push(startAddress);
        uint64_t maxAddress = startAddress;
        
        while (!worklist.empty()) {
            uint64_t addr = worklist.top();
            worklist.pop();
            
            if (visited.count(addr)) continue;
            visited.insert(addr);
            
            auto it = instructions_.find(addr);
            if (it == instructions_.end()) break;
            
            const Instruction& insn = it->second;
            funcInstructions.push_back(insn);
            insn.functionId = id;
            
            maxAddress = std::max(maxAddress, insn.address + insn.size);
            
            // Follow control flow
            if (insn.isReturn || insn.isTerminal) {
                // Don't follow returns/terminal instructions
                continue;
            }
            
            if (!insn.isBranch && !insn.isCall) {
                // Fall through to next instruction
                uint64_t nextAddr = insn.address + insn.size;
                if (!visited.count(nextAddr)) {
                    worklist.push(nextAddr);
                }
            }
            
            // Follow branch targets (but not calls - those go to other functions)
            if (insn.isBranch && insn.branchTarget.has_value()) {
                uint64_t target = *insn.branchTarget;
                if (!visited.count(target)) {
                    worklist.push(target);
                }
            }
        }
        
        func.endAddress = maxAddress;
        func.size = maxAddress - startAddress;
        func.instructionCount = static_cast<int>(funcInstructions.size());
        
        // Detect calling convention
        detectCallingConvention(func);
        
        // Detect function properties
        analyzeFunctionProperties(func, funcInstructions);
        
        return func;
    }

private:
    const std::unordered_map<uint64_t, Instruction>& instructions_;
    const BinaryInfo& binaryInfo_;
    
    void findEntryPoints(std::set<uint64_t>& entryPoints) {
        // Method 1: Look for prologue patterns
        for (const auto& [addr, insn] : instructions_) {
            if (isPrologueInstruction(insn)) {
                entryPoints.insert(addr);
            }
        }
        
        // Method 2: Find targets of call instructions
        for (const auto& [addr, insn] : instructions_) {
            if (isCallInstruction(insn.type) && insn.branchTarget.has_value()) {
                entryPoints.insert(*insn.branchTarget);
            }
        }
        
        // Method 3: Check symbol table
        for (const auto& sym : binaryInfo_.symbols) {
            if (sym.type == BinaryInfo::Symbol::Type::FUNCTION && sym.isDefined) {
                entryPoints.insert(sym.address);
            }
        }
        
        // Method 4: Check exports
        for (const auto& exp : binaryInfo_.exports) {
            if (exp.type == BinaryInfo::Symbol::Type::FUNCTION) {
                entryPoints.insert(exp.address);
            }
        }
    }
    
    bool isPrologueInstruction(const Instruction& insn) const {
        switch (insn.type) {
            case InstructionType::PUSH:
                // Push of frame pointer or link register
                for (const auto& op : insn.operands) {
                    if (op.type == OperandType::REGISTER &&
                        (op.reg == getFramePointer(binaryInfo_.arch) ||
                         op.reg == getLinkRegister(binaryInfo_.arch))) {
                        return true;
                    }
                }
                break;
                
            case InstructionType::MOV:
            case InstructionType::SUB:
                // Setting up stack/frame pointer
                for (const auto& op : insn.operands) {
                    if (op.type == OperandType::REGISTER &&
                        op.reg == getStackPointer(binaryInfo_.arch)) {
                        return true;
                    }
                }
                break;
                
            default:
                break;
        }
        return false;
    }
    
    void detectCallingConvention(Function& func) {
        // Analyze first few instructions to determine calling convention
        
        bool hasFramePointerSetup = false;
        bool hasStackAlignment = false;
        bool savesLinkRegister = false;
        
        for (const auto& bb : func.basicBlocks) {
            if (bb.isEntry) {
                for (size_t i = 0; i < std::min(bb.instructions.size(), size_t(5)); ++i) {
                    const Instruction& insn = bb.instructions[i];
                    
                    switch (insn.type) {
                        case InstructionType::PUSH:
                            for (const auto& op : insn.operands) {
                                if (op.type == OperandType::REGISTER &&
                                    op.reg == getLinkRegister(binaryInfo_.arch)) {
                                    savesLinkRegister = true;
                                }
                            }
                            break;
                            
                        case InstructionType::MOV:
                        case InstructionType::ADD:
                        case InstructionType::SUB:
                            for (const auto& op : insn.operands) {
                                if (op.type == OperandType::REGISTER &&
                                    op.reg == getFramePointer(binaryInfo_.arch)) {
                                    hasFramePointerSetup = true;
                                }
                            }
                            break;
                            
                        default:
                            break;
                    }
                }
                break;  // Only check entry block
            }
        }
        
        // Determine convention based on architecture and patterns
        switch (binaryInfo_.arch) {
            case Architecture::ARM32:
            case Architecture::THUMB:
                func.callingConvention = Function::CallingConvention::AAPCS;
                break;
            case Architecture::ARM64:
                func.callingConvention = Function::CallingConvention::AARCH64;
                break;
            case Architecture::X86_32:
                func.callingConvention = Function::CallingConvention::CDECL;
                break;
            case Architecture::X86_64:
                func.callingConvention = Function::CallingConvention::SYSTEM_V_AMD64;
                break;
            default:
                func.callingConvention = Function::CallingConvention::UNKNOWN;
                break;
        }
    }
    
    void analyzeFunctionProperties(Function& func, 
                                   const std::vector<Instruction>& instructions) {
        // Count various instruction types
        int callCount = 0;
        int branchCount = 0;
        int returnCount = 0;
        bool hasLocalVariables = false;
        
        for (const auto& insn : instructions) {
            if (isCallInstruction(insn.type)) {
                ++callCount;
                if (insn.branchTarget.has_value()) {
                    func.callees.push_back(*insn.branchTarget);
                }
            } else if (isBranchInstruction(insn.type)) {
                ++branchCount;
            } else if (isReturnInstruction(insn.type)) {
                ++returnCount;
            }
            
            // Check for local variable access (stack-relative addressing)
            if (insn.type == InstructionType::LDR || insn.type == InstructionType::STR) {
                for (const auto& op : insn.operands) {
                    if (op.type == OperandType::MEMORY &&
                        op.memory.baseReg == getStackPointer(binaryInfo_.arch) ||
                        op.memory.baseReg == getFramePointer(binaryInfo_.arch)) {
                        hasLocalVariables = true;
                    }
                }
            }
        }
        
        // Determine function type based on characteristics
        if (instructions.size() <= 4 && callCount == 1 && returnCount >= 1) {
            func.type = Function::Type::THUNK;
        } else if (func.name.find("plt_") != std::string::npos ||
                   func.name.find("got_") != std::string::npos) {
            func.type = Function::Type::THUNK;
        }
        
        // Detect noreturn functions
        if (returnCount == 0 && !func.callees.empty()) {
            // Might be noreturn - check common patterns
            func.isNoreturn = true;
        }
        
        // Generate simple signature hint
        if (hasLocalVariables) {
            func.signature = "void " + func.getDisplayName() + "()";
        }
    }
    
    void buildCallGraph(std::vector<Function>& functions) {
        // Build caller/callee relationships
        for (auto& func : functions) {
            for (uint64_t calleeAddr : func.callees) {
                // Find the callee function
                for (auto& otherFunc : functions) {
                    if (otherFunc.startAddress == calleeAddr) {
                        otherFunc.callers.push_back(func.startAddress);
                        break;
                    }
                }
            }
        }
    }
    
    std::string generateFunctionName(uint64_t address) const {
        // Check if address matches any known symbol
        for (const auto& sym : binaryInfo_.symbols) {
            if (sym.address == address && sym.type == BinaryInfo::Symbol::Type::FUNCTION) {
                return sym.name;
            }
        }
        
        // Generate default name
        return "sub_" + utils::formatAddress(address, false);
    }

};

} // namespace idapro
