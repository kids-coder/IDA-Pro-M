/**
 * @file function_detector.cpp
 * @brief Function Detector Implementation
 * 
 * Detects function boundaries in binary code using:
 * - ARM/Thumb prologue pattern matching (PUSH {R4-R7, LR}, etc.)
 * - Epilogue detection (BX LR, POP {PC})
 * - Symbol table hints for named functions
 * - Size estimation based on prologue/epilogue analysis
 * 
 * @version 3.0.0
 */

#include "ida_pro_native.h"
#include <algorithm>
#include <set>
#include <map>
#include <sstream>

namespace ida {

// ============================================================================
// FunctionDetector::Impl - PIMPL Implementation
// ============================================================================

class FunctionDetector::Impl {
public:
    uint32_t minFunctionSize{4};       // Minimum function size in bytes
    
    // Custom patterns
    std::vector<ProloguePattern> customPrologues;
    std::vector<EpiloguePattern> customEpilogues;
    
    // Default ARM prologue patterns
    static const std::vector<uint32_t> defaultArmPrologues;
    
    // Default Thumb prologue patterns (16-bit)
    static const std::vector<uint16_t> defaultThumbPrologues;
    
    // Default ARM epilogue patterns
    static const std::vector<uint32_t> defaultArmEpilogues;
    
    // Default Thumb epilogue patterns
    static const std::vector<uint16_t> defaultThumbEpilogues;
    
    Impl() = default;
    ~Impl() = default;
    
    /// Check if an opcode matches any known ARM prologue pattern
    [[nodiscard]] bool isArmPrologue(uint32_t opcode) const {
        // PUSH {R4-R11, LR} - common function prologue
        // Format: cond 1001 0 Rn 1111 1100100000000000
        // Or: cond 100P U 0 W 1 Rn list
        
        // Check standard PUSH patterns
        if ((opcode & 0xFFFFF000) == 0xE92D4000) return true;   // PUSH {R4}
        if ((opcode & 0xFFFFF000) == 0xE92D5000) return true;   // PUSH {R5}
        if ((opcode & 0xFFFFF000) == 0xE92D6000) return true;   // PUSH {R6}
        if ((opcode & 0xFFFFF000) == 0xE92D7000) return true;   // PUSH {R7}
        if ((opcode & 0xFFFFF800) == 0xE92D4800) return true;   // PUSH {R4, R5}
        if ((opcode & 0xFFFFF800) == 0xE92D4C00) return true;   // PUSH {R4-R6}
        if ((opcode & 0xFFFFF800) == 0xE92D4E00) return true;   // PUSH {R4-R7}
        if ((opcode & 0xFFFFF000) == 0xE92D4F00) return true;   // PUSH {R4-R7, LR}
        
        // STMDB SP!, {...} - alternative push syntax
        if ((opcode & 0xFFF00000) == 0xE9200000 && (opcode & 0x8000)) return true;
        
        // MOV R11/IP, SP or MOV R12/IP, SP (frame pointer setup)
        if ((opcode & 0xFFFF0FF0) == 0xE1A0B00D ||  // MOV R11, SP
            (opcode & 0xFFFF0FF0) == 0xE1A0C00D) {  // MOV R12, SP
            return true;
        }
        
        // SUB SP, SP, #imm (stack frame allocation)
        if ((opcode & 0xFFF00000) == 0xE240D000 ||  // SUB SP, SP, #imm
            (opcode & 0xFFF00000) == 0xE24DD000) {  // SUB SP, SP, #imm (alternate)
            return true;
        }
        
        // Check custom patterns
        for (const auto& pattern : customPrologues) {
            for (uint32_t armPattern : pattern.armPatterns) {
                if ((opcode & armPattern) == armPattern) return true;
            }
        }
        
        // Check default patterns
        for (uint32_t pattern : defaultArmPrologues) {
            if ((opcode & pattern) == pattern) return true;
        }
        
        return false;
    }
    
    /// Check if a halfword matches any known Thumb prologue pattern
    [[nodiscard]] bool isThumbPrologue(uint16_t halfWord) const {
        // PUSH {R7, LR} = 0xB580 to 0xB5FF with bit 8 set
        if ((halfWord & 0xFF00) == 0xB500 && (halfWord & 0x0100)) return true;
        
        // PUSH {R4-R7, LR} = 0xB5F0
        if ((halfWord & 0xFF00) == 0xB5F0) return true;
        
        // PUSH {Rx, LR} where x is low register
        if ((halfWord >> 8) == 0xB5 && (halfWord & 0xFF) != 0) return true;
        
        // SUB SP, #imm (Thumb stack frame)
        if ((halfWord >> 11) == 0b10110 && (halfWord & 0x7F) != 0) return true;
        
        // MOV Rx, SP / ADD Rx, SP, #0 (frame pointer)
        if (((halfWord >> 8) == 0x46 || (halfWord >> 8) == 0x44) &&
            ((halfWord & 0x07) >= 4 && (halfWord & 0x07) <= 7)) {
            return true;
        }
        
        // Check custom patterns
        for (const auto& pattern : customPrologues) {
            for (uint16_t thumbPattern : pattern.thumbPatterns) {
                if ((halfWord & thumbPattern) == thumbPattern) return true;
            }
        }
        
        // Check default patterns
        for (uint16_t pattern : defaultThumbPrologues) {
            if ((halfWord & pattern) == pattern) return true;
        }
        
        return false;
    }
    
    /// Check if an opcode matches any known ARM epilogue pattern
    [[nodiscard]] bool isArmEpilogue(uint32_t opcode) const {
        // POP {PC} - standard return
        if ((opcode & 0xFFFFF000) == 0xE8BD8000) return true;
        
        // LDM SP!, {PC} - alternate return
        if ((opcode & 0xFFFFF000) == 0xE89DA000) return true;
        
        // BX LR - standard return
        if ((opcode & 0xFFFFFF0) == 0xE12FFF1E) return true;
        
        // MOV PC, LR - alternate return
        if ((opcode & 0xFFFF0FF0) == 0xE1A0F00E) return true;
        
        // LDMFD SP!, {..., PC}
        if ((opcode & 0xFFFF0000) == 0xE8BD0000 && (opcode & 0x8000)) return true;
        
        // Check custom patterns
        for (const auto& pattern : customEpilogues) {
            for (uint32_t armPattern : pattern.armPatterns) {
                if ((opcode & armPattern) == armPattern) return true;
            }
        }
        
        // Check default patterns
        for (uint32_t pattern : defaultArmEpilogues) {
            if ((opcode & pattern) == pattern) return true;
        }
        
        return false;
    }
    
    /// Check if a halfword matches any known Thumb epilogue pattern
    [[nodiscard]] bool isThumbEpilogue(uint16_t halfWord) const {
        // POP {PC} = 0xBDxx with bit 0 set
        if ((halfWord >> 8) == 0xBD && (halfWord & 0x01)) return true;
        
        // POP {Rx, PC} - various forms
        if ((halfWord >> 8) == 0xBD && (halfWord & 0xFF) != 0) return true;
        
        // BX LR = 0x4770
        if (halfWord == 0x4770) return true;
        
        // Check custom patterns
        for (const auto& pattern : customEpilogues) {
            for (uint16_t thumbPattern : pattern.thumbPatterns) {
                if ((halfWord & thumbPattern) == thumbPattern) return true;
            }
        }
        
        // Check default patterns
        for (uint16_t pattern : defaultThumbEpilogues) {
            if ((halfWord & pattern) == pattern) return true;
        }
        
        return false;
    }
};

// ============================================================================
// Static Pattern Definitions
// ============================================================================

const std::vector<uint32_t> FunctionDetector::Impl::defaultArmPrologues = {
    0xE92D4000,  // PUSH {R4}
    0xE92D5000,  // PUSH {R5}
    0xE92D6000,  // PUSH {R6}
    0xE92D7000,  // PUSH {R7}
    0xE92D4F00,  // PUSH {R4-R7, LR}
};

const std::vector<uint16_t> FunctionDetector::Impl::defaultThumbPrologues = {
    0xB580,      // PUSH {R7, LR}
    0xB5F0,      // PUSH {R4-R7, LR}
    0xB500,      // PUSH {LR}
};

const std::vector<uint32_t> FunctionDetector::Impl::defaultArmEpilogues = {
    0xE8BD8000,  // POP {PC}
    0xE12FFF1E,  // BX LR
};

const std::vector<uint16_t> FunctionDetector::Impl::defaultThumbEpilogues = {
    0xBD00,      // POP {PC}
    0x4770,      // BX LR
};

// ============================================================================
// Constructor/Destructor
// ============================================================================

FunctionDetector::FunctionDetector() : impl_(std::make_unique<Impl>()) {}

FunctionDetector::~FunctionDetector() = default;

// ============================================================================
// Main Detection Entry Point
// ============================================================================

AnalysisResult<std::vector<Function>> FunctionDetector::detectFunctions(
    std::span<const std::byte> code,
    uint64_t baseAddress,
    Architecture arch
) {
    std::vector<Function> functions;
    
    if (code.empty()) {
        return functions;
    }
    
    switch (arch) {
        case Architecture::ARM: {
            auto addrs = scanArmPrologues(code, baseAddress);
            
            for (uint64_t addr : addrs) {
                size_t offset = static_cast<size_t>(addr - baseAddress);
                
                Function func{};
                func.startAddress = addr;
                func.type = Function::Type::Normal;
                func.callingConvention = Function::CallingConvention::AAPCS;
                
                // Find function end
                uint64_t endAddr = findArmFunctionEnd(addr, code);
                func.endAddress = endAddr;
                func.size = static_cast<uint32_t>(endAddr - addr);
                
                // Generate name
                std::ostringstream oss;
                oss << "func_" << std::hex << addr;
                func.name = oss.str();
                
                if (func.size >= impl_->minFunctionSize) {
                    functions.push_back(std::move(func));
                }
            }
            break;
        }
        
        case Architecture::Thumb:
        case Architecture::AArch64: {
            auto addrs = scanThumbPrologues(code, baseAddress);
            
            for (uint64_t addr : addrs) {
                size_t offset = static_cast<size_t>(addr - baseAddress);
                
                Function func{};
                func.startAddress = addr;
                func.type = Function::Type::Normal;
                func.callingConvention = Function::CallingConvention::AAPCS;
                
                // Find function end
                uint64_t endAddr = findThumbFunctionEnd(addr, code);
                func.endAddress = endAddr;
                func.size = static_cast<uint32_t>(endAddr - addr);
                
                // Generate name
                std::ostringstream oss;
                oss << "func_" << std::hex << addr;
                func.name = oss.str();
                
                if (func.size >= impl_->minFunctionSize) {
                    functions.push_back(std::move(func));
                }
            }
            break;
        }
        
        default:
            // For unsupported architectures, try basic heuristics
            break;
    }
    
    return functions;
}

// ============================================================================
// Symbol-Based Detection
// ============================================================================

std::vector<Function> FunctionDetector::detectFromSymbols(
    std::span<const SymbolEntry> symbols,
    std::span<const std::byte> code,
    uint64_t baseAddress,
    Architecture arch
) {
    std::vector<Function> functions;
    
    if (symbols.empty() || code.empty()) {
        return functions;
    }
    
    // Collect all function symbols and sort by address
    struct SymInfo {
        uint64_t address;
        uint64_t size;
        std::string name;
        SymbolEntry::Binding binding;
    };
    
    std::vector<SymInfo> funcSyms;
    
    for (const auto& sym : symbols) {
        if (sym.isFunction() && sym.isDefined()) {
            funcSyms.push_back({sym.address, sym.size, sym.name, sym.binding});
        }
    }
    
    // Sort by address
    std::sort(funcSyms.begin(), funcSyms.end(),
              [](const SymInfo& a, const SymInfo& b) {
                  return a.address < b.address;
              });
    
    // Create functions from symbols
    for (size_t i = 0; i < funcSyms.size(); ++i) {
        const auto& sym = funcSyms[i];
        
        Function func{};
        func.startAddress = sym.address;
        func.name = sym.name.empty() ? ("func_" + std::to_string(sym.address)) : sym.name;
        func.type = (sym.binding == SymbolEntry::Binding::Global) 
                   ? Function::Type::Export 
                   : Function::Type::Normal;
        func.callingConvention = (arch == Architecture::ARM || arch == Architecture::Thumb)
                               ? Function::CallingConvention::AAPCS
                               : Function::CallingConvention::Unknown;
        
        // Determine size from symbol info or next symbol
        if (sym.size > 0) {
            func.size = static_cast<uint32_t>(sym.size);
            func.endAddress = sym.address + sym.size;
        } else if (i + 1 < funcSyms.size()) {
            // Use next symbol's address as end
            func.endAddress = funcSyms[i + 1].address;
            func.size = static_cast<uint32_t>(func.endAddress - func.startAddress);
        } else {
            // Estimate from code analysis
            func.size = estimateFunctionSize(sym.address, code, arch);
            func.endAddress = sym.address + func.size;
        }
        
        if (func.size >= impl_->minFunctionSize) {
            functions.push_back(std::move(func));
        }
    }
    
    return functions;
}

// ============================================================================
// Boundary Refinement
// ============================================================================

void FunctionDetector::refineBoundaries(
    std::vector<Function>& functions,
    const ArmDisassembler& disasm
) const {
    // This would use the disassembler to refine boundaries by:
    // 1. Disassembling each function
    // 2. Finding actual instruction boundaries
    // 3. Adjusting sizes to be instruction-aligned
    
    for (auto& func : functions) {
        // Ensure minimum alignment
        switch (disasm.getMode()) {
            case ArmDisassembler::Mode::Arm:
                // ARM instructions are 4-byte aligned
                func.size = (func.size + 3) & ~3u;
                func.endAddress = func.startAddress + func.size;
                break;
                
            case ArmDisassembler::Mode::Thumb:
            case ArmDisassembler::Mode::Thumb2:
                // Thumb instructions are 2-byte aligned
                func.size = (func.size + 1) & ~1u;
                func.endAddress = func.startAddress + func.size;
                break;
        }
    }
}

// ============================================================================
// Size Estimation
// ============================================================================

uint32_t FunctionDetector::estimateFunctionSize(
    uint64_t startAddress,
    std::span<const std::byte> code,
    Architecture arch
) const {
    size_t startOffset = static_cast<size_t>(startAddress);  // Assuming base of 0
    
    if (startOffset >= code.size()) {
        return 0;
    }
    
    size_t maxSearch = std::min(code.size() - startOffset, 
                                static_cast<size_t>(65536));  // Max 64KB search
    
    auto searchArea = code.subspan(startOffset, maxSearch);
    
    switch (arch) {
        case Architecture::ARM: {
            // Scan for ARM epilogue
            for (size_t i = 0; i + 4 <= searchArea.size(); i += 4) {
                uint32_t opcode = Utils::readU32LE(searchArea.data() + i);
                if (impl_->isArmEpilogue(opcode)) {
                    return static_cast<uint32_t>(i + 4);  // Include epilogue
                }
            }
            break;
        }
        
        case Architecture::Thumb:
        case Architecture::AArch64: {
            // Scan for Thumb epilogue
            for (size_t i = 0; i + 2 <= searchArea.size(); i += 2) {
                uint16_t halfWord = Utils::readU16LE(searchArea.data() + i);
                
                // Check for Thumb-2 prefix first
                if (impl_->isThumbEpilogue(halfWord)) {
                    return static_cast<uint32_t>(i + 2);
                }
                
                // Skip Thumb-2 32-bit instructions
                uint8_t prefix = (halfWord >> 11) & 0x1F;
                if (prefix == 0x1C || prefix == 0x1D || 
                    prefix == 0x1E || prefix == 0x1F) {
                    i += 2;  // Skip second halfword
                }
            }
            break;
        }
        
        default:
            // Fallback: estimate based on average function size
            return static_cast<uint32_t>(std::min(maxSearch, static_cast<size_t>(256)));
    }
    
    // No epilogue found - return reasonable default
    return static_cast<uint32_t>(std::min(maxSearch, static_cast<size_t>(256)));
}

void FunctionDetector::setMinFunctionSize(uint32_t size) noexcept {
    if (impl_) impl_->minFunctionSize = size;
}

uint32_t FunctionDetector::getMinFunctionSize() const {
    return impl_ ? impl_->minFunctionSize : 4;
}

void FunctionDetector::addProloguePattern(const ProloguePattern& pattern) {
    if (impl_) {
        impl_->customPrologues.push_back(pattern);
    }
}

void FunctionDetector::addEpiloguePattern(const EpiloguePattern& pattern) {
    if (impl_) {
        impl_->customEpilogues.push_back(pattern);
    }
}

// ============================================================================
// ARM Prologue Scanning
// ============================================================================

std::vector<uint64_t> FunctionDetector::scanArmPrologues(
    std::span<const std::byte> code,
    uint64_t baseAddress
) const {
    std::vector<uint64_t> addresses;
    
    if (code.empty() || !impl_) return addresses;
    
    // Scan at 4-byte aligned addresses
    for (size_t offset = 0; offset + 4 <= code.size(); offset += 4) {
        uint32_t opcode = Utils::readU32LE(code.data() + offset);
        
        if (impl_->isArmPrologue(opcode)) {
            addresses.push_back(baseAddress + offset);
        }
    }
    
    return addresses;
}

// ============================================================================
// Thumb Prologue Scanning
// ============================================================================

std::vector<uint64_t> FunctionDetector::scanThumbPrologues(
    std::span<const std::byte> code,
    uint64_t baseAddress
) const {
    std::vector<uint64_t> addresses;
    
    if (code.empty() || !impl_) return addresses;
    
    // Scan at 2-byte aligned addresses
    for (size_t offset = 0; offset + 2 <= code.size(); offset += 2) {
        uint16_t halfWord = Utils::readU16LE(code.data() + offset);
        
        if (impl_->isThumbPrologue(halfWord)) {
            addresses.push_back(baseAddress + offset);
        }
        
        // Skip potential Thumb-2 second halfword
        uint8_t prefix = (halfWord >> 11) & 0x1F;
        if (prefix == 0x1E || prefix == 0x1F) {
            offset += 2;  // Skip next halfword (it's part of this instruction)
        }
    }
    
    return addresses;
}

// ============================================================================
// ARM Function End Detection
// ============================================================================

uint64_t FunctionDetector::findArmFunctionEnd(
    uint64_t startAddress,
    std::span<const std::byte> code
) const {
    size_t startOffset = static_cast<size_t>(startAddress);
    
    if (startOffset >= code.size() || !impl_) {
        return startOffset + 4;  // Minimum size
    }
    
    size_t maxSearch = std::min(code.size() - startOffset, 
                                static_cast<size_t>(65536));
    auto searchArea = code.subspan(startOffset, maxSearch);
    
    // Scan for epilogue pattern
    for (size_t i = 4; i + 4 <= searchArea.size(); i += 4) {
        uint32_t opcode = Utils::readU32LE(searchArea.data() + i);
        
        if (impl_->isArmEpilogue(opcode)) {
            return startAddress + i + 4;  // Include the epilogue instruction
        }
    }
    
    // If no epilogue found, return end of searchable area
    return startAddress + maxSearch;
}

// ============================================================================
// Thumb Function End Detection
// ============================================================================

uint64_t FunctionDetector::findThumbFunctionEnd(
    uint64_t startAddress,
    std::span<const std::byte> code
) const {
    size_t startOffset = static_cast<size_t>(startAddress);
    
    if (startOffset >= code.size() || !impl_) {
        return startOffset + 2;  // Minimum size
    }
    
    size_t maxSearch = std::min(code.size() - startOffset, 
                                static_cast<size_t>(65536));
    auto searchArea = code.subspan(startOffset, maxSearch);
    
    // Scan for epilogue pattern
    for (size_t i = 2; i + 2 <= searchArea.size(); i += 2) {
        uint16_t halfWord = Utils::readU16LE(searchArea.data() + i);
        
        if (impl_->isThumbEpilogue(halfWord)) {
            return startAddress + i + 2;  // Include the epilogue instruction
        }
        
        // Handle Thumb-2 32-bit instructions
        uint8_t prefix = (halfWord >> 11) & 0x1F;
        if (prefix == 0x1E || prefix == 0x1F) {
            i += 2;  // Skip second halfword
        }
    }
    
    // If no epilogue found, return end of searchable area
    return startAddress + maxSearch;
}

} // namespace ida
