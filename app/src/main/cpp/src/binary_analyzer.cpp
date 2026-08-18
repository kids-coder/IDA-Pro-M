/**
 * @file binary_analyzer.cpp
 * @brief Binary Analyzer Core Implementation (PIMPL)
 * 
 * Core analysis engine for binary files supporting ELF, PE, and Mach-O formats.
 * Architecture detection for x86, ARM, AArch64, RISC-V, and MIPS.
 * 
 * @version 3.0.0
 */

#include "ida_pro_native.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>

namespace ida {

// ============================================================================
// BinaryAnalyzer::Impl - PIMPL Implementation
// ============================================================================

class BinaryAnalyzer::Impl {
public:
    // File data
    MappedFile mappedFile{};
    std::vector<std::byte> memoryData;  // For in-memory loading
    bool fromMemory{false};
    std::string filePath;
    
    // Detected properties
    BinaryFormat format{BinaryFormat::Unknown};
    Architecture architecture{Architecture::Unknown};
    uint64_t entryPoint{0};
    uint64_t imageBase{0};
    uint64_t imageSize{0};
    
    // Analysis state
    bool loaded{false};
    bool analyzed{false};
    
    // Parsed structures
    std::unique_ptr<ElfParser> elfParser;
    std::vector<SectionHeader> sections;
    std::vector<SymbolEntry> symbols;
    std::vector<SymbolEntry> dynamicSymbols;
    std::vector<Function> functions;
    
    // Lookup tables for fast access
    std::map<uint64_t, size_t> functionByStartAddr;  // start_addr -> function index
    std::map<uint64_t, size_t> symbolByAddress;       // addr -> symbol index
    std::map<std::string, size_t> symbolByName;       // name -> symbol index
    
    // Disassembler instances
    std::unique_ptr<ArmDisassembler> armDisassembler;
    std::unique_ptr<FunctionDetector> functionDetector;
    
    // Statistics
    Statistics stats{};
    
    // Mutex for thread safety
    mutable std::shared_mutex dataMutex;
    
    Impl() {
        elfParser = std::make_unique<ElfParser>();
        armDisassembler = std::make_unique<ArmDisassembler>();
        functionDetector = std::make_unique<FunctionDetector>();
    }
    
    ~Impl() = default;
    
    // Non-copyable
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    
    /// Get pointer to raw file data
    [[nodiscard]] std::span<const std::byte> getData() const noexcept {
        if (fromMemory) {
            return memoryData;
        }
        return mappedFile.asBytes();
    }
    
    /// Get data size
    [[nodiscard]] size_t getDataSize() const noexcept {
        if (fromMemory) {
            return memoryData.size();
        }
        return mappedFile.size;
    }
    
    /// Convert virtual address to file offset
    [[nodiscard]] std::optional<size_t> vaddrToOffset(uint64_t vaddr) const {
        // Simple implementation: iterate through sections to find mapping
        for (const auto& section : sections) {
            if (section.isAllocated() && 
                vaddr >= section.virtualAddr && 
                vaddr < section.virtualAddr + section.size) {
                return static_cast<size_t>(section.fileOffset + (vaddr - section.virtualAddr));
            }
        }
        return std::nullopt;
    }
    
    /// Convert file offset to virtual address
    [[nodiscard]] std::optional<uint64_t> offsetToVaddr(size_t offset) const {
        for (const auto& section : sections) {
            if (offset >= section.fileOffset && 
                offset < section.fileOffset + section.size) {
                return section.virtualAddr + (offset - section.fileOffset);
            }
        }
        return std::nullopt;
    }
};

// ============================================================================
// BinaryAnalyzer Constructor/Destructor
// ============================================================================

BinaryAnalyzer::BinaryAnalyzer() : impl_(std::make_unique<Impl>()) {
    impl_->init();  // Initialize sub-components
}

BinaryAnalyzer::~BinaryAnalyzer() {
    close();
}

BinaryAnalyzer::BinaryAnalyzer(BinaryAnalyzer&& other) noexcept : impl_(std::move(other.impl_)) {}

BinaryAnalyzer& BinaryAnalyzer::operator=(BinaryAnalyzer&& other) noexcept {
    if (this != &other) {
        close();
        impl_ = std::move(other.impl_);
    }
    return *this;
}

void BinaryAnalyzer::init() {
    // Initialization is done in Impl constructor
}

// ============================================================================
// File Loading
// ============================================================================

AnalysisResult<void> BinaryAnalyzer::loadFile(const std::filesystem::path& path) {
    close();
    
    if (!std::filesystem::exists(path)) {
        return std::unexpected(AnalysisError::FileNotFound);
    }
    
    // Map file into memory
    auto mapResult = Utils::mapFile(path);
    if (!mapResult) {
        return std::unexpected(mapResult.error());
    }
    
    impl_->mappedFile = std::move(*mapResult);
    impl_->filePath = path.string();
    impl_->fromMemory = false;
    impl_->loaded = true;
    
    // Detect format and architecture
    auto data = impl_->getData();
    if (data.empty()) {
        return std::unexpected(AnalysisError::CorruptFile);
    }
    
    impl_->format = BinaryUtils::detectFormat(data);
    impl_->architecture = BinaryUtils::detectArchitecture(data, impl_->format);
    
    // Parse format-specific structures
    return parseFormat();
}

AnalysisResult<void> BinaryAnalyzer::loadMemory(std::span<const std::byte> data, std::string_view name) {
    close();
    
    if (data.empty()) {
        return std::unexpected(AnalysisError::InvalidFormat);
    }
    
    impl_->memoryData.assign(data.begin(), data.end());
    impl_->filePath = name;
    impl_->fromMemory = true;
    impl_->loaded = true;
    
    // Detect format and architecture
    impl_->format = BinaryUtils::detectFormat(impl_->memoryData);
    impl_->architecture = BinaryUtils::detectArchitecture(impl_->memoryData, impl_->format);
    
    return parseFormat();
}

void BinaryAnalyzer::close() noexcept {
    if (impl_) {
        if (!impl_->fromMemory && impl_->mappedFile.isValid()) {
            Utils::unmapFile(impl_->mappedFile);
        }
        
        impl_->mappedFile = {};
        impl_->memoryData.clear();
        impl_->memoryData.shrink_to_fit();
        impl_->filePath.clear();
        impl_->format = BinaryFormat::Unknown;
        impl_->architecture = Architecture::Unknown;
        impl_->entryPoint = 0;
        impl_->imageBase = 0;
        impl_->imageSize = 0;
        impl_->loaded = false;
        impl_->analyzed = false;
        impl_->sections.clear();
        impl_->symbols.clear();
        impl_->dynamicSymbols.clear();
        impl_->functions.clear();
        impl_->functionByStartAddr.clear();
        impl_->symbolByAddress.clear();
        impl_->symbolByName.clear();
        impl_->stats = {};
    }
}

bool BinaryAnalyzer::isLoaded() const noexcept {
    return impl_ && impl_->loaded;
}

// ============================================================================
// Property Accessors
// ============================================================================

BinaryFormat BinaryAnalyzer::getFormat() const noexcept {
    return impl_ ? impl_->format : BinaryFormat::Unknown;
}

Architecture BinaryAnalyzer::getArchitecture() const noexcept {
    return impl_ ? impl_->architecture : Architecture::Unknown;
}

uint64_t BinaryAnalyzer::getEntryPoint() const noexcept {
    return impl_ ? impl_->entryPoint : 0;
}

uint64_t BinaryAnalyzer::getImageBase() const noexcept {
    return impl_ ? impl_->imageBase : 0;
}

uint64_t BinaryAnalyzer::getImageSize() const noexcept {
    return impl_ ? impl_->imageSize : 0;
}

const std::string& BinaryAnalyzer::getFilePath() const noexcept {
    static const std::string empty;
    return impl_ ? impl_->filePath : empty;
}

// ============================================================================
// Analysis
// ============================================================================

AnalysisResult<void> BinaryAnalyzer::analyze() {
    if (!isLoaded()) {
        return std::unexpected(AnalysisError::NotInitialized);
    }
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Format-specific parsing already done in loadFile/loadMemory
    // Now perform deeper analysis
    
    // Extract sections based on format
    switch (impl_->format) {
        case BinaryFormat::ELF:
            extractElfSections();
            break;
        case BinaryFormat::PE:
            // PE extraction placeholder
            break;
        case BinaryFormat::MachO:
            // Mach-O extraction placeholder
            break;
        default:
            break;
    }
    
    // Extract entry point
    extractEntryPoint();
    
    // Extract symbols
    extractSymbols();
    
    // Detect functions
    auto funcResult = detectFunctionsInternal();
    if (!funcResult) {
        // Non-fatal: continue without full function detection
    }
    
    // Build lookup tables
    buildLookupTables();
    
    // Calculate image size
    calculateImageSize();
    
    auto endTime = std::chrono::high_resolution_clock::now();
    impl_->stats.analysisTimeMs = 
        std::chrono::duration<double, std::milli>(endTime - startTime).count();
    
    impl_->analyzed = true;
    
    // Update statistics
    impl_->stats.totalFunctions = static_cast<uint32_t>(impl_->functions.size());
    impl_->stats.totalSymbols = static_cast<uint32_t>(impl_->symbols.size());
    
    for (const auto& func : impl_->functions) {
        impl_->stats.totalInstructions += static_cast<uint32_t>(func.instructions.size());
    }
    
    for (const auto& sec : impl_->sections) {
        if (sec.isExecutable()) {
            impl_->stats.codeSections++;
            impl_->stats.codeSize += sec.size;
        }
    }
    
    return {};
}

bool BinaryAnalyzer::isAnalyzed() const noexcept {
    return impl_ && impl_->analyzed;
}

// ============================================================================
// Section Access
// ============================================================================

std::span<const SectionHeader> BinaryAnalyzer::getSections() const noexcept {
    if (!impl_) return {};
    return impl_->sections;
}

const SectionHeader* BinaryAnalyzer::getSection(uint32_t index) const noexcept {
    if (!impl_ || index >= impl_->sections.size()) return nullptr;
    return &impl_->sections[index];
}

const SectionHeader* BinaryAnalyzer::findSection(std::string_view name) const noexcept {
    if (!impl_) return nullptr;
    
    for (const auto& section : impl_->sections) {
        if (section.name == name) {
            return &section;
        }
    }
    return nullptr;
}

// ============================================================================
// Symbol Access
// ============================================================================

std::span<const SymbolEntry> BinaryAnalyzer::getSymbols() const noexcept {
    if (!impl_) return {};
    return impl_->symbols;
}

std::span<const SymbolEntry> BinaryAnalyzer::getDynamicSymbols() const noexcept {
    if (!impl_) return {};
    return impl_->dynamicSymbols;
}

const SymbolEntry* BinaryAnalyzer::findSymbol(uint64_t address) const noexcept {
    if (!impl_) return nullptr;
    
    auto it = impl_->symbolByAddress.lower_bound(address);
    if (it != impl_->symbolByAddress.begin()) {
        --it;
        const auto& sym = impl_->symbols[it->second];
        if (sym.address <= address && address < sym.address + sym.size) {
            return &sym;
        }
    }
    return nullptr;
}

const SymbolEntry* BinaryAnalyzer::findSymbol(std::string_view name) const noexcept {
    if (!impl_) return nullptr;
    
    auto it = impl_->symbolByName.find(std::string(name));
    if (it != impl_->symbolByName.end()) {
        return &impl_->symbols[it->second];
    }
    return nullptr;
}

std::string BinaryAnalyzer::getSymbolName(uint64_t address) const {
    if (!impl_) return {};
    
    // First try exact match
    const SymbolEntry* sym = findSymbol(address);
    if (sym && sym->address == address) {
        return sym->name;
    }
    
    // Find nearest symbol before this address
    const SymbolEntry* nearest = nullptr;
    uint64_t nearestDist = UINT64_MAX;
    
    for (const auto& s : impl_->symbols) {
        if (s.address <= address) {
            uint64_t dist = address - s.address;
            if (dist < nearestDist) {
                nearestDist = dist;
                nearest = &s;
            }
        }
    }
    
    if (nearest && !nearest->name.empty()) {
        std::ostringstream oss;
        oss << nearest->name;
        if (nearestDist > 0) {
            oss << "+0x" << std::hex << nearestDist;
        }
        return oss.str();
    }
    
    // Fallback: just return hex address
    std::ostringstream oss;
    oss << "0x" << std::hex << address;
    return oss.str();
}

// ============================================================================
// Function Access
// ============================================================================

std::span<const Function> BinaryAnalyzer::getFunctions() const noexcept {
    if (!impl_) return {};
    return impl_->functions;
}

const Function* BinaryAnalyzer::findFunction(uint64_t address) const noexcept {
    if (!impl_) return nullptr;
    
    auto it = impl_->functionByStartAddr.upper_bound(address);
    if (it != impl_->functionByStartAddr.begin()) {
        --it;
        const auto& func = impl_->functions[it->second];
        if (func.contains(address)) {
            return &func;
        }
    }
    return nullptr;
}

const Function* BinaryAnalyzer::findFunction(std::string_view name) const noexcept {
    if (!impl_) return nullptr;
    
    for (const auto& func : impl_->functions) {
        if (func.name == name) {
            return &func;
        }
    }
    return nullptr;
}

// ============================================================================
// Disassembly
// ============================================================================

AnalysisResult<std::vector<Instruction>> BinaryAnalyzer::disassemble(
    uint64_t startAddress,
    uint64_t size
) {
    if (!isAnalyzed()) {
        return std::unexpected(AnalysisError::NotInitialized);
    }
    
    std::vector<Instruction> instructions;
    
    // Get code data at the specified address
    auto codeData = getDataAt(startAddress, static_cast<size_t>(size));
    if (codeData.empty()) {
        return std::unexpected(AnalysisError::InvalidOffset);
    }
    
    // Use appropriate disassembler based on architecture
    switch (impl_->architecture) {
        case Architecture::ARM:
            impl_->armDisassembler->setMode(ArmDisassembler::Mode::Arm);
            return linearSweep(startAddress, size);
            
        case Architecture::Thumb:
            impl_->armDisassembler->setMode(ArmDisassembler::Mode::Thumb2);
            return linearSweep(startAddress, size);
            
        case Architecture::AArch64:
            // AArch64 disassembly would go here
            return std::unexpected(AnalysisError::UnsupportedArchitecture);
            
        default:
            return std::unexpected(AnalysisError::UnsupportedArchitecture);
    }
}

AnalysisResult<std::vector<Instruction>> BinaryAnalyzer::disassembleFunction(const Function& func) {
    return disassemble(func.startAddress, func.size);
}

AnalysisResult<Instruction> BinaryAnalyzer::disassembleAt(uint64_t address) {
    auto result = disassemble(address, 16);  // Try up to 16 bytes
    if (result && !result->empty()) {
        return (*result)[0];
    }
    return std::unexpected(result.error());
}

std::span<const std::byte> BinaryAnalyzer::getDataAt(uint64_t address, size_t size) const noexcept {
    if (!impl_) return {};
    
    auto offset = impl_->vaddrToOffset(address);
    if (!offset.has_value()) return {};
    
    auto data = impl_->getData();
    if (*offset + size > data.size()) {
        // Adjust size if we're near end of data
        size = data.size() - *offset;
        if (size == 0) return {};
    }
    
    return data.subspan(*offset, size);
}

template<typename T>
const T* BinaryAnalyzer::readAt(uint64_t address) const noexcept {
    auto data = getDataAt(address, sizeof(T));
    if (data.size() < sizeof(T)) return nullptr;
    return reinterpret_cast<const T*>(data.data());
}

// Explicit template instantiation for common types
template const uint8_t* BinaryAnalyzer::readAt<uint8_t>(uint64_t) const noexcept;
template const uint16_t* BinaryAnalyzer::readAt<uint16_t>(uint64_t) const noexcept;
template const uint32_t* BinaryAnalyzer::readAt<uint32_t>(uint64_t) const noexcept;
template const uint64_t* BinaryAnalyzer::readAt<uint64_t>(uint64_t) const noexcept;

// ============================================================================
// Linear Sweep Disassembly
// ============================================================================

AnalysisResult<std::vector<Instruction>> BinaryAnalyzer::linearSweep(
    uint64_t startAddress,
    uint64_t endAddress
) {
    if (!isAnalyzed()) {
        return std::unexpected(AnalysisError::NotInitialized);
    }
    
    std::vector<Instruction> instructions;
    uint64_t currentAddr = startAddress;
    uint64_t size = endAddress - startAddress;
    
    auto codeData = getDataAt(startAddress, static_cast<size_t>(size));
    if (codeData.empty()) {
        return std::unexpected(AnalysisError::InvalidOffset);
    }
    
    while (currentAddr < endAddress) {
        uint64_t offsetInCode = currentAddr - startAddress;
        if (offsetInCode >= codeData.size()) break;
        
        auto remaining = codeData.subspan(static_cast<size_t>(offsetInCode));
        
        auto decodeResult = impl_->armDisassembler->decode(currentAddr, remaining);
        
        if (!decodeResult || !decodeResult->success) {
            // Create invalid instruction placeholder
            Instruction insn;
            insn.address = currentAddr;
            insn.offset = static_cast<uint32_t>(offsetInCode);
            insn.size = impl_->armDisassembler->getMode() == ArmDisassembler::Mode::Thumb ? 2 : 4;
            insn.mnemonic = ".invalid";
            insn.operands = "";
            insn.bytes = Utils::toHex(remaining.first(insn.size));
            instructions.push_back(insn);
            currentAddr += insn.size;
            continue;
        }
        
        instructions.push_back(decodeResult->instruction);
        currentAddr += decodeResult->instruction.size;
    }
    
    return instructions;
}

AnalysisResult<std::vector<Instruction>> BinaryAnalyzer::recursiveDescent(
    uint64_t startAddress,
    uint64_t maxSize
) {
    // Placeholder for recursive descent implementation
    // This would follow branches/calls recursively
    return linearSweep(startAddress, startAddress + maxSize);
}

// ============================================================================
// Hash and Checksum
// ============================================================================

uint64_t BinaryAnalyzer::getFileChecksum() const noexcept {
    if (!impl_ || !isLoaded()) return 0;
    
    auto data = impl_->getData();
    return Utils::computeChecksum(data);
}

std::array<uint8_t, 32> BinaryAnalyzer::getFileHash() const noexcept {
    if (!impl_ || !isLoaded()) {
        return {};
    }
    
    auto data = impl_->getData();
    return Utils::computeSHA256(data);
}

// ============================================================================
// Statistics
// ============================================================================

BinaryAnalyzer::Statistics BinaryAnalyzer::getStatistics() const noexcept {
    if (!impl_) return {};
    return impl_->stats;
}

// ============================================================================
// Export
// ============================================================================

AnalysisResult<std::string> BinaryAnalyzer::exportJson() const {
    if (!isAnalyzed()) {
        return std::unexpected(AnalysisError::NotInitialized);
    }
    
    std::ostringstream oss;
    oss << "{";
    oss << "\"format\":\"" << formatToString(impl_->format) << "\",";
    oss << "\"architecture\":\"" << archToString(impl_->architecture) << "\",";
    oss << "\"entryPoint\":\"0x" << std::hex << impl_->entryPoint << "\",";
    oss << "\"imageBase\":\"0x" << impl_->imageBase << "\",";
    oss << "\"imageSize\":" << std::dec << impl_->imageSize << ",";
    oss << "\"sectionCount\":" << impl_->sections.size() << ",";
    oss << "\"symbolCount\":" << impl_->symbols.size() << ",";
    oss << "\"functionCount\":" << impl_->functions.size();
    oss << "}";
    
    return oss.str();
}

// ============================================================================
// Private Implementation Methods
// ============================================================================

AnalysisResult<void> BinaryAnalyzer::parseFormat() {
    auto data = impl_->getData();
    
    switch (impl_->format) {
        case BinaryFormat::ELF: {
            auto result = impl_->elfParser->parse(data);
            if (!result) {
                return std::unexpected(result.error());
            }
            
            // Extract info from ELF parser
            impl_->entryPoint = impl_->elfParser->getEntryPoint();
            
            // Convert ELF machine type to our Architecture enum
            uint16_t machine = impl_->elfParser->getMachine();
            switch (machine) {
                case 0x003: impl_->architecture = Architecture::X86; break;      // EM_386
                case 0x003E: impl_->architecture = Architecture::X86_64; break;   // EM_X86_64
                case 0x0028: impl_->architecture = Architecture::ARM; break;      // EM_ARM
                case 0xB7: impl_->architecture = Architecture::AArch64; break;    // EM_AARCH64
                case 0xF3: impl_->architecture = Architecture::RISCV; break;     // EM_RISCV
                case 0x008: impl_->architecture = Architecture::MIPS; break;     // EM_MIPS
                default:
                    // Keep detected architecture
                    break;
            }
            break;
        }
        
        case BinaryFormat::PE:
            // PE parsing placeholder
            break;
            
        case BinaryFormat::MachO:
            // Mach-O parsing placeholder
            break;
            
        case BinaryFormat::RawBinary:
            // Raw binary - use detected architecture
            break;
            
        default:
            return std::unexpected(AnalysisError::InvalidFormat);
    }
    
    return {};
}

void BinaryAnalyzer::extractElfSections() {
    if (!impl_->elfParser->isValid()) return;
    
    auto elfSections = impl_->elfParser->getSections();
    impl_->sections.assign(elfSections.begin(), elfSections.end());
}

void BinaryAnalyzer::extractEntryPoint() {
    if (impl_->format == BinaryFormat::ELF && impl_->elfParser->isValid()) {
        impl_->entryPoint = impl_->elfParser->getEntryPoint();
        impl_->imageBase = impl_->elfParser->getBaseAddress();
    } else {
        impl_->entryPoint = BinaryUtils::getDefaultEntryPoint(impl_->architecture);
        impl_->imageBase = impl_->entryPoint > 0x10000 ? 0 : impl_->entryPoint;
    }
}

void BinaryAnalyzer::extractSymbols() {
    if (impl_->format == BinaryFormat::ELF && impl_->elfParser->isValid()) {
        auto syms = impl_->elfParser->getSymbols();
        impl_->symbols.assign(syms.begin(), syms.end());
        
        auto dynSyms = impl_->elfParser->getDynamicSymbols();
        impl_->dynamicSymbols.assign(dynSyms.begin(), dynSyms.end());
    }
}

AnalysisResult<void> BinaryAnalyzer::detectFunctionsInternal() {
    // Find code sections
    for (const auto& section : impl_->sections) {
        if (!section.isExecutable() || section.size == 0) continue;
        
        auto sectionData = impl_->elfParser->getSectionData(section);
        if (sectionData.empty()) continue;
        
        // Use function detector
        auto result = impl_->functionDetector->detectFunctions(
            sectionData,
            section.virtualAddr,
            impl_->architecture
        );
        
        if (result) {
            for (auto& func : *result) {
                impl_->functions.push_back(std::move(func));
            }
        }
    }
    
    // Also detect from symbols
    if (!impl_->symbols.empty()) {
        auto symFuncs = impl_->functionDetector->detectFromSymbols(
            impl_->symbols,
            impl_->getData(),
            impl_->imageBase,
            impl_->architecture
        );
        
        // Merge with existing functions (avoid duplicates)
        for (auto& newFunc : symFuncs) {
            bool exists = false;
            for (const auto& existing : impl_->functions) {
                if (existing.startAddress == newFunc.startAddress) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                impl_->functions.push_back(std::move(newFunc));
            }
        }
    }
    
    // Sort functions by address
    std::sort(impl_->functions.begin(), impl_->functions.end(),
              [](const Function& a, const Function& b) {
                  return a.startAddress < b.startAddress;
              });
    
    // Refine boundaries using disassembly
    impl_->functionDetector->refineBoundaries(impl_->functions, *impl_->armDisassembler);
    
    return {};
}

void BinaryAnalyzer::buildLookupTables() {
    impl_->functionByStartAddr.clear();
    impl_->symbolByAddress.clear();
    impl_->symbolByName.clear();
    
    // Build function lookup
    for (size_t i = 0; i < impl_->functions.size(); ++i) {
        impl_->functionByStartAddr[impl_->functions[i].startAddress] = i;
    }
    
    // Build symbol lookups
    for (size_t i = 0; i < impl_->symbols.size(); ++i) {
        const auto& sym = impl_->symbols[i];
        if (sym.isDefined()) {
            impl_->symbolByAddress[sym.address] = i;
        }
        if (!sym.name.empty()) {
            impl_->symbolByName[sym.name] = i;
        }
    }
}

void BinaryAnalyzer::calculateImageSize() {
    if (impl_->sections.empty()) {
        impl_->imageSize = impl_->getDataSize();
        return;
    }
    
    uint64_t maxEnd = 0;
    for (const auto& section : impl_->sections) {
        if (section.isAllocated()) {
            uint64_t end = section.virtualAddr + section.size;
            if (end > maxEnd) {
                maxEnd = end;
            }
        }
    }
    
    impl_->imageSize = maxEnd > 0 ? maxEnd - impl_->imageBase : impl_->getDataSize();
}

} // namespace ida
