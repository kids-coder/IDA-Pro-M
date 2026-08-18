/**
 * @file ida_pro_native.h
 * @brief IDA Pro M Native Analysis Library - Main Header
 * 
 * Modern C++23 binary analysis/disassembly library for Android.
 * Features: PIMPL pattern, std::expected, concepts, constexpr where possible.
 * 
 * @version 3.0.0
 * @license Proprietary
 */

#ifndef IDA_PRO_NATIVE_H
#define IDA_PRO_NATIVE_H

// C++23 Standard Library Headers
#include <expected>
#include <concepts>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <span>
#include <optional>
#include <variant>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <system_error>

// Platform-specific headers
#if defined(__ANDROID__) || defined(ANDROID)
    #include <jni.h>
    #include <android/log.h>
    #include <sys/mman.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

namespace ida {

// ============================================================================
// Version Information
// ============================================================================

struct VersionInfo {
    static constexpr uint32_t MAJOR = IDA_PRO_NATIVE_VERSION_MAJOR;
    static constexpr uint32_t MINOR = IDA_PRO_NATIVE_VERSION_MINOR;
    static constexpr uint32_t PATCH = IDA_PRO_NATIVE_VERSION_PATCH;
    
    [[nodiscard]] static constexpr std::string_view toString() noexcept {
        return "3.0.0";
    }
};

// ============================================================================
// Error Types
// ============================================================================

enum class AnalysisError : uint8_t {
    None = 0,
    FileNotFound,
    FileAccessDenied,
    InvalidFormat,
    UnsupportedArchitecture,
    CorruptFile,
    OutOfMemory,
    InvalidOffset,
    ParseError,
    NotInitialized,
    DisassemblyError,
    UnknownError
};

[[nodiscard]] constexpr std::string_view errorToString(AnalysisError err) noexcept {
    switch (err) {
        case AnalysisError::None:                  return "No error";
        case AnalysisError::FileNotFound:          return "File not found";
        case AnalysisError::FileAccessDenied:      return "Access denied";
        case AnalysisError::InvalidFormat:         return "Invalid format";
        case AnalysisError::UnsupportedArchitecture: return "Unsupported architecture";
        case AnalysisError::CorruptFile:           return "Corrupt file";
        case AnalysisError::OutOfMemory:           return "Out of memory";
        case AnalysisError::InvalidOffset:         return "Invalid offset";
        case AnalysisError::ParseError:            return "Parse error";
        case AnalysisError::NotInitialized:        return "Not initialized";
        case AnalysisError::DisassemblyError:      return "Disassembly error";
        case AnalysisError::UnknownError:          return "Unknown error";
    }
    return "Unknown error";
}

template<typename T>
using AnalysisResult = std::expected<T, AnalysisError>;

// ============================================================================
// Architecture Enumeration
// ============================================================================

enum class Architecture : uint8_t {
    Unknown = 0,
    X86,
    X86_64,
    ARM,
    Thumb,
    AArch64,
    RISCV32,
    RISCV64,
    MIPS,
    MIPS64
};

[[nodiscard]] constexpr std::string_view archToString(Architecture arch) noexcept {
    switch (arch) {
        case Architecture::X86:       return "x86 (32-bit)";
        case Architecture::X86_64:    return "x86_64 (64-bit)";
        case Architecture::ARM:       return "ARM (32-bit)";
        case Architecture::Thumb:     return "Thumb (16/32-bit)";
        case Architecture::AArch64:   return "AArch64 (ARM64)";
        case Architecture::RISCV32:   return "RISC-V 32-bit";
        case Architecture::RISCV64:   return "RISC-V 64-bit";
        case Architecture::MIPS:      return "MIPS 32-bit";
        case Architecture::MIPS64:    return "MIPS 64-bit";
        default:                      return "Unknown";
    }
}

[[nodiscard]] constexpr bool isArmFamily(Architecture arch) noexcept {
    return arch == Architecture::ARM || 
           arch == Architecture::Thumb || 
           arch == Architecture::AArch64;
}

[[nodiscard]] constexpr bool is64Bit(Architecture arch) noexcept {
    return arch == Architecture::X86_64 || 
           arch == Architecture::AArch64 ||
           arch == Architecture::RISCV64 ||
           arch == Architecture::MIPS64;
}

// ============================================================================
// Binary Format Enumeration
// ============================================================================

enum class BinaryFormat : uint8_t {
    Unknown = 0,
    ELF,
    PE,
    MachO,
    RawBinary
};

[[nodiscard]] constexpr std::string_view formatToString(BinaryFormat fmt) noexcept {
    switch (fmt) {
        case BinaryFormat::ELF:        return "ELF";
        case BinaryFormat::PE:         return "PE (Windows)";
        case BinaryFormat::MachO:      return "Mach-O (macOS/iOS)";
        case BinaryFormat::RawBinary:  return "Raw Binary";
        default:                       return "Unknown";
    }
}

// ============================================================================
// Data Structures
// ============================================================================

#pragma pack(push, 1)

/// Represents a single decoded instruction
struct Instruction {
    uint64_t address{0};              ///< Virtual address of instruction
    uint32_t offset{0};               ///< File offset of instruction
    uint32_t size{0};                 ///< Instruction size in bytes
    uint32_t opcode{0};               ///< Raw opcode bytes (up to 4 bytes)
    std::string mnemonic{};           ///< Instruction mnemonic (e.g., "MOV", "BL")
    std::string operands{};           ///< Operand string (e.g., "R0, [SP, #4]")
    std::string bytes{};              ///< Hex representation of raw bytes
    
    bool isBranch{false};             ///< Is this a branch instruction?
    bool isCall{false};               ///< Is this a call instruction?
    bool isReturn{false};             ///< Is this a return instruction?
    bool isConditional{false};        ///< Is this conditional execution?
    
    std::optional<uint64_t> branchTarget; ///< Target address if branch/call
    std::optional<std::string> referenceName; ///< Symbol name if referencing one
    
    /// Check if instruction is valid
    [[nodiscard]] constexpr bool isValid() const noexcept {
        return size > 0 && !mnemonic.empty();
    }
    
    /// Reset instruction to empty state
    void reset() noexcept {
        address = 0;
        offset = 0;
        size = 0;
        opcode = 0;
        mnemonic.clear();
        operands.clear();
        bytes.clear();
        isBranch = false;
        isCall = false;
        isReturn = false;
        isConditional = false;
        branchTarget.reset();
        referenceName.reset();
    }
};

/// Represents a detected function in the binary
struct Function {
    uint64_t startAddress{0};         ///< Function start address
    uint64_t endAddress{0};           ///< Function end address (exclusive)
    uint32_t size{0};                 ///< Function size in bytes
    std::string name{};               ///< Function name (from symbols or generated)
    
    enum class Type : uint8_t {
        Unknown,
        Normal,                        ///< Regular function
        Thunk,                         ///< Trampoline/thunk function
        Import,                        ///< Imported function
        Export,                        ///< Exported function
        Stub                           ///< Stub/placholder function
    } type{Type::Unknown};
    
    enum class CallingConvention : uint8_t {
        Unknown,
        AAPCS,                         ///< ARM Architecture Procedure Call Std
        AAPCS_VFP,                     ///< AAPCS with VFP registers
        CDecl,                         ///< x86 C declaration
        StdCall,                       ///< x86 Standard call
        FastCall                       ///< x86 Fast call
    } callingConvention{CallingConvention::Unknown};
    
    std::vector<Instruction> instructions; ///< Disassembled instructions
    std::vector<uint64_t> callers;         ///< Addresses that call this function
    std::vector<uint64_t> callees;         ///< Addresses called by this function
    
    /// Calculate function size from addresses
    [[nodiscard]] constexpr uint32_t calculatedSize() const noexcept {
        return static_cast<uint32_t>(endAddress - startAddress);
    }
    
    /// Check if address falls within this function
    [[nodiscard]] constexpr bool contains(uint64_t addr) const noexcept {
        return addr >= startAddress && addr < endAddress;
    }
    
    /// Check if function has been fully disassembled
    [[nodiscard]] bool isFullyDisassembled() const noexcept {
        if (size == 0) return false;
        uint32_t totalInsnSize = 0;
        for (const auto& insn : instructions) {
            totalInsnSize += insn.size;
        }
        return totalInsnSize >= size;
    }
};

/// Entry in the symbol table
struct SymbolEntry {
    uint64_t address{0};              ///< Symbol address/value
    uint64_t size{0};                 ///< Symbol size (0 if unknown)
    uint32_t nameOffset{0};           ///< Offset into string table
    uint16_t sectionIndex{0};         ///< Section index (SHN_XINDEX for large)
    
    enum class Type : uint8_t {
        None = 0,
        Object,                        ///< Variable/object
        Function,                      ///< Function/code
        Section,                       ///< Section symbol
        File,                          ///< Source file name
        Common,                        ///< Common block
        TLS                            ///< Thread-local storage
    } type{Type::None};
    
    enum class Binding : uint8_t {
        Local,                         ///< Local symbol
        Global,                        ///< Global symbol
        Weak,                          ///< Weak symbol
        GNUUnique                      ///< GNU unique symbol
    } binding{Binding::Local};
    
    enum class Visibility : uint8_t {
        Default,
        Internal,
        Hidden,
        Protected
    } visibility{Visibility::Default};
    
    std::string name{};               ///< Symbol name (resolved)
    
    [[nodiscard]] constexpr bool isFunction() const noexcept {
        return type == Type::Function;
    }
    
    [[nodiscard]] constexpr bool isGlobal() const noexcept {
        return binding == Binding::Global || binding == Binding::Weak;
    }
    
    [[nodiscard]] constexpr bool isDefined() const noexcept {
        return sectionIndex != 0;  // SHN_UNDEF = 0
    }
};

/// ELF Section Header
struct SectionHeader {
    uint32_t index{0};                ///< Section index
    uint64_t nameOffset{0};           ///< Name offset in string table
    uint64_t type{0};                 ///< Section type (SHT_*)
    uint64_t flags{0};                ///< Section flags (SHF_*)
    uint64_t virtualAddr{0};          ///< Virtual address (in memory)
    uint64_t fileOffset{0};           ///< File offset
    uint64_t size{0};                 ///< Section size
    uint32_t link{0};                 ///< Link to another section
    uint32_t info{0};                 ///< Additional info
    uint64_t addralign{0};            ///< Alignment
    uint64_t entrySize{0};            ///< Entry size (if table)
    
    std::string name{};               ///< Resolved section name
    
    /// Check if section contains executable code
    [[nodiscard]] constexpr bool isExecutable() const noexcept {
        return (flags & 0x4) != 0;  // SHF_EXECINSTR
    }
    
    /// Check if section is writable
    [[nodiscard]] constexpr bool isWritable() const noexcept {
        return (flags & 0x1) != 0;  // SHF_WRITE
    }
    
    /// Check if section is allocated in memory
    [[nodiscard]] constexpr bool isAllocated() const noexcept {
        return (flags & 0x2) != 0;  // SHF_ALLOC
    }
    
    /// Check if this is a null section
    [[nodiscard]] constexpr bool isNull() const noexcept {
        return type == 0;
    }
    
    /// Get number of entries (for tables)
    [[nodiscard]] constexpr uint32_t entryCount() const noexcept {
        return entrySize > 0 ? static_cast<uint32_t>(size / entrySize) : 0;
    }
};

/// Memory-mapped file wrapper
struct MappedFile {
    void* data{nullptr};              ///< Pointer to mapped data
    size_t size{0};                   ///< Size of mapped region
    int fd{-1};                       ///< File descriptor
    bool owned{true};                 ///< Whether we own the mapping
    
    [[nodiscard]] constexpr bool isValid() const noexcept {
        return data != nullptr && size > 0;
    }
    
    [[nodiscard]] constexpr std::span<const std::byte> asBytes() const noexcept {
        return {static_cast<const std::byte*>(data), size};
    }
    
    template<typename T>
    [[nodiscard]] const T* at(size_t offset) const noexcept {
        if (offset + sizeof(T) > size) return nullptr;
        return reinterpret_cast<const T*>(static_cast<const std::byte*>(data) + offset);
    }
    
    template<typename T>
    [[nodiscard]] const T* atChecked(size_t offset) const {
        if (offset + sizeof(T) > size) {
            throw std::out_of_range("MappedFile access out of range");
        }
        return reinterpret_cast<const T*>(static_cast<const std::byte*>(data) + offset);
    }
};

#pragma pack(pop)

// ============================================================================
// Concepts for Type Constraints
// =================================================================namespace

template<typename T>
concept ReadableContainer = requires(T t) {
    { t.data() } -> std::convertible_to<const std::byte*>;
    { t.size() } -> std::convertible_to<size_t>;
};

template<typename T>
concept BinaryParser = requires(T parser, std::span<const std::byte> data) {
    { parser.parse(data) } -> std::same_as<AnalysisResult<void>>;
    { parser.getFormat() } -> std::same_as<BinaryFormat>;
    { parser.getArchitecture() } -> std::same_as<Architecture>;
};

// ============================================================================
// Utils Namespace
// ============================================================================

namespace Utils {

/// Convert bytes to hex string
[[nodiscard]] std::string toHex(std::span<const std::byte> data, bool uppercase = false) noexcept;

/// Convert bytes to hex string with spaces between bytes
[[nodiscard]] std::string toHexSpaced(std::span<const std::byte> data, bool uppercase = false) noexcept;

/// Convert single byte to hex (2 characters)
[[nodiscard]] constexpr char byteToHexChar(uint8_t nibble, bool uppercase = false) noexcept {
    constexpr std::array lowerChars = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    constexpr std::array upperChars = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    return uppercase ? upperChars[nibble & 0xF] : lowerChars[nibble & 0xF];
}

/// Parse hex string to bytes
[[nodiscard]] AnalysisResult<std::vector<uint8_t>> fromHex(std::string_view hex) noexcept;

/// Memory-map a file for reading
[[nodiscard]] AnalysisResult<MappedFile> mapFile(const std::filesystem::path& path) noexcept;

/// Unmap a previously mapped file
void unmapFile(MappedFile& mapped) noexcept;

/// Compute SHA-256 hash (placeholder - use real crypto in production)
[[nodiscard]] std::array<uint8_t, 32> computeSHA256(std::span<const std::byte> data) noexcept;

/// Compute simple checksum (FNV-1a variant)
[[nodiscard]] constexpr uint64_t computeChecksum(std::span<const std::byte> data) noexcept {
    uint64_t hash = 14695981039346656037ULL;
    for (const auto byte : data) {
        hash ^= static_cast<uint8_t>(byte);
        hash *= 1099511628211ULL;
    }
    return hash;
}

/// Compute CRC32 checksum
[[nodiscard]] uint32_t computeCRC32(std::span<const std::byte> data) noexcept;

/// Safe string copy with bounds checking
[[nodiscard]] size_t safeStrCopy(char* dest, std::string_view src, size_t maxSize) noexcept;

/// UTF-8 to JNI modified UTF-8 conversion
[[nodiscard]] std::string toModifiedUTF8(std::string_view utf8);

/// JNI modified UTF-8 to UTF-8 conversion  
[[nodiscard]] std::string fromModifiedUTF8(std::string_view mutf8);

/// Align value to boundary
[[nodiscard]] constexpr uintptr_t alignTo(uintptr_t value, uintptr_t alignment) noexcept {
    return (value + alignment - 1) & ~(alignment - 1);
}

/// Check if value is aligned
[[nodiscard]] constexpr bool isAligned(uintptr_t value, uintptr_t alignment) noexcept {
    return (value & (alignment - 1)) == 0;
}

/// Read little-endian 16-bit value
[[nodiscard]] constexpr uint16_t readU16LE(const void* ptr) noexcept {
    auto bytes = static_cast<const uint8_t*>(ptr);
    return static_cast<uint16_t>(bytes[0]) | (static_cast<uint16_t>(bytes[1]) << 8);
}

/// Read little-endian 32-bit value
[[nodiscard]] constexpr uint32_t readU32LE(const void* ptr) noexcept {
    auto bytes = static_cast<const uint8_t*>(ptr);
    return static_cast<uint32_t>(bytes[0]) | 
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

/// Read little-endian 64-bit value
[[nodiscard]] constexpr uint64_t readU64LE(const void* ptr) noexcept {
    auto bytes = static_cast<const uint8_t*>(ptr);
    uint64_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    }
    return result;
}

/// Write little-endian 16-bit value
constexpr void writeU16LE(void* ptr, uint16_t value) noexcept {
    auto bytes = static_cast<uint8_t*>(ptr);
    bytes[0] = static_cast<uint8_t>(value);
    bytes[1] = static_cast<uint8_t>(value >> 8);
}

/// Write little-endian 32-bit value
constexpr void writeU32LE(void* ptr, uint32_t value) noexcept {
    auto bytes = static_cast<uint8_t*>(ptr);
    bytes[0] = static_cast<uint8_t>(value);
    bytes[1] = static_cast<uint8_t>(value >> 8);
    bytes[2] = static_cast<uint8_t>(value >> 16);
    bytes[3] = static_cast<uint8_t>(value >> 24);
}

} // namespace Utils

// ============================================================================
// BinaryUtils Namespace
// ============================================================================

namespace BinaryUtils {

/// Detect binary format from magic bytes
[[nodiscard]] BinaryFormat detectFormat(std::span<const std::byte> header) noexcept;

/// Detect architecture from ELF header or PE header
[[nodiscard]] Architecture detectArchitecture(std::span<const std::byte> header, BinaryFormat fmt) noexcept;

/// Detect if ARM binary uses Thumb mode by default
[[nodiscard]] bool detectThumbMode(std::span<const std::byte> elfHeader) noexcept;

/// Get default entry point for architecture
[[nodiscard]] constexpr uint64_t getDefaultEntryPoint(Architecture arch) noexcept {
    switch (arch) {
        case Architecture::AArch64: return 0x400000ULL + 0x1000; // Typical AArch64 base
        case Architecture::ARM:
        case Architecture::Thumb:   return 0x8000ULL;  // Typical ARM base
        case Architecture::X86:
        case Architecture::X86_64:  return 0x400000ULL + 0x1000; // Typical x86 base
        default:                    return 0;
    }
}

/// Get instruction set characteristics
struct ArchCharacteristics {
    uint8_t minInstructionSize{1};
    uint8_t maxInstructionSize{4};
    uint8_t defaultInstructionSize{4};
    bool hasVariableLength{false};
    bool hasDelaySlot{false};
    bool isLittleEndian{true};
    uint8_t registerSize{32};
    uint8_t wordSize{32};
};

[[nodiscard]] constexpr ArchCharacteristics getArchCharacteristics(Architecture arch) noexcept {
    ArchCharacteristics chars{};
    switch (arch) {
        case Architecture::ARM:
            chars.minInstructionSize = 4;
            chars.maxInstructionSize = 4;
            chars.defaultInstructionSize = 4;
            chars.registerSize = 32;
            chars.wordSize = 32;
            break;
        case Architecture::Thumb:
            chars.minInstructionSize = 2;
            chars.maxInstructionSize = 4;
            chars.defaultInstructionSize = 2;
            chars.hasVariableLength = true;
            chars.registerSize = 32;
            chars.wordSize = 32;
            break;
        case Architecture::AArch64:
            chars.minInstructionSize = 4;
            chars.maxInstructionSize = 4;
            chars.defaultInstructionSize = 4;
            chars.registerSize = 64;
            chars.wordSize = 64;
            break;
        case Architecture::X86:
            chars.minInstructionSize = 1;
            chars.maxInstructionSize = 15;
            chars.defaultInstructionSize = 4;
            chars.hasVariableLength = true;
            chars.registerSize = 32;
            chars.wordSize = 32;
            break;
        case Architecture::X86_64:
            chars.minInstructionSize = 1;
            chars.maxInstructionSize = 15;
            chars.defaultInstructionSize = 4;
            chars.hasVariableLength = true;
            chars.registerSize = 64;
            chars.wordSize = 64;
            break;
        case Architecture::RISCV32:
            chars.minInstructionSize = 2;
            chars.maxInstructionSize = 4;
            chars.defaultInstructionSize = 4;
            chars.hasVariableLength = true;
            chars.registerSize = 32;
            chars.wordSize = 32;
            break;
        case Architecture::RISCV64:
            chars.minInstructionSize = 2;
            chars.maxInstructionSize = 4;
            chars.defaultInstructionSize = 4;
            chars.hasVariableLength = true;
            chars.registerSize = 64;
            chars.wordSize = 64;
            break;
        case Architecture::MIPS:
        case Architecture::MIPS64:
            chars.minInstructionSize = 4;
            chars.maxInstructionSize = 4;
            chars.defaultInstructionSize = 4;
            chars.hasDelaySlot = true;
            chars.registerSize = (arch == Architecture::MIPS64) ? 64 : 32;
            chars.wordSize = (arch == Architecture::MIPS64) ? 64 : 32;
            break;
        default:
            break;
    }
    return chars;
}

} // namespace BinaryUtils

// ============================================================================
// Simple Thread Pool
// ============================================================================

class SimpleThreadPool {
public:
    explicit SimpleThreadPool(size_t numThreads = 0);
    ~SimpleThreadPool();
    
    // Non-copyable, non-movable
    SimpleThreadPool(const SimpleThreadPool&) = delete;
    SimpleThreadPool& operator=(const SimpleThreadPool&) = delete;
    SimpleThreadPool(SimpleThreadPool&&) = delete;
    SimpleThreadPool& operator=(SimpleThreadPool&&) = delete;
    
    /// Submit a task to the pool
    using Task = std::function<void()>;
    void submit(Task task);
    
    /// Wait for all pending tasks to complete
    void waitForAll();
    
    /// Get number of worker threads
    [[nodiscard]] size_t threadCount() const noexcept;
    
    /// Check if pool is running
    [[nodiscard]] bool isRunning() const noexcept;
    
    /// Initialize global thread pool (call once)
    static void initializeGlobal(size_t numThreads = 0);
    
    /// Shutdown global thread pool
    static void shutdownGlobal();
    
    /// Get global thread pool instance
    [[nodiscard]] static SimpleThreadPool* global() noexcept;
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    
    static std::unique_ptr<SimpleThreadPool> globalInstance_;
    static std::mutex globalMutex_;
};

// ============================================================================
// ElfParser Class
// ============================================================================

class ElfParser {
public:
    ElfParser();
    ~ElfParser();
    
    // Non-copyable
    ElfParser(const ElfParser&) = delete;
    ElfParser& operator=(const ElfParser&) = delete;
    
    /// Parse ELF file from memory
    AnalysisResult<void> parse(std::span<const std::byte> data);
    
    /// Check if valid ELF was parsed
    [[nodiscard]] bool isValid() const noexcept;
    
    /// Get ELF class (32 or 64 bit)
    [[nodiscard]] uint8_t getClass() const noexcept;
    
    /// Get ELF endianness (1=LE, 2=BE)
    [[nodiscard]] uint8_t getEndianness() const noexcept;
    
    /// Get machine/architecture type
    [[nodiscard]] uint16_t getMachine() const noexcept;
    
    /// Get entry point address
    [[nodiscard]] uint64_t getEntryPoint() const noexcept;
    
    /// Get program header count
    [[nodiscard]] uint16_t getProgramHeaderCount() const noexcept;
    
    /// Get section header count
    [[nodiscard]] uint16_t getSectionHeaderCount() const noexcept;
    
    /// Get section headers
    [[nodiscard]] std::span<const SectionHeader> getSections() const noexcept;
    
    /// Find section by name
    [[nodiscard]] const SectionHeader* findSection(std::string_view name) const noexcept;
    
    /// Get section data
    [[nodiscard]] std::span<const std::byte> getSectionData(const SectionHeader& section) const noexcept;
    
    /// Get symbol table entries
    [[nodiscard]] std::span<const SymbolEntry> getSymbols() const noexcept;
    
    /// Get dynamic symbol table entries
    [[nodiscard]] std::span<const SymbolEntry> getDynamicSymbols() const noexcept;
    
    /// Find symbol by address
    [[nodiscard]] const SymbolEntry* findSymbol(uint64_t address) const noexcept;
    
    /// Find symbol by name
    [[nodiscard]] const SymbolEntry* findSymbol(std::string_view name) const noexcept;
    
    /// Get string from string table
    [[nodiscard]] std::string getString(uint64_t offset) const;
    
    /// Get base address for loading
    [[nodiscard]] uint64_t getBaseAddress() const noexcept;
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    
    /// Parse ELF32 header and structures
    AnalysisResult<void> parseELF32(std::span<const std::byte> data);
    
    /// Parse ELF64 header and structures
    AnalysisResult<void> parseELF64(std::span<const std::byte> data);
};

// ============================================================================
// ArmDisassembler Class
// ============================================================================

class ArmDisassembler {
public:
    enum class Mode : uint8_t {
        Arm,       ///< ARM mode (32-bit instructions)
        Thumb,     ///< Thumb mode (16-bit instructions)
        Thumb2     ///< Thumb-2 mode (mixed 16/32-bit)
    };
    
    struct DecodeResult {
        Instruction instruction;
        bool success{false};
        AnalysisError error{AnalysisError::None};
        
        [[nodiscard]] constexpr explicit operator bool() const noexcept {
            return success;
        }
    };
    
    explicit ArmDisassembler(Mode mode = Mode::Arm);
    ~ArmDisassembler();
    
    // Non-copyable but movable
    ArmDisassembler(const ArmDisassembler&) = delete;
    ArmDisassembler& operator=(const ArmDisassembler&) = delete;
    ArmDisassembler(ArmDisassembler&&) noexcept;
    ArmDisassembler& operator=(ArmDisassembler&&) noexcept;
    
    /// Set disassembly mode
    void setMode(Mode mode) noexcept;
    
    /// Get current mode
    [[nodiscard]] Mode getMode() const noexcept;
    
    /// Decode single instruction at address
    DecodeResult decode(uint64_t address, std::span<const std::byte> code) const;
    
    /// Decode multiple instructions
    std::vector<DecodeResult> decodeBlock(
        uint64_t startAddress, 
        std::span<const std::byte> code,
        size_t maxInstructions = 0
    ) const;
    
    /// Determine instruction size for current mode
    [[nodiscard]] uint8_t getInstructionSize(uint16_t thumbHalfWord) const noexcept;
    
    /// Format instruction for display
    [[nodiscard]] std::string formatInstruction(const Instruction& insn) const;
    
    /// Check if instruction is a prologue pattern
    [[nodiscard]] bool isPrologue(const Instruction& insn) const noexcept;
    
    /// Check if instruction is an epilogue pattern
    [[nodiscard]] bool isEpilogue(const Instruction& insn) const noexcept;
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    
    /// Decode ARM mode instruction (32-bit)
    DecodeResult decodeArm(uint64_t address, uint32_t opcode) const;
    
    /// Decode Thumb mode instruction (16-bit)
    DecodeResult decodeThumb16(uint64_t address, uint16_t opcode) const;
    
    /// Decode Thumb-2 instruction (32-bit)
    DecodeResult decodeThumb2(uint64_t address, uint32_t opcode) const;
    
    /// Data processing instructions (ARM)
    DecodeResult decodeDataProcessing(uint64_t address, uint32_t opcode) const;
    
    /// Load/store instructions (ARM)
    DecodeResult decodeLoadStore(uint64_t address, uint32_t opcode) const;
    
    /// Branch instructions (ARM)
    DecodeResult decodeBranch(uint64_t address, uint32_t opcode) const;
    
    /// Multiply instructions (ARM)
    DecodeResult decodeMultiply(uint64_t address, uint32_t opcode) const;
};

// ============================================================================
// FunctionDetector Class
// ============================================================================

class FunctionDetector {
public:
    FunctionDetector();
    ~FunctionDetector();
    
    // Non-copyable
    FunctionDetector(const FunctionDetector&) = delete;
    FunctionDetector& operator=(const FunctionDetector&) = delete;
    
    /// Detect functions in code section
    AnalysisResult<std::vector<Function>> detectFunctions(
        std::span<const std::byte> code,
        uint64_t baseAddress,
        Architecture arch
    );
    
    /// Detect functions using symbol table hints
    std::vector<Function> detectFromSymbols(
        std::span<const SymbolEntry> symbols,
        std::span<const std::byte> code,
        uint64_t baseAddress,
        Architecture arch
    );
    
    /// Refine function boundaries
    void refineBoundaries(
        std::vector<Function>& functions,
        const ArmDisassembler& disasm
    ) const;
    
    /// Estimate function size from prologue/epilogue analysis
    [[nodiscard]] uint32_t estimateFunctionSize(
        uint64_t startAddress,
        std::span<const std::byte> code,
        Architecture arch
    ) const;
    
    /// Set minimum function size threshold
    void setMinFunctionSize(uint32_t size) noexcept;
    
    /// Get minimum function size threshold
    [[nodiscard]] uint32_t getMinFunctionSize() const noexcept;
    
    /// Prologue patterns for detection
    struct ProloguePattern {
        std::vector<uint32_t> armPatterns;    ///< ARM mode prologue opcodes
        std::vector<uint16_t> thumbPatterns;  ///< Thumb mode prologue halfwords
        std::string description;
    };
    
    /// Add custom prologue pattern
    void addProloguePattern(const ProloguePattern& pattern);
    
    /// Epilogue patterns for detection
    struct EpiloguePattern {
        std::vector<uint32_t> armPatterns;
        std::vector<uint16_t> thumbPatterns;
        std::string description;
    };
    
    /// Add custom epilogue pattern
    void addEpiloguePattern(const EpiloguePattern& pattern);
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    
    /// Scan for ARM prologues
    std::vector<uint64_t> scanArmPrologues(
        std::span<const std::byte> code,
        uint64_t baseAddress
    ) const;
    
    /// Scan for Thumb prologues
    std::vector<uint64_t> scanThumbPrologues(
        std::span<const std::byte> code,
        uint64_t baseAddress
    ) const;
    
    /// Match ARM function end
    [[nodiscard]] uint64_t findArmFunctionEnd(
        uint64_t startAddress,
        std::span<const std::byte> code
    ) const;
    
    /// Match Thumb function end
    [[nodiscard]] uint64_t findThumbFunctionEnd(
        uint64_t startAddress,
        std::span<const std::byte> code
    ) const;
};

// ============================================================================
// BinaryAnalyzer Class (PIMPL Pattern)
// ============================================================================

class BinaryAnalyzer {
public:
    BinaryAnalyzer();
    ~BinaryAnalyzer();
    
    // Non-copyable, movable
    BinaryAnalyzer(const BinaryAnalyzer&) = delete;
    BinaryAnalyzer& operator=(const BinaryAnalyzer&) = delete;
    BinaryAnalyzer(BinaryAnalyzer&&) noexcept;
    BinaryAnalyzer& operator=(BinaryAnalyzer&&) noexcept;
    
    /// Load binary from file path
    AnalysisResult<void> loadFile(const std::filesystem::path& path);
    
    /// Load binary from memory
    AnalysisResult<void> loadMemory(std::span<const std::byte> data, std::string_view name = "memory");
    
    /// Close loaded binary and free resources
    void close() noexcept;
    
    /// Check if binary is loaded
    [[nodiscard]] bool isLoaded() const noexcept;
    
    /// Get detected binary format
    [[nodiscard]] BinaryFormat getFormat() const noexcept;
    
    /// Get detected architecture
    [[nodiscard]] Architecture getArchitecture() const noexcept;
    
    /// Get entry point address
    [[nodiscard]] uint64_t getEntryPoint() const noexcept;
    
    /// Get image base address
    [[nodiscard]] uint64_t getImageBase() const noexcept;
    
    /// Get total image size
    [[nodiscard]] uint64_t getImageSize() const noexcept;
    
    /// Get file path
    [[nodiscard]] const std::string& getFilePath() const noexcept;
    
    /// Analyze binary structure
    AnalysisResult<void> analyze();
    
    /// Check if analysis is complete
    [[nodiscard]] bool isAnalyzed() const noexcept;
    
    /// Get all sections
    [[nodiscard]] std::span<const SectionHeader> getSections() const noexcept;
    
    /// Get section by index
    [[nodiscard]] const SectionHeader* getSection(uint32_t index) const noexcept;
    
    /// Get section by name
    [[nodiscard]] const SectionHeader* findSection(std::string_view name) const noexcept;
    
    /// Get all symbols
    [[nodiscard]] std::span<const SymbolEntry> getSymbols() const noexcept;
    
    /// Get dynamic symbols
    [[nodiscard]] std::span<const SymbolEntry> getDynamicSymbols() const noexcept;
    
    /// Find symbol by address
    [[nodiscard]] const SymbolEntry* findSymbol(uint64_t address) const noexcept;
    
    /// Find symbol by name
    [[nodiscard]] const SymbolEntry* findSymbol(std::string_view name) const noexcept;
    
    /// Get symbol name for address (or nearest)
    [[nodiscard]] std::string getSymbolName(uint64_t address) const;
    
    /// Get all detected functions
    [[nodiscard]] std::span<const Function> getFunctions() const noexcept;
    
    /// Find function containing address
    [[nodiscard]] const Function* findFunction(uint64_t address) const noexcept;
    
    /// Find function by name
    [[nodiscard]] const Function* findFunction(std::string_view name) const noexcept;
    
    /// Disassemble address range
    AnalysisResult<std::vector<Instruction>> disassemble(
        uint64_t startAddress,
        uint64_t size
    );
    
    /// Disassemble entire function
    AnalysisResult<std::vector<Instruction>> disassembleFunction(const Function& func);
    
    /// Disassemble single instruction
    AnalysisResult<Instruction> disassembleAt(uint64_t address);
    
    /// Get raw data at virtual address
    [[nodiscard]] std::span<const std::byte> getDataAt(uint64_t address, size_t size) const noexcept;
    
    /// Read value at virtual address
    template<typename T>
    [[nodiscard]] const T* readAt(uint64_t address) const noexcept;
    
    /// Linear sweep disassembly (basic)
    AnalysisResult<std::vector<Instruction>> linearSweep(
        uint64_t startAddress,
        uint64_t endAddress
    );
    
    /// Recursive descent disassembly placeholder
    AnalysisResult<std::vector<Instruction>> recursiveDescent(
        uint64_t startAddress,
        uint64_t maxSize
    );
    
    /// Get file checksum
    [[nodiscard]] uint64_t getFileChecksum() const noexcept;
    
    /// Get SHA-256 hash
    [[nodiscard]] std::array<uint8_t, 32> getFileHash() const noexcept;
    
    /// Get analysis statistics
    struct Statistics {
        uint32_t totalFunctions{0};
        uint32_t totalInstructions{0};
        uint32_t totalSymbols{0};
        uint32_t codeSections{0};
        uint64_t codeSize{0};
        double analysisTimeMs{0.0};
    };
    
    [[nodiscard]] Statistics getStatistics() const noexcept;
    
    /// Export analysis results (placeholder for serialization)
    AnalysisResult<std::string> exportJson() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    
    /// Internal initialization
    void init();
    
    /// Perform format-specific parsing
    AnalysisResult<void> parseFormat();
    
    /// Run function detection
    AnalysisResult<void> detectFunctionsInternal();
    
    /// Build address lookup tables
    void buildLookupTables();
};

// ============================================================================
// JNI Interface Functions (Android only)
// ============================================================================

#if defined(__ANDROID__) || defined(ANDROID)

namespace jni {

/// Java class paths
inline constexpr std::string_view NATIVE_ANALYZER_CLASS = 
    "com/idapro/native/NativeBinaryAnalyzer";

/// Initialize JNI bindings
[[nodiscard]] jint registerNatives(JNIEnv* env);

/// Create new analyzer instance
[[nodiscard]] jlong createAnalyzer();

/// Destroy analyzer instance
void destroyAnalyzer(jlong handle);

/// Load file through JNI
[[nodiscard]] jstring jniLoadFile(jlong handle, JNIEnv* env, jstring path);

/// Get format string
[[nodiscard]] jstring jniGetFormat(jlong handle, JNIEnv* env);

/// Get architecture string
[[nodiscard]] jstring jniGetArchitecture(jlong handle, JNIEnv* env);

/// Get entry point
[[nodiscard]] jlong jniGetEntryPoint(jlong handle);

/// Get function count
[[nodiscard]] jint jniGetFunctionCount(jlong handle);

/// Get function info as JSON string
[[nodiscard]] jstring jniGetFunctionInfo(jlong handle, JNIEnv* env, jint index);

/// Get symbol count
[[nodiscard]] jint jniGetSymbolCount(jlong handle);

/// Get symbol info as JSON string
[[nodiscard]] jstring jniGetSymbolInfo(jlong handle, JNIEnv* env, jint index);

/// Disassemble range
[[nodiscard]] jstring jniDisassemble(jlong handle, JNIEnv* env, jlong startAddr, jlong size);

/// Get sections as JSON
[[nodiscard]] jstring jniGetSections(jlong handle, JNIEnv* env);

/// Get file hash as hex string
[[nodiscard]] jstring jniGetFileHash(jlong handle, JNIEnv* env);

/// Get statistics as JSON
[[nodiscard]] jstring jniGetStatistics(jlong handle, JNIEnv* env);

/// Analyze loaded binary
[[nodiscard]] jboolean jniAnalyze(jlong handle, JNIEnv* env);

/// Check if loaded
[[nodiscard]] jboolean jniIsLoaded(jlong handle);

/// Close and cleanup
void jniClose(jlong handle);

} // namespace jni

#endif // __ANDROID__ || ANDROID

} // namespace ida

#endif // IDA_PRO_NATIVE_H
