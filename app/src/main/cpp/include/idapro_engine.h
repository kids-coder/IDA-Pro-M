/**
 * IDA Pro M - Native Disassembly Engine
 * Main Header File
 * Version 3.0.0
 * 
 * Complete disassembly engine supporting ARM, ARM64, x86, x86-64 architectures.
 * Provides instruction decoding, operand analysis, control flow graph construction,
 * string extraction, pattern scanning, and cross-reference analysis.
 */

#ifndef IDAPRO_ENGINE_H
#define IDAPRO_ENGINE_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <functional>
#include <optional>
#include <array>

namespace idapro {

// ============================================================================
// Architecture Enumeration
// ============================================================================

enum class Architecture : uint8_t {
    UNKNOWN = 0,
    ARM32 = 1,
    ARM64 = 2,
    THUMB = 3,
    X86_32 = 4,
    X86_64 = 5,
    MIPS = 6,
    MIPS64 = 7
};

const char* architectureToString(Architecture arch);

// ============================================================================
// Instruction Types
// ============================================================================

enum class InstructionType : uint16_t {
    // Data processing
    INVALID = 0,
    NOP = 1,
    MOV = 100,
    MOVW,
    MOVT,
    MVN,
    
    // Arithmetic
    ADD = 200,
    SUB,
    MUL,
    DIV,
    MOD,
    ADC,
    SBC,
    RSB,
    RSC,
    NEG,
    
    // Logical
    AND = 300,
    ORR,
    EOR,
    BIC,
    ORN,
    NOT,
    SHL,
    SHR,
    SAR,
    ROL,
    ROR,
    
    // Comparison
    CMP = 400,
    CMN,
    TST,
    TEQ,
    
    // Branch/Jump
    B = 500,
    BL,
    BX,
    BLX,
    CBZ,
    CBNZ,
    TBZ,
    TBNZ,
    RET,
    CALL,
    JMP,
    
    // Load/Store
    LDR = 600,
    STR,
    LDM,
    STM,
    PUSH,
    POP,
    LDRB,
    STRB,
    LDRH,
    STRH,
    LDRD,
    STRD,
    LDREX,
    STREX,
    
    // System
    SVC = 700,
    HVC,
    SMC,
    MRC,
    MCR,
    MRRC,
    MCRR,
    DMB,
    DSB,
    ISB,
    WFI,
    WFE,
    SEV,
    SEVL,
    YIELD,
    CLREX,
    
    // SIMD/Vector (ARM NEON / x86 SSE/AVX)
    VADD = 800,
    VSUB,
    VMUL,
    VDIV,
    VMOV,
    VLD,
    VST,
    VCVT,
    
    // Floating Point
    FADD = 900,
    FSUB,
    FMUL,
    FDIV,
    FMOV,
    FCMP,
    FCVT,
    
    // x86 specific
    LEA = 1000,
    INT,
    INT3,
    LOOP,
    LOOPE,
    LOOPNE,
    MOVSX,
    MOVZX,
    CDQ,
    CQO,
    CPUID,
    RDTSC,
    SYSCALL,
    SYSRET,
    
    // Pseudo-instructions
    DB = 1100,  // Define byte
    DW,         // Define word
    DD,         // Define double word
    DQ          // Define quad word
};

const char* instructionTypeToString(InstructionType type);
bool isBranchInstruction(InstructionType type);
bool isCallInstruction(InstructionType type);
bool isReturnInstruction(InstructionType type);
bool isConditionalBranch(InstructionType type);

// ============================================================================
// Condition Codes (ARM)
// ============================================================================

enum class ConditionCode : uint8_t {
    EQ = 0,   // Equal
    NE = 1,   // Not equal
    CS = 2,   // Carry set (HS)
    CC = 3,   // Carry clear (LO)
    MI = 4,   // Minus/negative
    PL = 5,   // Plus/positive or zero
    VS = 6,   // Overflow
    VC = 7,   // No overflow
    HI = 8,   // Unsigned higher
    LS = 9,   // Unsigned lower or same
    GE = 10,  // Signed greater or equal
    LT = 11,  // Signed less than
    GT = 12,  // Signed greater than
    LE = 13,  // Signed less than or equal
    AL = 14,  // Always (unconditional)
    NV = 15   // Never (reserved)
};

const char* conditionCodeToString(ConditionCode cc);

// ============================================================================
// Operand Types
// ============================================================================

enum class OperandType : uint8_t {
    NONE = 0,
    REGISTER = 1,
    IMMEDIATE = 2,
    MEMORY = 3,
    LABEL = 4,
    FLOAT_IMMEDIATE = 5,
    SYSTEM_REGISTER = 6,
    CONDITION_CODE = 7,
    SHIFTED_REGISTER = 8,
    INDEXED_MEMORY = 9,
    PC_RELATIVE = 10,
    RELATIVE_OFFSET = 11
};

// ============================================================================
// Register Definitions
// ============================================================================

enum class Register : uint16_t {
    // General purpose registers
    R0 = 0, R1, R2, R3, R4, R5, R6, R7,
    R8, R9, R10, R11, R12,
    SP = 13,     // Stack pointer (R13)
    LR = 14,     // Link register (R14)
    PC = 15,     // Program counter (R15)
    
    // ARM64 registers
    X0 = 100, X1, X2, X3, X4, X5, X6, X7,
    X8, X9, X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23,
    X24, X25, X26, X27, X28,
    X29 = 129,   // Frame pointer
    X30 = 130,   // Link register
    SP64 = 131,  // Stack pointer (64-bit)
    PC64 = 132,  // Program counter (64-bit)
    
    // ARM64 32-bit view of registers
    W0 = 200, W1, W2, W3, W4, W5, W6, W7,
    W8, W9, W10, W11, W12, W13, W14, W15,
    W16, W17, W18, W19, W20, W21, W22, W23,
    W24, W25, W26, W27, W28,
    W29 = 229, W30 = 230, WSP = 231,
    
    // SIMD/Vector registers (ARM)
    Q0 = 300, Q1, Q2, Q3, Q4, Q5, Q6, Q7,
    Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15,
    Q16, Q17, Q18, Q19, Q20, Q21, Q22, Q23,
    Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,
    
    // Double precision (subset of Q)
    D0 = 400, D1, D2, D3, D4, D5, D6, D7,
    D8, D9, D10, D11, D12, D13, D14, D15,
    D16, D17, D18, D19, D20, D21, D22, D23,
    D24, D25, D26, D27, D28, D29, D30, D31,
    
    // Single precision (subset of D)
    S0 = 500, S1, S2, S3, S4, S5, S6, S7,
    S8, S9, S10, S11, S12, S13, S14, S15,
    S16, S17, S18, S19, S20, S21, S22, S23,
    S24, S25, S26, S27, S28, S29, S30, S31,
    
    // Half precision
    H0 = 600, H1, H2, H3, H4, H5, H6, H7,
    H8, H9, H10, H11, H12, H13, H14, H15,
    H16, H17, H18, H19, H20, H21, H22, H23,
    H24, H25, H26, H27, H28, H29, H30, H31,
    
    // x86 registers
    EAX = 700, EBX, ECX, EDX,
    ESI, EDI, EBP, ESP,
    EIP = 708,
    EFLAGS = 709,
    
    // x86-64 registers
    RAX = 800, RBX, RCX, RDX,
    RSI, RDI, RBP, RSP,
    R8, R9, R10, R11, R12, R13, R14, R15,
    RIP = 816, RFLAGS = 817,
    
    // x86 8-bit registers
    AL = 900, BL, CL, DL,
    AH, BH, CH, DH,
    SIL, DIL, BPL, SPL,
    R8B = 908, R9B, R10B, R11B, R12B, R13B, R14B, R15B,
    
    // x86 16-bit registers
    AX = 1000, BX, CX, DX,
    SI, DI, BP, SP,
    R8W = 1008, R9W, R10W, R11W, R12W, R13W, R14W, R15W,
    
    // x86 segment registers
    ES = 1100, CS, SS, DS, FS, GS,
    
    // x86 SIMD registers
    XMM0 = 1200, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
    XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,
    XMM16, XMM17, XMM18, XMM19, XMM20, XMM21, XMM22, XMM23,
    XMM24, XMM25, XMM26, XMM27, XMM28, XMM29, XMM30, XMM31,
    
    // AVX registers (YMM/ZMM)
    YMM0 = 1300, YMM1, YMM2, YMM3, YMM4, YMM5, YMM6, YMM7,
    YMM8, YMM9, YMM10, YMM11, YMM12, YMM13, YMM14, YMM15,
    YMM16, YMM17, YMM18, YMM19, YMM20, YMM21, YMM22, YMM23,
    YMM24, YMM25, YMM26, YMM27, YMM28, YMM29, YMM30, YMM31,
    
    ZMM0 = 1400, ZMM1, ZMM2, ZMM3, ZMM4, ZMM5, ZMM6, ZMM7,
    ZMM8, ZMM9, ZMM10, ZMM11, ZMM12, ZMM13, ZMM14, ZMM15,
    ZMM16, ZMM17, ZMM18, ZMM19, ZMM20, ZMM21, ZMM22, ZMM23,
    ZMM24, ZMM25, ZMM26, ZMM27, ZMM28, ZMM29, ZMM30, ZMM31,
    
    // Special/Pseudo registers
    NONE = 0xFFFF,
    ZERO = 0xFFFE,  // Zero register (ARM64)
    FLAGS = 0xFFFD,
    CPSR = 0xFFFC,  // Current program status register (ARM)
    APSR = 0xFFFB,  // Application program status register
    NZCV = 0xFFFA,  // Condition flags
    FP = 0xFFF9,    // Frame pointer (generic)
    SP_GENERIC = 0xFFF8,
    LR_GENERIC = 0xFFF7,
    PC_GENERIC = 0xFFF6
};

const char* registerToString(Register reg, bool wide = false);
Register getStackPointer(Architecture arch);
Register getLinkRegister(Architecture arch);
Register getProgramCounter(Architecture arch);
Register getFramePointer(Architecture arch);

// ============================================================================
// Shift Types
// ============================================================================

enum class ShiftType : uint8_t {
    LSL = 0,  // Logical shift left
    LSR = 1,  // Logical shift right
    ASR = 2,  // Arithmetic shift right
    ROR = 3,  // Rotate right
    RRX = 4,  // Rotate right with extend (ARM only)
    MSL = 5   // Move shifted left (ARM64 only)
};

const char* shiftTypeToString(ShiftType type);

// ============================================================================
// Memory Access Types
// ============================================================================

enum class AccessType : uint8_t {
    READ = 1,
    WRITE = 2,
    READ_WRITE = 3,
    FETCH = 4  // Instruction fetch
};

// ============================================================================
// Operand Structure
// ============================================================================

struct Operand {
    OperandType type = OperandType::NONE;
    
    union {
        int64_t immediateValue;
        double floatValue;
        Register reg;
        struct {
            Register baseReg;
            int64_t offset;
            Register indexReg;
            uint8_t scale;
            bool preIndexed;
            bool postIndexed;
            bool writeback;
        } memory;
        struct {
            Register reg;
            ShiftType shiftType;
            uint8_t shiftAmount;
            Register shiftReg;  // Register-specified shift amount
        } shiftedReg;
    };
    
    uint8_t size = 0;       // Size in bytes (1, 2, 4, 8, 16, 32)
    bool signExtended = false;
    bool negated = false;
    
    std::string toString() const;
    std::string toHexString() const;
};

// ============================================================================
// Instruction Structure
// ============================================================================

struct Instruction {
    uint64_t address = 0;           // Virtual address
    std::vector<uint8_t> rawBytes;  // Raw machine code bytes
    
    InstructionType type = InstructionType::INVALID;
    Architecture arch = Architecture::UNKNOWN;
    ConditionCode conditionCode = ConditionCode::AL;
    
    std::string mnemonic;           // Assembly mnemonic
    std::string operandsStr;        // Formatted operands string
    std::vector<Operand> operands;  // Parsed operands
    
    uint8_t size = 0;               // Instruction size in bytes
    uint8_t operandCount = 0;
    
    // Control flow information
    bool isBranch = false;
    bool isCall = false;
    bool isReturn = false;
    bool isConditional = false;
    bool isTerminal = false;        // Does not fall through to next instruction
    
    // Target address for branches/calls
    std::optional<uint64_t> branchTarget;
    
    // References
    std::vector<uint64_t> xrefsTo;   // Cross-references TO this instruction
    std::vector<uint64_t> xrefsFrom; // Cross-references FROM this instruction
    
    // Analysis metadata
    std::string comment;
    std::string label;
    int functionId = -1;
    int basicBlockId = -1;
    
    // Flags
    bool hasDelaySlot = false;      // For MIPS/ARM (interworking)
    bool isThumb = false;           // Thumb mode indicator
    bool modifiesFlags = false;
    bool readsFlags = false;
    bool isPrivileged = false;
    
    // Methods
    std::string toString(bool hexAddresses = true) const;
    std::string toHexBytes() const;
    std::string toDisassemblyLine() const;
    
    // Comparison operators
    bool operator==(const Instruction& other) const {
        return address == other.address && rawBytes == other.rawBytes;
    }
    bool operator!=(const Instruction& other) const { return !(*this == other); }
};

// ============================================================================
// Basic Block Structure (for CFG)
// ============================================================================

struct BasicBlock {
    int id = -1;
    uint64_t startAddress = 0;
    uint64_t endAddress = 0;
    std::vector<Instruction> instructions;
    
    // Successors (outgoing edges)
    std::vector<int> successors;
    // Predecessors (incoming edges)
    std::vector<int> predecessors;
    
    bool isEntry = false;
    bool isExit = false;
    bool isLoopHeader = false;
    bool isLoopExit = false;
    
    // Loop info
    int loopDepth = 0;
    int loopId = -1;
    
    // Dominance
    std::vector<int> dominators;
    int immediateDominator = -1;
    
    std::string label() const;
    size_t size() const { return instructions.size(); }
};

// ============================================================================
// Function Structure
// ============================================================================

struct Function {
    int id = -1;
    uint64_t startAddress = 0;
    uint64_t endAddress = 0;
    uint64_t size = 0;
    
    std::string name;
    std::string demangledName;
    
    // Type information
    enum class Type : uint8_t {
        NORMAL = 0,
        THUNK = 1,      // Jump function
        LIBRARY = 2,    // Imported/exported library function
        IMPORTED = 3,   // External import
        EXPORTED = 4,   // External export
        WEAK = 5,       // Weak symbol
        STATIC = 6,     // Local/static function
        INLINE = 7      // Inline function
    } type = Type::NORMAL;
    
    // Calling convention
    enum class CallingConvention : uint8_t {
        UNKNOWN = 0,
        AAPCS = 1,      // ARM Architecture Procedure Call Standard
        AAPCS_VFP = 2,  // AAPCS with VFP
        AARCH64 = 3,    // ARM64 calling convention
        CDECL = 4,      // x86 cdecl
        STDCALL = 5,    // x86 stdcall
        FASTCALL = 6,   // x86 fastcall
        THISCALL = 7,   // x86 thiscall
        SYSTEM_V_AMD64 = 8  // x86-64 System V ABI
    } callingConvention = CallingConvention::UNKNOWN;
    
    // Control flow graph
    std::vector<BasicBlock> basicBlocks;
    std::unordered_map<int, std::vector<int>> adjacencyList;
    
    // Statistics
    int instructionCount = 0;
    int edgeCount = 0;
    int cyclomaticComplexity = 0;
    
    // References
    std::vector<uint64_t> callers;      // Functions that call this one
    std::vector<uint64_t> callees;      // Functions called by this one
    std::vector<uint64_t> xrefsTo;      // Non-call references to this function
    
    // Metadata
    std::string comment;
    std::string signature;
    bool hasVariableArgs = false;
    bool isNoreturn = false;
    bool isPure = false;
    bool isConst = false;
    
    // Decompilation hints
    std::string decompiledCode;
    std::vector<std::pair<std::string, std::string>> localVariables;
    
    std::string getDisplayName() const;
};

// ============================================================================
// String Entry Structure
// ============================================================================

struct StringEntry {
    uint64_t address = 0;
    std::string value;
    
    enum class Encoding : uint8_t {
        ASCII = 0,
        UTF8 = 1,
        UTF16_LE = 2,
        UTF16_BE = 3,
        UTF32_LE = 4,
        UTF32_BE = 5
    } encoding = Encoding::ASCII;
    
    uint32_t length = 0;       // Character length
    uint32_t byteLength = 0;   // Byte length including null terminator
    
    enum class Type : uint8_t {
        UNKNOWN = 0,
        PRINTABLE = 1,
        WIDE = 2,
        UNICODE = 3,
        C_STRING = 4,
        JAVA_STRING = 5,
        PATH = 6,
        URL = 7,
        EMAIL = 8,
        IP_ADDRESS = 9,
        GUID = 10,
        REGEX = 11,
        XML = 12,
        JSON = 13,
        BASE64 = 14,
        HEX = 15,
        FORMAT_STRING = 16
    } type = Type::UNKNOWN;
    
    // Reference information
    std::vector<uint64_t> xrefs;
    bool isReferenced = false;
    
    std::string toString() const;
};

// ============================================================================
// Cross-Reference Structure
// ============================================================================

struct Xref {
    enum class Type : uint8_t {
        DATA = 0,       // Data reference
        CODE = 1,       // Code reference (jump/branch)
        CALL = 2,       // Call reference
        STRING = 3,     // String reference
        IMPORT = 4,     // Import reference
        EXPORT = 5,     // Export reference
        READ = 6,       // Read access
        WRITE = 7,      // Write access
        UNDEFINED = 8   // Unknown type
    } type = Type::UNDEFINED;
    
    uint64_t from = 0;  // Source address
    uint64_t to = 0;    // Target address
    
    // Additional context
    Instruction* fromInstruction = nullptr;
    std::string context;
    
    std::string toString() const;
};

// ============================================================================
// Section/Header Structure (Binary Format)
// ============================================================================

struct Section {
    std::string name;
    uint64_t virtualAddress = 0;
    uint64_t virtualSize = 0;
    uint64_t fileOffset = 0;
    uint64_t fileSize = 0;
    
    enum class Type : uint8_t {
        CODE = 0,
        DATA = 1,
        RODATA = 2,     // Read-only data
        BSS = 3,        // Uninitialized data
        HEAP = 4,
        STACK = 5,
        IMPORT = 6,
        EXPORT = 7,
        RESOURCE = 8,
        DEBUG = 9,
        EXCEPTION = 10,
        TLS = 11,       // Thread-local storage
        GNU_EH_FRAME = 12,
        GNU_HASH = 13,
        DYNAMIC = 14,
        DYNSTR = 15,
        DYNSYM = 16,
        GOT = 17,       // Global offset table
        PLT = 18,       // Procedure linkage table
        REL = 19,       // Relocations
        UNKNOWN = 255
    } type = Type::UNKNOWN;
    
    uint32_t flags = 0;
    bool executable = false;
    bool writable = false;
    bool readable = false;
    
    std::vector<uint8_t> data;
};

struct BinaryInfo {
    enum class Format : uint8_t {
        UNKNOWN = 0,
        ELF = 1,
        PE = 2,
        MACH_O = 3,
        DEX = 4,
        RAW = 5,
        COFF = 6,
        OLE = 7
    } format = Format::UNKNOWN;
    
    Architecture arch = Architecture::UNKNOWN;
    bool is64Bit = false;
    bool isLittleEndian = true;
    
    uint64_t entryPoint = 0;
    uint64_t imageBase = 0;
    uint64_t imageSize = 0;
    
    std::string fileName;
    std::string fullPath;
    uint64_t fileSize = 0;
    
    // Hashes
    std::string md5Hash;
    std::string sha256Hash;
    
    // Sections
    std::vector<Section> sections;
    
    // Symbols
    struct Symbol {
        std::string name;
        uint64_t address = 0;
        uint64_t size = 0;
        
        enum class Type : uint8_t {
            NONE = 0,
            FUNCTION = 1,
            OBJECT = 2,
            SECTION = 3,
            FILE_SYM = 4,
            COMMON = 5,
            THREAD_LOCAL = 6
        } type = Type::NONE;
        
        enum class Binding : uint8_t {
            LOCAL = 0,
            GLOBAL = 1,
            WEAK = 2,
            GNU_UNIQUE = 3
        } binding = Binding::LOCAL;
        
        bool isDefined = false;
        bool isImported = false;
        bool isExported = false;
    };
    std::vector<Symbol> symbols;
    
    // Imports/Exports
    struct Import {
        std::string name;
        std::string library;
        uint64_t address = 0;
        bool isOrdinal = false;
        uint16_t ordinal = 0;
    };
    std::vector<Import> imports;
    std::vector<Symbol> exports;
    
    // Relocations
    struct Relocation {
        uint64_t offset = 0;
        uint64_t symbolIndex = 0;
        enum class Type : uint32_t {
            NONE = 0,
            ABSOLUTE = 1,
            PC_RELATIVE = 2,
            GOT-relative = 3,
            PLT-relative = 4,
            COPY = 5,
            GLOB_DAT = 6,
            JUMP_SLOT = 7,
            RELATIVE = 8
        } type = Type::NONE;
        int64_t addend = 0;
    };
    std::vector<Relocation> relocations;
    
    // Dynamic linking info
    std::vector<std::string> neededLibraries;
    std::string soname;
    uint32_t runPath = 0;
    
    // Android-specific (DEX)
    struct DexInfo {
        uint32_t version = 0;
        uint32_t stringCount = 0;
        uint32_t typeCount = 0;
        uint32_t protoCount = 0;
        uint32_t fieldCount = 0;
        uint32_t methodCount = 0;
        uint32_t classCount = 0;
    } dexInfo;
    
    std::string getFormatString() const;
    std::string getArchString() const;
};

// ============================================================================
// Pattern/M Signature Structure
// ============================================================================

struct PatternSignature {
    std::string name;
    std::string description;
    std::vector<uint8_t> pattern;      // Byte pattern with wildcards (0xFF = wildcard)
    std::vector<uint8_t> mask;         // Mask for wildcard matching
    std::string category;
    std::string author;
    float confidence = 0.0f;
    
    bool match(const uint8_t* data, size_t size) const;
    std::string toString() const;
};

// ============================================================================
// Analysis Options
// ============================================================================

struct AnalysisOptions {
    bool autoAnalyze = true;
    bool deepScan = false;
    bool buildCFG = true;
    bool extractStrings = true;
    bool resolveXrefs = true;
    bool identifyFunctions = true;
    bool detectPatterns = true;
    bool followThunkFunctions = true;
    bool analyzeSwitchStatements = true;
    bool recoverFunctionBoundaries = true;
    
    // String extraction options
    uint32_t minStringLength = 4;
    uint32_t maxStringLength = 4096;
    bool extractUnicodeStrings = true;
    bool extractWideStrings = true;
    bool detectStringTypes = true;
    
    // Pattern detection
    std::vector<PatternSignature> customPatterns;
    
    // Performance limits
    size_t maxMemoryUsage = 512 * 1024 * 1024;  // 512 MB default
    uint32_t maxInstructionsPerFunction = 100000;
    uint32_t maxAnalysisTimeSeconds = 300;  // 5 minutes max
};

// ============================================================================
// Analysis Result Structure
// ============================================================================

struct AnalysisResult {
    bool success = false;
    std::string errorMessage;
    
    BinaryInfo binaryInfo;
    
    std::unordered_map<uint64_t, Instruction> instructions;
    std::vector<Function> functions;
    std::vector<StringEntry> strings;
    std::vector<Xref> xrefs;
    
    // Statistics
    uint64_t totalInstructions = 0;
    uint64_t totalFunctions = 0;
    uint64_t totalStrings = 0;
    uint64_t totalXrefs = 0;
    
    // Timing
    double analysisTimeSeconds = 0.0;
    
    // Phase completion status
    bool phaseDisassemblyComplete = false;
    bool phaseFunctionIdentificationComplete = false;
    bool phaseCFGConstructionComplete = false;
    bool phaseStringExtractionComplete = false;
    bool phaseXrefResolutionComplete = false;
    bool phasePatternDetectionComplete = false;
    
    // Warnings
    std::vector<std::string> warnings;
};

// ============================================================================
// Progress Callback Type
// ============================================================================

using ProgressCallback = std::function<void(int percent, const std::string& phase)>;
using LogCallback = std::function<void(const std::string& message)>;

// ============================================================================
// Main Disassembler Class
// ============================================================================

class DisassemblerEngine {
public:
    DisassemblerEngine();
    ~DisassemblerEngine();
    
    // Disable copying
    DisassemblerEngine(const DisassemblerEngine&) = delete;
    DisassemblerEngine& operator=(const DisassemblerEngine&) = delete;
    
    // Core operations
    bool loadFile(const std::string& filePath);
    bool loadBuffer(const uint8_t* data, size_t size, const std::string& name = "buffer");
    void unload();
    
    // Analysis
    AnalysisResult analyze(const AnalysisOptions& options = AnalysisOptions{},
                          ProgressCallback progressCb = nullptr,
                          LogCallback logCb = nullptr);
    void cancelAnalysis();
    
    // Query functions
    Instruction* getInstructionAt(uint64_t address);
    const Instruction* getInstructionAt(uint64_t address) const;
    std::vector<Instruction*> getInstructionsInRange(uint64_t start, uint64_t end);
    
    Function* getFunctionAt(uint64_t address);
    Function* getFunctionContaining(uint64_t address);
    Function* getFunctionById(int id);
    
    BasicBlock* getBasicBlockAt(uint64_t address);
    
    StringEntry* getStringAt(uint64_t address);
    std::vector<StringEntry*> getStringsWithValue(const std::string& value);
    
    std::vector<Xref*> getXrefsTo(uint64_t address);
    std::vector<Xref*> getXrefsFrom(uint64_t address);
    
    // Search functions
    std::vector<Instruction*> searchInstructions(const std::string& query);
    std::vector<Instruction*> searchPattern(const std::vector<uint8_t>& pattern);
    std::vector<StringEntry*> searchStrings(const std::string& query);
    
    // Navigation
    Instruction* getNextInstruction(uint64_t address);
    Instruction* getPreviousInstruction(uint64_t address);
    uint64_t getEntryPoint() const;
    std::vector<uint64_t> getFunctionEntryPoints() const;
    
    // Utility functions
    std::string disassembleAt(uint64_t address);
    std::string getHexDump(uint64_t offset, size_t length);
    std::vector<uint8_t> readMemory(uint64_t address, size_t size);
    bool writeMemory(uint64_t address, const std::vector<uint8_t>& data);
    
    // State queries
    bool isLoaded() const { return loaded_; }
    bool isAnalyzed() const { return analyzed_; }
    const BinaryInfo& getBinaryInfo() const { return binaryInfo_; }
    const AnalysisResult& getLastResult() const { return lastResult_; }
    
    // Architecture-specific decoders
    static Instruction decodeARM(uint64_t address, const uint8_t* data, size_t maxSize);
    static Instruction decodeARM64(uint64_t address, const uint8_t* data, size_t maxSize);
    static Instruction decodeThumb(uint64_t address, const uint8_t* data, size_t maxSize);
    static Instruction decodeX86_32(uint64_t address, const uint8_t* data, size_t maxSize);
    static Instruction decodeX86_64(uint64_t address, const uint8_t* data, size_t maxSize);
    
private:
    // Internal state
    std::vector<uint8_t> fileData_;
    BinaryInfo binaryInfo_;
    AnalysisResult lastResult_;
    bool loaded_ = false;
    bool analyzed_ = false;
    bool cancelled_ = false;
    
    // Analysis components
    bool detectFormat();
    bool parseBinaryHeaders();
    std::vector<Instruction> disassembleSection(const Section& section);
    std::vector<Function> identifyFunctions();
    std::vector<BasicBlock> constructCFG(Function& func);
    std::vector<StringEntry> extractStrings();
    std::vector<Xref> resolveXrefs();
    std::vector<PatternSignature> detectPatterns();
    
    // Helper methods
    Instruction decodeInstruction(uint64_t address, const uint8_t* data, size_t maxSize);
    uint64_t virtualToFileOffset(uint64_t vaddr) const;
    uint64_t fileToVirtualOffset(uint64_t foffset) const;
    const uint8_t* getPointerAtVirtualAddress(uint64_t vaddr) const;
    bool isValidAddress(uint64_t addr) const;
    
    // CFG construction helpers
    void splitIntoBasicBlocks(Function& func);
    void connectBasicBlocks(Function& func);
    int computeCyclomaticComplexity(const Function& func) const;
    
    // String extraction helpers
    std::vector<StringEntry> extractAsciiStrings();
    std::vector<StringEntry> extractWideStrings();
    std::vector<StringEntry> extractUtf8Strings();
    void classifyString(StringEntry& str);
    
    // Pattern scanning
    std::vector<size_t> scanForPattern(const std::vector<uint8_t>& pattern,
                                        const std::vector<uint8_t>& mask);
};

// ============================================================================
// JNI Bridge Functions (for Kotlin/Java interop)
// ============================================================================

extern "C" {

// Initialization
JNIEXPORT jlong JNICALL Java_com_mobile_idapro_native_DisassemblerNative_createEngine(JNIEnv*, jobject);
JNIEXPORT void JNICALL Java_com_mobile_idapro_native_DisassemblerNative_destroyEngine(JNIEnv*, jlong);

// File operations
JNIEXPORT jboolean JNICALL Java_com_mobile_idapro_native_DisassemblerNative_loadFile(JNIEnv*, jlong, jstring);
JNIEXPORT jboolean JNICALL Java_com_mobile_idapro_native_DisassemblerNative_loadBuffer(JNIEnv*, jlong, jbyteArray, jstring);
JNIEXPORT void JNICALL Java_com_mobile_idapro_native_DisassemblerNative_unload(JNIEnv*, jlong);

// Analysis
JNIEXPORT jlong JNICALL Java_com_mobile_idapro_native_DisassemblerNative_analyze(JNIEnv*, jlong, jint, jboolean, jboolean, jboolean, jboolean, jboolean, jboolean, jboolean, jboolean, jboolean, jint, jint);

// Query functions
JNIEXPORT jbyteArray JNICALL Java_com_mobile_idapro_native_DisassemblerNative_getInstructionAt(JNIEnv*, jlong, jlong);
JNIEXPORT jbyteArray JNICALL Java_com_mobile_idapro_native_DisassemblerNative_disassembleRange(JNIEnv*, jlong, jlong, jlong);
JNIEXPORT jbyteArray JNICALL Java_com_mobile_idapro_native_DisassemblerNative_getStrings(JNIEnv*, jlong, jstring);
JNIEXPORT jbyteArray JNICALL Java_com_mobile_idapro_native_DisassemblerNative_getFunctions(JNIEnv*, jlong);
JNIEXPORT jbyteArray JNICALL Java_com_mobile_idapro_native_DisassemblerNative_getBinaryInfo(JNIEnv*, jlong);

// Hex dump
JNIEXPORT jstring JNICALL Java_com_mobile_idapro_native_DisassemblerNative_getHexDump(JNIEnv*, jlong, jlong, jint);

// Utility
JNIEXPORT jstring JNICALL Java_com_mobile_idapro_native_DisassemblerNative_getVersion(JNIEnv*);
JNIEXPORT jstring JNICALL Java_com_mobile_idapro_native_DisassemblerNative_getSupportedArchitectures(JNIEnv*);

} // extern "C"

// ============================================================================
// Utility Functions
// ============================================================================

namespace utils {

std::string formatAddress(uint64_t addr, bool withPrefix = true);
std::string formatBytes(const uint8_t* data, size_t size, char separator = ' ');
std::string formatHexByte(uint8_t byte);
std::string formatHexWord(uint16_t word);
std::string formatHexDword(uint32_t dword);
std::string formatHexQword(uint64_t qword);

std::string computeMD5(const uint8_t* data, size_t size);
std::string computeSHA256(const uint8_t* data, size_t size);

std::string trimWhitespace(const std::string& str);
std::vector<std::string> splitString(const std::string& str, char delimiter);
std::string toLower(const std::string& str);
std::string toUpper(const std::string& str);
bool startsWith(const std::string& str, const std::string& prefix);
bool endsWith(const std::string& str, const std::string& suffix);

template<typename T>
T swapEndian(T value);

uint16_t swapEndian16(uint16_t value);
uint32_t swapEndian32(uint32_t value);
uint64_t swapEndian64(uint64_t value);

} // namespace utils

} // namespace idapro

#endif // IDAPRO_ENGINE_H
