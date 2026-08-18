/**
 * @file elf_parser.cpp
 * @brief ELF Parser Implementation
 * 
 * Full 32-bit and 64-bit ELF (Executable and Linkable Format) parser.
 * Supports section headers, symbol tables (.symtab, .dynsym), and string tables.
 * 
 * ELF Specification: https://refspecs.linuxbase.org/elf/
 * 
 * @version 3.0.0
 */

#include "ida_pro_native.h"
#include <algorithm>
#include <cstring>

namespace ida {

// ============================================================================
// ELF Constants and Structures
// ============================================================================

namespace ElfConstants {

// ELF Magic
constexpr std::array<uint8_t, 4> ELFMAGIC = {0x7F, 'E', 'L', 'F'};

// ELF Class (32/64 bit)
constexpr uint8_t ELFCLASSNONE = 0;
constexpr uint8_t ELFCLASS32   = 1;
constexpr uint8_t ELFCLASS64   = 2;

// Data Encoding (Endianness)
constexpr uint8_t ELFDATANONE = 0;
constexpr uint8_t ELFDATA2LSB = 1;  // Little-endian
constexpr uint8_t ELFDATA2MSB = 2;  // Big-endian

// ELF Version
constexpr uint8_t EV_CURRENT = 1;

// OS/ABI
constexpr uint8_t ELFOSABI_NONE    = 0;   // UNIX System V
constexpr uint8_t ELFOSABI_HPUX    = 1;   // HP-UX
constexpr uint8_t ELFOSABI_NETBSD  = 2;   // NetBSD
constexpr uint8_t ELFOSABI_LINUX   = 3;   // Linux
constexpr uint8_t ELFOSABI_HURD    = 4;   // GNU Hurd
constexpr uint8_t ELFOSABI_FREEBSD = 9;   // FreeBSD
constexpr uint8_t ELFOSABI_OPENBSD = 12;  // OpenBSD

// Machine types (e_machine)
constexpr uint16_t EM_NONE       = 0;     // No machine
constexpr uint16_t EM_386        = 3;     // Intel 80386
constexpr uint16_t EM_ARM        = 40;    // ARM
constexpr uint16_t EM_X86_64     = 62;    // AMD x86-64
constexpr uint16_t EM_AARCH64    = 183;   // ARM AArch64
constexpr uint16_t EM_RISCV      = 243;   // RISC-V
constexpr uint16_t EM_MIPS       = 8;     // MIPS
constexpr uint16_t EM_MIPS_RS3_LE= 10;    // MIPS RS3000 LE

// Section Header Types (sh_type)
constexpr uint32_t SHT_NULL      = 0;     // Section header table entry unused
constexpr uint32_t SHT_PROGBITS  = 1;     // Program data
constexpr uint32_t SHT_SYMTAB    = 2;     // Symbol table
constexpr uint32_t SHT_STRTAB    = 3;     // String table
constexpr uint32_t SHT_RELA      = 4;     // Relocation entries with addends
constexpr uint32_t SHT_HASH      = 5;     // Symbol hash table
constexpr uint32_t SHT_DYNAMIC   = 6;     // Dynamic linking information
constexpr uint32_t SHT_NOTE      = 7;     // Notes
constexpr uint32_t SHT_NOBITS    = 8;     // Program space with no data (bss)
constexpr uint32_t SHT_REL       = 9;     // Relocation entries, no addends
constexpr uint32_t SHT_DYNSYM    = 11;    // Dynamic linker symbol table
constexpr uint32_t SHT_INIT_ARRAY= 14;    // Array of constructors
constexpr uint32_t SHT_FINI_ARRAY= 15;    // Array of destructors

// Special Section Indices
constexpr uint16_t SHN_UNDEF     = 0;
constexpr uint16_t SHN_LORESERVE = 0xff00;
constexpr uint16_t SHN_ABS       = 0xfff1;
constexpr uint16_t SHN_COMMON    = 0xfff2;

// Section Header Flags (sh_flags)
constexpr uint64_t SHF_WRITE     = 0x1;   // Writable
constexpr uint64_t SHF_ALLOC     = 0x2;   // Occupies memory during execution
constexpr uint64_t SHF_EXECINSTR = 0x4;   // Executable

// Symbol Binding (st_info upper 4 bits)
constexpr uint8_t STB_LOCAL     = 0;      // Local symbol
constexpr uint8_t STB_GLOBAL    = 1;      // Global symbol
constexpr uint8_t STB_WEAK      = 2;      // Weak symbol

// Symbol Type (st_info lower 4 bits)
constexpr uint8_t STT_NOTYPE    = 0;      // Not specified
constexpr uint8_t STT_OBJECT    = 1;      // Data object
constexpr uint8_t STT_FUNC      = 2;      // Function
constexpr uint8_t STT_SECTION   = 3;      // Section
constexpr uint8_t STT_FILE      = 4;      // Source file
constexpr uint8_t STT_COMMON    = 5;      // Common block
constexpr uint8_t STT_TLS       = 6;      // Thread-local storage

// Symbol Visibility (st_other)
constexpr uint8_t STV_DEFAULT   = 0;
constexpr uint8_t STV_INTERNAL  = 1;
constexpr uint8_t STV_HIDDEN    = 2;
constexpr uint8_t STV_PROTECTED = 3;

// Program Header Types (p_type)
constexpr uint32_t PT_NULL      = 0;      // Program header table entry unused
constexpr uint32_t PT_LOAD      = 1;      // Loadable segment
constexpr uint32_t PT_DYNAMIC   = 2;      // Dynamic linking information
constexpr uint32_t PT_INTERP    = 3;      // Program interpreter
constexpr uint32_t PT_NOTE      = 4;      // Auxiliary information
constexpr uint32_t PT_SHLIB     = 5;      // Reserved
constexpr uint32_t PT_PHDR      = 6;      // Entry for header table itself
constexpr uint32_t PT_GNU_EH_FRAME = 0x6474e550;  // GCC .eh_frame_hdr
constexpr uint32_t PT_GNU_STACK = 0x6474e551;      // Indicates stack executability
constexpr uint32_t PT_GNU_RELRO = 0x6474e552;      // Read-only after relocation

// Program Header Flags (p_flags)
constexpr uint32_t PF_X = 0x1;           // Execute
constexpr uint32_t PF_W = 0x2;           // Write
constexpr uint32_t PF_R = 0x4;           // Read

} // namespace ElfConstants

#pragma pack(push, 1)

/// ELF32 Header (52 bytes)
struct Elf32_Ehdr {
    uint8_t  e_ident[16];    // Magic number and other info
    uint16_t e_type;         // Object file type
    uint16_t e_machine;      // Architecture
    uint32_t e_version;      // Object file version
    uint32_t e_entry;        // Entry point virtual address
    uint32_t e_phoff;        // Program header table file offset
    uint32_t e_shoff;        // Section header table file offset
    uint32_t e_flags;        Processor-specific flags
    uint16_t e_ehsize;       // ELF header size in bytes
    uint16_t e_phentsize;    // Program header table entry size
    uint16_t e_phnum;        // Program header table entry count
    uint16_t e_shentsize;    // Section header table entry size
    uint16_t e_shnum;        // Section header table entry count
    uint16_t e_shstrndx;     // Section header string table index
};

/// ELF64 Header (64 bytes)
struct Elf64_Ehdr {
    uint8_t  e_ident[16];    // Magic number and other info
    uint16_t e_type;         // Object file type
    uint16_t e_machine;      // Architecture
    uint32_t e_version;      // Object file version
    uint64_t e_entry;        // Entry point virtual address
    uint64_t e_phoff;        // Program header table file offset
    uint64_t e_shoff;        // Section header table file offset
    uint32_t e_flags;        // Processor-specific flags
    uint16_t e_ehsize;       // ELF header size in bytes
    uint16_t e_phentsize;    // Program header table entry size
    uint16_t e_phnum;        // Program header table entry count
    uint16_t e_shentsize;    // Section header table entry size
    uint16_t e_shnum;        // Section header table entry count
    uint16_t e_shstrndx;     // Section header string table index
};

/// ELF32 Section Header (40 bytes)
struct Elf32_Shdr {
    uint32_t sh_name;        // Section name (string table index)
    uint32_t sh_type;        // Section type
    uint32_t sh_flags;       // Section flags
    uint32_t sh_addr;        // Section virtual addr at execution
    uint32_t sh_offset;      // Section file offset
    uint32_t sh_size;        // Section size in bytes
    uint32_t sh_link;        // Link to another section
    uint32_t sh_info;        // Additional section information
    uint32_t sh_addralign;   // Section alignment
    uint32_t sh_entsize;     // Entry size if section holds table
};

/// ELF64 Section Header (64 bytes)
struct Elf64_Shdr {
    uint32_t sh_name;        // Section name (string table index)
    uint32_t sh_type;        // Section type
    uint64_t sh_flags;       // Section flags
    uint64_t sh_addr;        // Section virtual addr at execution
    uint64_t sh_offset;      // Section file offset
    uint64_t sh_size;        // Section size in bytes
    uint32_t sh_link;        // Link to another section
    uint32_t sh_info;        // Additional section information
    uint64_t sh_addralign;   // Section alignment
    uint64_t sh_entsize;     // Entry size if section holds table
};

/// ELF32 Symbol Table Entry (16 bytes)
struct Elf32_Sym {
    uint32_t st_name;        // Symbol name (string table index)
    uint32_t st_value;       // Symbol value
    uint32_t st_size;        // Symbol size
    uint8_t  st_info;        // Symbol type and binding
    uint8_t  st_other;       // Symbol visibility
    uint16_t st_shndx;       // Section index
};

/// ELF64 Symbol Table Entry (24 bytes)
struct Elf64_Sym {
    uint32_t st_name;        // Symbol name (string table index)
    uint8_t  st_info;        // Symbol type and binding
    uint8_t  st_other;       // Symbol visibility
    uint16_t st_shndx;       // Section index
    uint64_t st_value;       // Symbol value
    uint64_t st_size;        // Symbol size
};

/// ELF32 Program Header (32 bytes)
struct Elf32_Phdr {
    uint32_t p_type;         // Segment type
    uint32_t p_offset;       // Segment file offset
    uint32_t p_vaddr;        // Segment virtual address
    uint32_t p_paddr;        // Segment physical address
    uint32_t p_filesz;       // Segment size in file
    uint32_t p_memsz;        // Segment size in memory
    uint32_t p_flags;        // Segment flags
    uint32_t p_align;        // Segment alignment
};

/// ELF64 Program Header (56 bytes)
struct Elf64_Phdr {
    uint32_t p_type;         // Segment type
    uint32_t p_flags;        // Segment flags
    uint64_t p_offset;       // Segment file offset
    uint64_t p_vaddr;        // Segment virtual address
    uint64_t p_paddr;        // Segment physical address
    uint64_t p_filesz;       // Segment size in file
    uint64_t p_memsz;        // Segment size in memory
    uint64_t p_align;        // Segment alignment
};

#pragma pack(pop)

// ============================================================================
// ElfParser::Impl - PIMPL Implementation
// ============================================================================

class ElfParser::Impl {
public:
    // Raw data reference
    std::span<const std::byte> data;
    
    // Parsed header info
    bool isValid{false};
    uint8_t elfClass{0};          // 32 or 64 bit
    uint8_t endianness{0};        // 1=LE, 2=BE
    uint16_t machine{0};
    uint64_t entryPoint{0};
    
    // Counts
    uint16_t programHeaderCount{0};
    uint16_t sectionHeaderCount{0};
    uint16_t shstrndx{0};         // Section header string table index
    
    // Offsets and sizes
    uint64_t programHeaderOffset{0};
    uint64_t sectionHeaderOffset{0};
    uint16_t programHeaderEntrySize{0};
    uint16_t sectionHeaderEntrySize{0};
    
    // Parsed structures
    std::vector<SectionHeader> sections;
    std::vector<SymbolEntry> symbols;
    std::vector<SymbolEntry> dynamicSymbols;
    
    // String table cache
    std::vector<uint8_t> shstrtab;    // Section header string table
    std::vector<uint8_t> strtab;      // Regular string table
    std::vector<uint8_t> dynstr;      // Dynamic string table
    
    Impl() = default;
    ~Impl() = default;
    
    /// Validate ELF magic bytes
    [[nodiscard]] static bool checkMagic(std::span<const std::byte> header) noexcept {
        if (header.size() < 16) return false;
        
        auto bytes = reinterpret_cast<const uint8_t*>(header.data());
        return bytes[0] == 0x7F && 
               bytes[1] == 'E' && 
               bytes[2] == 'L' && 
               bytes[3] == 'F';
    }
    
    /// Read string from a string table
    [[nodiscard]] std::string readString(const std::vector<uint8_t>& strTab, uint64_t offset) const {
        if (offset >= strTab.size()) return {};
        
        const char* start = reinterpret_cast<const char*>(strTab.data() + offset);
        const char* end = start;
        size_t remaining = strTab.size() - offset;
        
        while (remaining > 0 && *end != '\0') {
            ++end;
            --remaining;
        }
        
        return std::string(start, end - start);
    }
    
    /// Parse symbol entry from raw data
    template<typename ElfSym>
    [[nodiscard]] SymbolEntry parseSymbol(const ElfSym* sym, 
                                          const std::vector<uint8_t>& strTab) const {
        SymbolEntry entry{};
        
        if constexpr (std::is_same_v<ElfSym, Elf32_Sym>) {
            entry.nameOffset = sym->st_name;
            entry.address = sym->st_value;
            entry.size = sym->st_size;
            entry.sectionIndex = sym->st_shndx;
        } else {
            entry.nameOffset = sym->st_name;
            entry.address = sym->st_value;
            entry.size = sym->st_size;
            entry.sectionIndex = sym->st_shndx;
        }
        
        // Extract binding and type from st_info
        uint8_t bind = sym->st_info >> 4;
        uint8_t type = sym->st_info & 0xF;
        
        switch (bind) {
            case ElfConstants::STB_LOCAL:  entry.binding = SymbolEntry::Binding::Local; break;
            case ElfConstants::STB_GLOBAL: entry.binding = SymbolEntry::Binding::Global; break;
            case ElfConstants::STB_WEAK:   entry.binding = SymbolEntry::Binding::Weak; break;
            default:                        entry.binding = SymbolEntry::Binding::Local; break;
        }
        
        switch (type) {
            case ElfConstants::STT_NOTYPE:  entry.type = SymbolEntry::Type::None; break;
            case ElfConstants::STT_OBJECT:  entry.type = SymbolEntry::Type::Object; break;
            case ElfConstants::STT_FUNC:    entry.type = SymbolEntry::Type::Function; break;
            case ElfConstants::STT_SECTION: entry.type = SymbolEntry::Type::Section; break;
            case ElfConstants::STT_FILE:    entry.type = SymbolEntry::Type::File; break;
            case ElfConstants::STT_COMMON:  entry.type = SymbolEntry::Type::Common; break;
            case ElfConstants::STT_TLS:     entry.type = SymbolEntry::Type::TLS; break;
            default:                         entry.type = SymbolEntry::Type::None; break;
        }
        
        // Visibility from st_other
        switch (sym->st_other & 0x3) {
            case ElfConstants::STV_DEFAULT:   entry.visibility = SymbolEntry::Visibility::Default; break;
            case ElfConstants::STV_INTERNAL:  entry.visibility = SymbolEntry::Visibility::Internal; break;
            case ElfConstants::STV_HIDDEN:    entry.visibility = SymbolEntry::Visibility::Hidden; break;
            case ElfConstants::STV_PROTECTED: entry.visibility = SymbolEntry::Visibility::Protected; break;
            default:                           entry.visibility = SymbolEntry::Visibility::Default; break;
        }
        
        // Resolve name
        entry.name = readString(strTab, entry.nameOffset);
        
        return entry;
    }
    
    /// Parse section header from raw data
    template<typename ElfShdr>
    [[nodiscard]] SectionHeader parseSectionHeader(const ElfShdr* shdr, uint32_t index) const {
        SectionHeader section{};
        section.index = index;
        section.nameOffset = shdr->sh_name;
        section.type = shdr->sh_type;
        section.flags = shdr->sh_flags;
        section.virtualAddr = shdr->sh_addr;
        section.fileOffset = shdr->sh_offset;
        section.size = shdr->sh_size;
        section.link = shdr->sh_link;
        section.info = shdr->sh_info;
        section.addralign = shdr->sh_addralign;
        section.entrySize = shdr->sh_entsize;
        
        // Resolve name from shstrtab
        section.name = readString(shstrtab, section.nameOffset);
        
        return section;
    }
};

// ============================================================================
// ElfParser Constructor/Destructor
// ============================================================================

ElfParser::ElfParser() : impl_(std::make_unique<Impl>()) {}

ElfParser::~ElfParser() = default;

AnalysisResult<void> ElfParser::parse(std::span<const std::byte> data) {
    // Reset state
    impl_->isValid = false;
    impl_->sections.clear();
    impl_->symbols.clear();
    impl_->dynamicSymbols.clear();
    impl_->shstrtab.clear();
    impl_->strtab.clear();
    impl_->dynstr.clear();
    
    // Check minimum size and magic
    if (data.size() < (sizeof(Elf32_Ehdr))) {
        return std::unexpected(AnalysisError::InvalidFormat);
    }
    
    if (!Impl::checkMagic(data)) {
        return std::unexpected(AnalysisError::InvalidFormat);
    }
    
    impl_->data = data;
    
    // Read ELF class to determine 32 vs 64 bit
    auto bytes = reinterpret_cast<const uint8_t*>(data.data());
    impl_->elfClass = bytes[4];
    impl_->endianness = bytes[5];
    
    // Validate endianness (we only support little-endian on most Android devices)
    if (impl_->endianness != ElfConstants::ELFDATA2LSB &&
        impl_->endianness != ElfConstants::ELFDATA2MSB) {
        return std::unexpected(AnalysisError::CorruptFile);
    }
    
    // Parse based on class
    if (impl_->elfClass == ElfConstants::ELFCLASS32) {
        return parseELF32(data);
    } else if (impl_->elfClass == ElfConstants::ELFCLASS64) {
        return parseELF64(data);
    } else {
        return std::unexpected(AnalysisError::UnsupportedArchitecture);
    }
}

bool ElfParser::isValid() const noexcept {
    return impl_ && impl_->isValid;
}

uint8_t ElfParser::getClass() const noexcept {
    return impl_ ? impl_->elfClass : 0;
}

uint8_t ElfParser::getEndianness() const noexcept {
    return impl_ ? impl_->endianness : 0;
}

uint16_t ElfParser::getMachine() const noexcept {
    return impl_ ? impl_->machine : 0;
}

uint64_t ElfParser::getEntryPoint() const noexcept {
    return impl_ ? impl_->entryPoint : 0;
}

uint16_t ElfParser::getProgramHeaderCount() const noexcept {
    return impl_ ? impl_->programHeaderCount : 0;
}

uint16_t ElfParser::getSectionHeaderCount() const noexcept {
    return impl_ ? impl_->sectionHeaderCount : 0;
}

std::span<const SectionHeader> ElfParser::getSections() const noexcept {
    if (!impl_) return {};
    return impl_->sections;
}

const SectionHeader* ElfParser::findSection(std::string_view name) const noexcept {
    if (!impl_) return nullptr;
    
    for (const auto& section : impl_->sections) {
        if (section.name == name) {
            return &section;
        }
    }
    return nullptr;
}

std::span<const std::byte> ElfParser::getSectionData(const SectionHeader& section) const noexcept {
    if (!impl_ || !impl_->isValid) return {};
    
    if (section.fileOffset + section.size > impl_->data.size()) {
        return {};
    }
    
    return impl_->data.subspan(section.fileOffset, section.size);
}

std::span<const SymbolEntry> ElfParser::getSymbols() const noexcept {
    if (!impl_) return {};
    return impl_->symbols;
}

std::span<const SymbolEntry> ElfParser::getDynamicSymbols() const noexcept {
    if (!impl_) return {};
    return impl_->dynamicSymbols;
}

const SymbolEntry* ElfParser::findSymbol(uint64_t address) const noexcept {
    if (!impl_) return nullptr;
    
    // Search regular symbols first
    for (const auto& sym : impl_->symbols) {
        if (sym.isDefined() && sym.address <= address && 
            address < sym.address + (sym.size > 0 ? sym.size : 1)) {
            return &sym;
        }
    }
    
    // Then search dynamic symbols
    for (const auto& sym : impl_->dynamicSymbols) {
        if (sym.isDefined() && sym.address <= address && 
            address < sym.address + (sym.size > 0 ? sym.size : 1)) {
            return &sym;
        }
    }
    
    return nullptr;
}

const SymbolEntry* ElfParser::findSymbol(std::string_view name) const noexcept {
    if (!impl_) return nullptr;
    
    for (const auto& sym : impl_->symbols) {
        if (sym.name == name) {
            return &sym;
        }
    }
    
    for (const auto& sym : impl_->dynamicSymbols) {
        if (sym.name == name) {
            return &sym;
        }
    }
    
    return nullptr;
}

std::string ElfParser::getString(uint64_t offset) const {
    if (!impl_) return {};
    
    // Try each string table
    std::string result = impl_->readString(impl_->strtab, offset);
    if (!result.empty()) return result;
    
    result = impl_->readString(impl_->dynstr, offset);
    if (!result.empty()) return result;
    
    result = impl_->readString(impl_->shstrtab, offset);
    return result;
}

uint64_t ElfParser::getBaseAddress() const noexcept {
    if (!impl_ || impl_->sections.empty()) return 0;
    
    // Find lowest allocated virtual address
    uint64_t base = UINT64_MAX;
    for (const auto& section : impl_->sections) {
        if (section.isAllocated() && section.virtualAddr < base) {
            base = section.virtualAddr;
        }
    }
    
    return base != UINT64_MAX ? base : 0;
}

// ============================================================================
// ELF32 Parsing
// ============================================================================

AnalysisResult<void> ElfParser::parseELF32(std::span<const std::byte> data) {
    if (data.size() < sizeof(Elf32_Ehdr)) {
        return std::unexpected(AnalysisError::InvalidFormat);
    }
    
    auto ehdr = reinterpret_cast<const Elf32_Ehdr*>(data.data());
    
    // Store header info
    impl_->machine = ehdr->e_machine;
    impl_->entryPoint = ehdr->e_entry;
    impl_->programHeaderCount = ehdr->e_phnum;
    impl_->sectionHeaderCount = ehdr->e_shnum;
    impl_->programHeaderOffset = ehdr->e_phoff;
    impl_->sectionHeaderOffset = ehdr->e_shoff;
    impl_->programHeaderEntrySize = ehdr->e_phentsize;
    impl_->sectionHeaderEntrySize = ehdr->e_shentsize;
    impl_->shstrndx = ehdr->e_shstrndx;
    
    // Load section header string table first
    if (impl_->shstrndx < impl_->sectionHeaderCount) {
        size_t shdrOffset = impl_->sectionHeaderOffset + 
                           (impl_->shstrndx * sizeof(Elf32_Shdr));
        
        if (shdrOffset + sizeof(Elf32_Shdr) <= data.size()) {
            auto shstrShdr = reinterpret_cast<const Elf32_Shdr*>(
                data.data() + shdrOffset);
            
            if (shstrShdr->sh_offset + shstrShdr->sh_size <= data.size()) {
                auto strData = data.subspan(shstrShdr->sh_offset, shstrShdr->sh_size);
                impl_->shstrtab.assign(strData.begin(), strData.end());
            }
        }
    }
    
    // Parse all section headers
    impl_->sections.reserve(impl_->sectionHeaderCount);
    
    for (uint16_t i = 0; i < impl_->sectionHeaderCount; ++i) {
        size_t offset = impl_->sectionHeaderOffset + (i * sizeof(Elf32_Shdr));
        
        if (offset + sizeof(Elf32_Shdr) > data.size()) {
            continue;  // Skip invalid entries
        }
        
        auto shdr = reinterpret_cast<const Elf32_Shdr*>(data.data() + offset);
        impl_->sections.push_back(impl_->parseSectionHeader(shdr, i));
    }
    
    // Load string tables and parse symbols
    loadStringTablesAndSymbols32(data);
    
    impl_->isValid = true;
    return {};
}

void ElfParser::loadStringTablesAndSymbols32(std::span<const std::byte> data) {
    for (const auto& section : impl_->sections) {
        // Load string tables
        if (section.type == ElfConstants::SHT_STRTAB) {
            if (section.fileOffset + section.size <= data.size()) {
                auto strData = data.subspan(section.fileOffset, section.size);
                
                if (section.name == ".strtab") {
                    impl_->strtab.assign(strData.begin(), strData.end());
                } else if (section.name == ".dynstr") {
                    impl_->dynstr.assign(strData.begin(), strData.end());
                }
            }
        }
        
        // Parse symbol tables
        if ((section.type == ElfConstants::SHT_SYMTAB || 
             section.type == ElfConstants::SHT_DYNSYM) &&
            section.entrySize >= sizeof(Elf32_Sym)) {
            
            if (section.fileOffset + section.size <= data.size()) {
                auto symData = data.subspan(section.fileOffset, section.size);
                uint32_t count = section.entryCount();
                
                // Determine which string table to use
                const auto& strTab = (section.type == ElfConstants::SHT_SYMTAB) 
                                     ? impl_->strtab : impl_->dynstr;
                
                std::vector<SymbolEntry>* targetSyms = 
                    (section.type == ElfConstants::SHT_SYMTAB) 
                    ? &impl_->symbols : &impl_->dynamicSymbols;
                
                targetSyms->reserve(count);
                
                for (uint32_t j = 0; j < count; ++j) {
                    size_t symOffset = j * sizeof(Elf32_Sym);
                    
                    if (symOffset + sizeof(Elf32_Sym) <= symData.size()) {
                        auto sym = reinterpret_cast<const Elf32_Sym*>(symData.data() + symOffset);
                        targetSyms->push_back(impl_->parseSymbol(sym, strTab));
                    }
                }
            }
        }
    }
}

// ============================================================================
// ELF64 Parsing
// ============================================================================

AnalysisResult<void> ElfParser::parseELF64(std::span<const std::byte> data) {
    if (data.size() < sizeof(Elf64_Ehdr)) {
        return std::unexpected(AnalysisError::InvalidFormat);
    }
    
    auto ehdr = reinterpret_cast<const Elf64_Ehdr*>(data.data());
    
    // Store header info
    impl_->machine = ehdr->e_machine;
    impl_->entryPoint = ehdr->e_entry;
    impl_->programHeaderCount = ehdr->e_phnum;
    impl_->sectionHeaderCount = ehdr->e_shnum;
    impl_->programHeaderOffset = ehdr->e_phoff;
    impl_->sectionHeaderOffset = ehdr->e_shoff;
    impl_->programHeaderEntrySize = ehdr->e_phentsize;
    impl_->sectionHeaderEntrySize = ehdr->e_shentsize;
    impl_->shstrndx = ehdr->e_shstrndx;
    
    // Load section header string table first
    if (impl_->shstrndx < impl_->sectionHeaderCount) {
        size_t shdrOffset = impl_->sectionHeaderOffset + 
                           (impl_->shstrndx * sizeof(Elf64_Shdr));
        
        if (shdrOffset + sizeof(Elf64_Shdr) <= data.size()) {
            auto shstrShdr = reinterpret_cast<const Elf64_Shdr*>(
                data.data() + shdrOffset);
            
            if (shstrShdr->sh_offset + shstrShdr->sh_size <= data.size()) {
                auto strData = data.subspan(shstrShdr->sh_offset, shstrShdr->sh_size);
                impl_->shstrtab.assign(strData.begin(), strData.end());
            }
        }
    }
    
    // Parse all section headers
    impl_->sections.reserve(impl_->sectionHeaderCount);
    
    for (uint16_t i = 0; i < impl_->sectionHeaderCount; ++i) {
        size_t offset = impl_->sectionHeaderOffset + (i * sizeof(Elf64_Shdr));
        
        if (offset + sizeof(Elf64_Shdr) > data.size()) {
            continue;  // Skip invalid entries
        }
        
        auto shdr = reinterpret_cast<const Elf64_Shdr*>(data.data() + offset);
        impl_->sections.push_back(impl_->parseSectionHeader(shdr, i));
    }
    
    // Load string tables and parse symbols
    loadStringTablesAndSymbols64(data);
    
    impl_->isValid = true;
    return {};
}

void ElfParser::loadStringTablesAndSymbols64(std::span<const std::byte> data) {
    for (const auto& section : impl_->sections) {
        // Load string tables
        if (section.type == ElfConstants::SHT_STRTAB) {
            if (section.fileOffset + section.size <= data.size()) {
                auto strData = data.subspan(section.fileOffset, section.size);
                
                if (section.name == ".strtab") {
                    impl_->strtab.assign(strData.begin(), strData.end());
                } else if (section.name == ".dynstr") {
                    impl_->dynstr.assign(strData.begin(), strData.end());
                }
            }
        }
        
        // Parse symbol tables
        if ((section.type == ElfConstants::SHT_SYMTAB || 
             section.type == ElfConstants::SHT_DYNSYM) &&
            section.entrySize >= sizeof(Elf64_Sym)) {
            
            if (section.fileOffset + section.size <= data.size()) {
                auto symData = data.subspan(section.fileOffset, section.size);
                uint32_t count = section.entryCount();
                
                // Determine which string table to use
                const auto& strTab = (section.type == ElfConstants::SHT_SYMTAB) 
                                     ? impl_->strtab : impl_->dynstr;
                
                std::vector<SymbolEntry>* targetSyms = 
                    (section.type == ElfConstants::SHT_SYMTAB) 
                    ? &impl_->symbols : &impl_->dynamicSymbols;
                
                targetSyms->reserve(count);
                
                for (uint32_t j = 0; j < count; ++j) {
                    size_t symOffset = j * sizeof(Elf64_Sym);
                    
                    if (symOffset + sizeof(Elf64_Sym) <= symData.size()) {
                        auto sym = reinterpret_cast<const Elf64_Sym*>(symData.data() + symOffset);
                        targetSyms->push_back(impl_->parseSymbol(sym, strTab));
                    }
                }
            }
        }
    }
}

} // namespace ida
