/**
 * IDA Pro M - Binary Format Parsers
 * Supports: ELF, PE, Mach-O, DEX formats
 */

#include "idapro_engine.h"
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>

namespace idapro {

// ============================================================================
// ELF Parser
// ============================================================================

namespace elf {

// ELF structures (simplified)
struct ElfHeader {
    uint8_t  e_ident[16];  // Magic number and other info
    uint16_t e_type;       // Object file type
    uint16_t e_machine;    // Architecture
    uint32_t e_version;    // Object file version
    uint64_t e_entry;      // Entry point virtual address
    uint64_t e_phoff;      // Program header table file offset
    uint64_t e_shoff;      // Section header table file offset
    uint32_t e_flags;      // Processor-specific flags
    uint16_t e_ehsize;     // ELF header size in bytes
    uint16_t e_phentsize;  // Program header table entry size
    uint16_t e_phnum;      // Program header table entry count
    uint16_t e_shentsize;  // Section header table entry size
    uint16_t e_shnum;      // Section header table entry count
    uint16_t e_shstrndx;   // Section header string table index
};

struct ElfSectionHeader {
    uint32_t sh_name;      // Section name (string table index)
    uint32_t sh_type;      // Section type
    uint64_t sh_flags;     // Section flags
    uint64_t sh_addr;      // Section virtual address
    uint64_t sh_offset;    // Section file offset
    uint64_t sh_size;      // Section size in bytes
    uint32_t sh_link;      // Link to another section
    uint32_t sh_info;      // Additional section information
    uint64_t sh_addralign; // Section alignment
    uint64_t sh_entsize;   // Entry size if section holds table
};

struct ElfProgramHeader {
    uint32_t p_type;   // Segment type
    uint32_t p_flags;  // Segment flags
    uint64_t p_offset; // Segment file offset
    uint64_t p_vaddr;  // Segment virtual address
    uint64_t p_paddr;  // Segment physical address
    uint64_t p_filesz; // Segment size in file
    uint64_t p_memsz;  // Segment size in memory
    uint64_t p_align;  // Segment alignment
};

struct ElfSymbol {
    uint32_t st_name;   // Symbol name (string table index)
    unsigned char st_info;   // Symbol type and binding
    unsigned char st_other;  // Symbol visibility
    uint16_t st_shndx;  // Section index
    uint64_t st_value;  // Symbol value
    uint64_t st_size;  // Symbol size
};

class ElfParser {
public:
    static bool parse(const uint8_t* data, size_t size, BinaryInfo& info) {
        if (size < sizeof(ElfHeader)) return false;
        
        const ElfHeader* hdr = reinterpret_cast<const ElfHeader*>(data);
        
        // Check magic number
        if (hdr->e_ident[0] != 0x7F || hdr->e_ident[1] != 'E' ||
            hdr->e_ident[2] != 'L' || hdr->e_ident[3] != 'F') {
            return false;
        }
        
        info.format = BinaryInfo::Format::ELF;
        
        // Determine class (32/64 bit)
        info.is64Bit = (hdr->e_ident[4] == 2);
        
        // Determine endianness
        info.isLittleEndian = (hdr->e_ident[5] == 1);
        
        // Entry point
        info.entryPoint = hdr->e_entry;
        
        // Architecture
        switch (hdr->e_machine) {
            case 0x03: info.arch = Architecture::X86_32; break;
            case 0x3E: info.arch = Architecture::X86_64; break;
            case 0x28: info.arch = Architecture::ARM32; break;
            case 0xB7: info.arch = Architecture::ARM64; break;
            case 0x08: info.arch = Architecture::MIPS; break;
            default:   info.arch = Architecture::UNKNOWN; break;
        }
        
        // Parse sections
        if (hdr->e_shoff > 0 && hdr->e_shnum > 0) {
            parseSections(data, size, hdr, info);
        }
        
        // Parse program headers for image base calculation
        if (hdr->e_phoff > 0 && hdr->e_phnum > 0) {
            parseProgramHeaders(data, size, hdr, info);
        }
        
        // Parse symbol tables
        parseSymbols(data, size, hdr, info);
        
        // Parse dynamic section for imports/exports
        parseDynamic(data, size, hdr, info);
        
        return true;
    }

private:
    static void parseSections(const uint8_t* data, size_t size,
                               const ElfHeader* hdr, BinaryInfo& info) {
        size_t offset = hdr->e_shoff;
        
        for (int i = 0; i < hdr->e_shnum && offset + sizeof(ElfSectionHeader) <= size; ++i) {
            const ElfSectionHeader* shdr = 
                reinterpret_cast<const ElfSectionHeader*>(data + offset);
            
            Section sec;
            
            // Get section name from string table
            if (hdr->e_shstrndx < hdr->e_shnum) {
                const ElfSectionHeader* strtabHdr =
                    reinterpret_cast<const ElfSectionHeader*>(
                        data + hdr->e_shoff + hdr->e_shstrndx * hdr->e_shentsize);
                
                if (shdr->sh_name < strtabHdr->sh_size &&
                    strtabHdr->sh_offset + shdr->sh_name < size) {
                    sec.name = reinterpret_cast<const char*>(
                        data + strtabHdr->sh_offset + shdr->sh_name);
                }
            }
            
            sec.virtualAddress = shdr->sh_addr;
            sec.virtualSize = shdr->sh_size;
            sec.fileOffset = shdr->sh_offset;
            sec.fileSize = std::min(shdr->sh_size, static_cast<uint64_t>(size - shdr->sh_offset));
            sec.flags = static_cast<uint32_t>(shdr->sh_flags);
            
            // Determine section type
            switch (shdr->sh_type) {
                case 1:  sec.type = Section::Type::CODE; break;     // SHT_PROGBITS
                case 8:  sec.type = Section::Type::BSS; break;      // SHT_NOBITS
                case 2:  sec.type = Section::Type::SYMTAB; break;   // SHT_SYMTAB
                case 3:  sec.type = Section::Type::STR; break;      // SHT_STRTAB
                case 4:  sec.type = Section::Type::RELA; break;     // SHT_RELA
                case 9:  sec.type = Section::Type::REL; break;      // SHT_REL
                case 11: sec.type = Section::Type::DYNAMIC; break;  // SHT_DYNAMIC
                case 14: sec.type = Section::Type::GOT; break;      // SHT_HASH
                case 6:  sec.type = Section::Type::SYMTAB; break;   // SHT_DYNSYM
                default:
                    // Determine by name or flags
                    if (sec.name.find(".text") != std::string::npos) {
                        sec.type = Section::Type::CODE;
                    } else if (sec.name.find(".rodata") != std::string::npos) {
                        sec.type = Section::Type::RODATA;
                    } else if (sec.name.find(".data") != std::string::npos) {
                        sec.type = Section::Type::DATA;
                    } else if (sec.name.find(".bss") != std::string::npos) {
                        sec.type = Section::Type::BSS;
                    } else if (sec.name.find(".got") != std::string::npos ||
                               sec.name.find(".plt") != std::string::npos) {
                        sec.type = Section::Type::GOT;
                    } else {
                        sec.type = Section::Type::UNKNOWN;
                    }
                    break;
            }
            
            sec.executable = (shdr->sh_flags & 0x4) != 0;
            sec.writable = (shdr->sh_flags & 0x2) != 0;
            sec.readable = (shdr->sh_flags & 0x1) != 0;
            
            // Copy section data
            if (shdr->sh_offset < size && shdr->sh_size > 0) {
                size_t copySize = std::min(shdr->sh_size, size - shdr->sh_offset);
                sec.data.assign(data + shdr->sh_offset, data + shdr->sh_offset + copySize);
            }
            
            info.sections.push_back(sec);
            offset += hdr->e_shentsize;
        }
    }
    
    static void parseProgramHeaders(const uint8_t* data, size_t size,
                                     const ElfHeader* hdr, BinaryInfo& info) {
        size_t offset = hdr->e_phoff;
        uint64_t minAddr = UINT64_MAX;
        
        for (int i = 0; i < hdr->e_phnum && offset + sizeof(ElfProgramHeader) <= size; ++i) {
            const ElfProgramHeader* phdr =
                reinterpret_cast<const ElfProgramHeader*>(data + offset);
            
            if (phdr->p_type == 1) {  // PT_LOAD
                if (phdr->p_vaddr < minAddr) {
                    minAddr = phdr->p_vaddr;
                }
            }
            
            offset += hdr->e_phentsize;
        }
        
        info.imageBase = (minAddr != UINT64_MAX) ? minAddr : 0;
    }
    
    static void parseSymbols(const uint8_t* data, size_t size,
                              const ElfHeader* hdr, BinaryInfo& info) {
        // Find symbol table sections
        for (const auto& sec : info.sections) {
            if (sec.type == Section::Type::SYMTAB || sec.type == Section::Type::DYNAMIC) {
                // Parse symbols from this section
                size_t symOffset = sec.fileOffset;
                size_t symCount = sec.fileSize / (info.is64Bit ? 24 : 16);  // Elf64_Sym / Elf32_Sym
                
                for (size_t j = 0; j < symCount; ++j) {
                    const ElfSymbol* sym;
                    if (info.is64Bit) {
                        sym = reinterpret_cast<const ElfSymbol*>(data + symOffset + j * 24);
                    } else {
                        // Simplified - would need separate Elf32_Sym struct
                        sym = reinterpret_cast<const ElfSymbol*>(data + symOffset + j * 16);
                    }
                    
                    if (sym->st_name == 0 && sym->st_value == 0) continue;
                    
                    BinaryInfo::Symbol symbol;
                    
                    // Get name from associated string table
                    if (sym->st_name < info.sections[sec.id].fileSize) {
                        // Would need proper string table lookup
                        symbol.name = "symbol_" + utils::formatAddress(sym->st_value, false);
                    }
                    
                    symbol.address = sym->st_value;
                    symbol.size = sym->st_size;
                    
                    // Binding
                    switch (sym->st_info >> 4) {
                        case 0: symbol.binding = BinaryInfo::Symbol::Binding::LOCAL; break;
                        case 1: symbol.binding = BinaryInfo::Symbol::Binding::GLOBAL; break;
                        case 2: symbol.binding = BinaryInfo::Symbol::Binding::WEAK; break;
                        default: symbol.binding = BinaryInfo::Symbol::Binding::LOCAL; break;
                    }
                    
                    // Type
                    switch (sym->st_info & 0xF) {
                        case 0: symbol.type = BinaryInfo::Symbol::Type::NONE; break;
                        case 1: symbol.type = BinaryInfo::Symbol::Type::OBJECT; break;
                        case 2: symbol.type = BinaryInfo::Symbol::Type::FUNCTION; break;
                        case 3: symbol.type = BinaryInfo::Symbol::Type::SECTION; break;
                        case 4: symbol.type = BinaryInfo::Symbol::Type::FILE_SYM; break;
                        default: symbol.type = BinaryInfo::Symbol::Type::NONE; break;
                    }
                    
                    symbol.isDefined = (sym->st_shndx != 0);
                    symbol.isExported = (symbol.binding == BinaryInfo::Symbol::Binding::GLOBAL &&
                                        symbol.isDefined);
                    symbol.isImported = !symbol.isDefined;
                    
                    if (symbol.type == BinaryInfo::Symbol::Type::FUNCTION ||
                        symbol.address > 0) {
                        info.symbols.push_back(symbol);
                        
                        if (symbol.isExported) {
                            info.exports.push_back(symbol);
                        }
                    }
                }
            }
        }
    }
    
    static void parseDynamic(const uint8_t* data, size_t size,
                              const ElfHeader* hdr, BinaryInfo& info) {
        // Find dynamic section
        for (const auto& sec : info.sections) {
            if (sec.type == Section::Type::DYNAMIC) {
                // Parse dynamic entries to find needed libraries
                // This is simplified - full implementation would iterate entries
                (void)data; (void)size;
                break;
            }
        }
    }
};

} // namespace elf

// ============================================================================
// PE Parser (Windows)
// ============================================================================

namespace pe {

// DOS Header
struct DosHeader {
    uint16_t e_magic;      // Magic number ("MZ")
    uint16_t e_cblp;       // Bytes on last page of file
    uint16_t e_cp;         // Pages in file
    uint16_t e_crlc;       // Relocations
    uint16_t e_cparhdr;    // Size of header in paragraphs
    uint16_t e_minalloc;   // Minimum extra paragraphs needed
    uint16_t e_maxalloc;   // Maximum extra paragraphs needed
    uint16_t e_ss;         // Initial (relative) SS value
    uint16_t e_sp;         // Initial SP value
    uint16_t e_csum;       // Checksum
    uint16_t e_ip;         // Initial IP value
    uint16_t e_cs;         // Initial (relative) CS value
    uint16_t e_lfarlc;     // File address of relocation table
    uint16_t e_ovno;       // Overlay number
    uint16_t e_res[4];     // Reserved words
    uint16_t e_oemid;      // OEM identifier
    uint16_t e_oeminfo;    // OEM information
    uint16_t e_res2[10];   // Reserved words
    int32_t  e_lfanew;     // File address of new exe header
};

// PE Signature
struct PeSignature {
    uint32_t signature;  // "PE\0\0"
};

// COFF File Header
struct CoffFileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

// Optional Header (PE32)
struct OptionalHeaderPe32 {
    uint16_t Magic;                       // 0x10B for PE32
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;                   // Windows-specific
    uint32_t SectionAlignment;
    uint32 FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    // DataDirectory follows...
};

class PeParser {
public:
    static bool parse(const uint8_t* data, size_t size, BinaryInfo& info) {
        if (size < sizeof(DosHeader)) return false;
        
        const DosHeader* dosHdr = reinterpret_cast<const DosHeader*>(data);
        
        // Check MZ magic
        if (dosHdr->e_magic != 0x5A4D) {  // "MZ"
            return false;
        }
        
        // Get PE header offset
        int32_t peOffset = dosHdr->e_lfanew;
        if (peOffset < 0 || peOffset + sizeof(PeSignature) > static_cast<int32_t>(size)) {
            return false;
        }
        
        const PeSignature* peSig = reinterpret_cast<const PeSignature*>(data + peOffset);
        if (peSig->signature != 0x00004550) {  // "PE\0\0"
            return false;
        }
        
        info.format = BinaryInfo::Format::PE;
        
        // Parse COFF header
        const CoffFileHeader* coffHdr = 
            reinterpret_cast<const CoffFileHeader*>(data + peOffset + sizeof(PeSignature));
        
        // Determine architecture
        switch (coffHdr->Machine) {
            case 0x14C: info.arch = Architecture::X86_32; break;   // IMAGE_FILE_MACHINE_I386
            case 0x8664: info.arch = Architecture::X86_64; break;  // IMAGE_FILE_MACHINE_AMD64
            case 0xAA64: info.arch = Architecture::ARM64; break;   // IMAGE_FILE_MACHINE_ARM64
            case 0x01C0: info.arch = Architecture::ARM32; break;   // IMAGE_FILE_MACHINE_ARM
            default: info.arch = Architecture::UNKNOWN; break;
        }
        
        info.is64Bit = (coffHdr->Machine == 0x8664);
        info.isLittleEndian = true;
        
        // Parse optional header
        if (peOffset + sizeof(PeSignature) + sizeof(CoffFileHeader) + 
            sizeof(OptionalHeaderPe32) <= size) {
            const OptionalHeaderPe32* optHdr =
                reinterpret_cast<const OptionalHeaderPe32*>(
                    data + peOffset + sizeof(PeSignature) + sizeof(CoffFileHeader));
            
            info.entryPoint = optHdr->AddressOfEntryPoint;
            info.imageBase = optHdr->ImageBase;
        }
        
        // Parse sections (simplified)
        parseSections(data, size, coffHdr, peOffset, info);
        
        return true;
    }

private:
    static void parseSections(const uint8_t* data, size_t size,
                               const CoffFileHeader* coffHdr, int32_t peOffset,
                               BinaryInfo& info) {
        // Section headers follow optional header
        size_t sectionOffset = peOffset + sizeof(PeSignature) + sizeof(CoffFileHeader) +
                               coffHdr->SizeOfOptionalHeader;
        
        // Each section header is 40 bytes
        for (int i = 0; i < coffHdr->NumberOfSections; ++i) {
            if (sectionOffset + 40 > size) break;
            
            const char* sectionName = reinterpret_cast<const char*>(data + sectionOffset);
            uint32_t virtualSize = *reinterpret_cast<const uint32_t*>(data + sectionOffset + 8);
            uint32_t virtualAddress = *reinterpret_cast<const uint32_t*>(data + sectionOffset + 12);
            uint32_t sizeOfRawData = *reinterpret_cast<const uint32_t*>(data + sectionOffset + 16);
            uint32_t pointerToRawData = *reinterpret_cast<const uint32_t*>(data + sectionOffset + 20);
            uint32_t characteristics = *reinterpret_cast<const uint32_t*>(data + sectionOffset + 36);
            
            Section sec;
            sec.name = sectionName;
            sec.virtualAddress = virtualAddress;
            sec.virtualSize = virtualSize;
            sec.fileOffset = pointerToRawData;
            sec.fileSize = std::min(sizeOfRawData, static_cast<uint32_t>(size - pointerToRawData));
            sec.flags = characteristics;
            
            // Determine type based on characteristics
            if (characteristics & 0x20000000) {  // IMAGE_SCN_MEM_EXECUTE
                sec.type = Section::Type::CODE;
                sec.executable = true;
            } else if (characteristics & 0x40000000) {  // IMAGE_SCN_MEM_READ
                if (characteristics & 0x80000000) {  // IMAGE_SCN_MEM_WRITE
                    sec.type = Section::Type::DATA;
                    sec.writable = true;
                } else {
                    sec.type = Section::Type::RODATA;
                }
                sec.readable = true;
            } else {
                sec.type = Section::Type::UNKNOWN;
            }
            
            // Copy section data
            if (pointerToRawData < size && sizeOfRawData > 0) {
                size_t copySize = std::min(sizeOfRawData, static_cast<uint32_t>(size - pointerToRawData));
                sec.data.assign(data + pointerToRawData, data + pointerToRawData + copySize);
            }
            
            info.sections.push_back(sec);
            sectionOffset += 40;
        }
    }
};

} // namespace pe

// ============================================================================
// Main Binary Parser Interface
// ============================================================================

bool DisassemblerEngine::detectFormat() {
    if (fileData_.size() < 4) {
        binaryInfo_.format = BinaryInfo::Format::RAW;
        return true;
    }
    
    // Check for known formats
    
    // ELF
    if (fileData_[0] == 0x7F && fileData_[1] == 'E' && 
        fileData_[2] == 'L' && fileData_[3] == 'F') {
        return elf::ElfParser::parse(fileData_.data(), fileData_.size(), binaryInfo_);
    }
    
    // PE/MZ
    if (fileData_[0] == 'M' && fileData_[1] == 'Z') {
        return pe::PeParser::parse(fileData_.data(), fileData_.size(), binaryInfo_);
    }
    
    // Mach-O
    if ((fileData_[0] == 0xCE && fileData_[1] == 0xFA &&
         fileData_[2] == 0xED && fileData_[3] == 0xFE) ||
        (fileData_[0] == 0xCF && fileData_[1] == 0xFA &&
         fileData_[2] == 0xED && fileData_[3] == 0xFE)) {
        binaryInfo_.format = BinaryInfo::Format::MACH_O;
        // Would implement Mach-O parsing here
        return true;
    }
    
    // DEX (Android)
    if (fileData_.size() >= 8 &&
        fileData_[0] == 'd' && fileData_[1] == 'e' &&
        fileData_[2] == 'x' && fileData_[3] == '\n' &&
        fileData_[4] == '0' && fileData_[5] == '3' &&
        fileData_[6] == '0') {
        binaryInfo_.format = BinaryInfo::Format::DEX;
        binaryInfo_.arch = Architecture::ARM32;  // Default assumption
        // Would implement DEX parsing here
        return true;
    }
    
    // Unknown/raw format
    binaryInfo_.format = BinaryInfo::Format::RAW;
    binaryInfo_.arch = Architecture::UNKNOWN;
    
    return true;
}

} // namespace idapro
