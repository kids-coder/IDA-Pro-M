/**
 * IDA Pro M - Pattern Scanner
 * Binary pattern matching for signature detection and malware analysis
 */

#include "idapro_engine.h"
#include <algorithm>
#include <vector>
#include <string>
#include <regex>

namespace idapro {

// ============================================================================
// Pattern Scanner Implementation
// ============================================================================

class PatternScannerImpl {
public:
    explicit PatternScannerImpl(const uint8_t* data, size_t size)
        : data_(data), size_(size) {}
    
    // Scan for exact byte sequence
    std::vector<size_t> scanExact(const uint8_t* pattern, size_t patternSize) const {
        std::vector<size_t> results;
        
        if (patternSize == 0 || patternSize > size_) {
            return results;
        }
        
        // Simple byte-by-byte scan (could be optimized with Boyer-Moore or similar)
        for (size_t pos = 0; pos <= size_ - patternSize; ++pos) {
            bool match = true;
            for (size_t i = 0; i < patternSize; ++i) {
                if (data_[pos + i] != pattern[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                results.push_back(pos);
            }
        }
        
        return results;
    }
    
    // Scan for pattern with wildcards
    std::vector<size_t> scanWithMask(const uint8_t* pattern, const uint8_t* mask, 
                                      size_t patternSize) const {
        std::vector<size_t> results;
        
        if (patternSize == 0 || patternSize > size_) {
            return results;
        }
        
        for (size_t pos = 0; pos <= size_ - patternSize; ++pos) {
            bool match = true;
            for (size_t i = 0; i < patternSize; ++i) {
                if ((mask[i] & data_[pos + i]) != pattern[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                results.push_back(pos);
            }
        }
        
        return results;
    }
    
    // Scan for IDA-style pattern string (e.g., "48 8B ?? ?? 48 89")
    std::vector<size_t> scanIDAPattern(const std::string& idaPattern) const {
        // Parse IDA pattern format
        std::vector<uint8_t> pattern;
        std::vector<uint8_t> mask;
        
        std::istringstream iss(idaPattern);
        std::string token;
        
        while (iss >> token) {
            if (token == "??" || token == "?" || token == "??") {
                pattern.push_back(0x00);
                mask.push_back(0x00);  // Wildcard
            } else if (token.size() == 2) {
                uint8_t byte = 0;
                char high = std::toupper(token[0]);
                char low = std::toupper(token[1]);
                
                if ((high >= '0' && high <= '9') || (high >= 'A' && high <= 'F')) {
                    byte |= (high >= 'A' ? (high - 'A' + 10) : (high - '0')) << 4;
                }
                if ((low >= '0' && low <= '9') || (low >= 'A' && low <= 'F')) {
                    byte |= (low >= 'A' ? (low - 'A' + 10) : (low - '0'));
                }
                
                pattern.push_back(byte);
                mask.push_back(0xFF);
            }
        }
        
        return scanWithMask(pattern.data(), mask.data(), pattern.size());
    }
    
    // Scan for text/ASCII pattern
    std::vector<size_t> scanText(const std::string& text, bool caseSensitive = true) const {
        std::vector<size_t> results;
        
        if (text.empty() || text.size() > size_) {
            return results;
        }
        
        const uint8_t* textData = reinterpret_cast<const uint8_t*>(text.c_str());
        size_t textSize = text.size();
        
        if (caseSensitive) {
            return scanExact(textData, textSize);
        } else {
            // Case-insensitive search
            for (size_t pos = 0; pos <= size_ - textSize; ++pos) {
                bool match = true;
                for (size_t i = 0; i < textSize; ++i) {
                    char c1 = std::tolower(static_cast<unsigned char>(data_[pos + i]));
                    char c2 = std::tolower(static_cast<unsigned char>(textData[i]));
                    if (c1 != c2) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    results.push_back(pos);
                }
            }
            
            return results;
        }
    }
    
    // Scan for regex pattern in data (treats as bytes)
    std::vector<size_t> scanRegex(const std::string& regexPattern) const {
        std::vector<size_t> results;
        
        try {
            std::regex re(regexPattern, std::regex::optimize);
            
            // Convert data to string representation for regex matching
            std::string dataStr(reinterpret_cast<const char*>(data_), size_);
            
            std::sregex_iterator it(dataStr.begin(), dataStr.end(), re);
            std::sregex_iterator end;
            
            while (it != end) {
                results.push_back(it->position());
                ++it;
            }
        } catch (const std::regex_error&) {
            // Invalid regex, return empty results
        }
        
        return results;
    }

private:
    const uint8_t* data_;
    size_t size_;
};

// ============================================================================
// Signature Database
// ============================================================================

class SignatureDatabase {
public:
    void addSignature(const PatternSignature& sig) {
        signatures_.push_back(sig);
    }
    
    void addSignature(const std::string& name, const std::string& idaPattern,
                      const std::string& category = "", float confidence = 1.0f) {
        PatternSignature sig;
        sig.name = name;
        sig.category = category;
        sig.confidence = confidence;
        
        // Parse IDA pattern
        std::istringstream iss(idaPattern);
        std::string token;
        
        while (iss >> token) {
            if (token == "??" || token == "?") {
                sig.pattern.push_back(0x00);
                sig.mask.push_back(0x00);
            } else if (token.size() == 2) {
                uint8_t byte = 0;
                char high = std::toupper(token[0]);
                char low = std::toupper(token[1]);
                
                if ((high >= '0' && high <= '9') || (high >= 'A' && high <= 'F')) {
                    byte |= (high >= 'A' ? (high - 'A' + 10) : (high - '0')) << 4;
                }
                if ((low >= '0' && low <= '9') || (low >= 'A' && low <= 'F')) {
                    byte |= (low >= 'A' ? (low - 'A' + 10) : (low - '0'));
                }
                
                sig.pattern.push_back(byte);
                sig.mask.push_back(0xFF);
            }
        }
        
        signatures_.push_back(sig);
    }
    
    std::vector<PatternSignature> scanAll(const uint8_t* data, size_t size) const {
        std::vector<PatternSignature> matches;
        PatternScannerImpl scanner(data, size);
        
        for (const auto& sig : signatures_) {
            auto positions = scanner.scanWithMask(sig.pattern.data(), 
                                                   sig.mask.data(), 
                                                   sig.pattern.size());
            if (!positions.empty()) {
                PatternSignature matchedSig = sig;  // Copy
                matches.push_back(matchedSig);
            }
        }
        
        return matches;
    }
    
    std::vector<std::pair<std::string, std::vector<size_t>>> 
    scanDetailed(const uint8_t* data, size_t size) const {
        std::vector<std::pair<std::string, std::vector<size_t>>> results;
        PatternScannerImpl scanner(data, size);
        
        for (const auto& sig : signatures_) {
            auto positions = scanner.scanWithMask(sig.pattern.data(),
                                                   sig.mask.data(),
                                                   sig.pattern.size());
            if (!positions.empty()) {
                results.emplace_back(sig.name, positions);
            }
        }
        
        return results;
    }
    
    size_t signatureCount() const { return signatures_.size(); }
    void clear() { signatures_.clear(); }

private:
    std::vector<PatternSignature> signatures_;
};

// ============================================================================
// Common Signatures Library
// ============================================================================

class CommonSignatures {
public:
    static void populateCompilerSignatures(SignatureDatabase& db) {
        // GCC/Clang function prologue patterns
        db.addSignature("GCC_PushBP", "55 89 E5", "compiler", 0.95f);
        db.addSignature("GCC_SubSP_Immediate", "83 EC", "compiler", 0.90f);
        db.addSignature("GCC_StackAlign", "48 83 EC", "compiler", 0.90f);
        
        // MSVC function prologue
        db.addSignature("MSVC_PushBP", "55 8B EC", "compiler", 0.95f);
        db.addSignature("MSVC_ChainESP", "81 EC", "compiler", 0.90f);
        
        // ARM compiler patterns
        db.addSignature("ARM_Push_LR", "2D E9 F? 4?", "compiler", 0.90f);
        db.addSignature("ARM64_STP_FP_LR", "FD 7B B? A?", "compiler", 0.90f);
        
        // LLVM patterns
        db.addSignature("LLVM_StackProbe", "48 83 3C 25 00 00 00 00 00", "compiler", 0.85f);
    }
    
    static void populateLibrarySignatures(SignatureDatabase& db) {
        // C runtime functions
        db.addSignature("CRT_printf", "FF 15 ?? ?? ?? ??", "crt", 0.85f);
        db.addSignature("CRT_malloc", "FF 25 ?? ?? ?? ??", "crt", 0.85f);
        db.addSignature("CRT_memcpy", "A5", "crt", 0.70f);  // Too generic
        
        // OpenSSL
        db.addSignature("OpenSSL_Header", "23 30 21 4F 70 65 6E 53 53 4C", "crypto", 0.99f);
        
        // zlib
        db.addSignature("zlib_Header", "78 01 78 9C", "compression", 0.90f);
        db.addSignature("zlib_Header2", "78 DA", "compression", 0.90f);
        
        // PNG header
        db.addSignature("PNG_Header", "89 50 4E 47 0D 0A 1A 0A", "image", 1.0f);
        
        // JPEG header
        db.addSignature("JPEG_Header", "FF D8 FF", "image", 0.95f);
        
        // ZIP/JAR/Dex header
        db.addSignature("ZIP_Header", "50 4B 03 04", "archive", 0.95f);
        db.addSignature("DEX_Header", "64 65 78 0A 30 33", "android", 1.0f);
        
        // ELF header
        db.addSignature("ELF_Header", "7F 45 4C 46", "executable", 1.0f);
        
        // PE header
        db.addSignature("PE_Header", "4D 5A 90 00", "executable", 1.0f);
        
        // Mach-O header
        db.addSignature("MachO_BE_Header", "CE FA ED FE", "executable", 1.0f);
        db.addSignature("MachO_LE_Header", "CF FA ED FE", "executable", 1.0f);
    }
    
    static void populateAntiDebugSignatures(SignatureDatabase& db) {
        // Anti-debugging techniques
        db.addSignature("IsDebuggerPresent_API", "64 A1 30 00 00 00", "antidebug", 0.95f);
        db.addSignature("Peb_BeingDebugged_Check", "65 3A 02", "antidebug", 0.85f);
        db.addSignature("NtGlobalFlag_Check", "65 A1 30 00 00 00 83 ?? 70", "antidebug", 0.80f);
        db.addSignature("INT3_Scan", "CC CC CC", "antidebug", 0.75f);
        db.addSignature("RDTSC_Timing", "0F 31", "antidebug", 0.70f);
        db.addSignature("GetTickCount_Check", "FF 15 ?? ?? ?? ?? 3B C3", "antidebug", 0.80f);
    }
    
    static void populatePackersSignatures(SignatureDatabase& db) {
        // Executable packers
        db.addSignature("UPX_Packed", "UPX!", "packer", 1.0f);
        db.addSignature("ASPack_Header", "41 53 50 61 63 6B", "packer", 0.95f);
        db.addSignature("PECompact_Header", "50 45 43 6F 6D 70 61 63 74", "packer", 0.95f);
        db.addSignature("Themida_Header", "54 68 65 6D 69 64 61", "packer", 0.95f);
        db.addSignature("VMProtect_Header", "56 4D 50 72 6F 74 65 63 74", "packer", 0.99f);
    }
};

} // namespace idapro
