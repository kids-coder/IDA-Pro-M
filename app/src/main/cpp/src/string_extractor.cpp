/**
 * IDA Pro M - String Extractor
 * Extracts strings from binary data in various encodings
 */

#include "idapro_engine.h"
#include <vector>
#include <string>
#include <regex>
#include <algorithm>
#include <cctype>

namespace idapro {

// ============================================================================
// String Extraction Configuration
// ============================================================================

struct StringExtractionConfig {
    uint32_t minLength = 4;        // Minimum string length
    uint32_t maxLength = 4096;     // Maximum string length
    bool extractAscii = true;
    bool extractUtf8 = true;
    bool extractWideStrings = true;  // UTF-16
    bool extractUnicode = true;
    
    // Character filters
    bool allowControlChars = false;
    bool allowExtendedAscii = true;
    float printableRatioThreshold = 0.7f;  // Minimum ratio of printable chars
    
    // Null termination
    bool requireNullTerminated = true;
    
    // Type detection
    bool detectTypes = true;
};

// ============================================================================
// ASCII String Extractor
// ============================================================================

class AsciiStringExtractor {
public:
    explicit AsciiStringExtractor(const StringExtractionConfig& config)
        : config_(config) {}
    
    std::vector<StringEntry> extract(const uint8_t* data, size_t size) const {
        std::vector<StringEntry> results;
        
        if (!config_.extractAscii || size == 0) {
            return results;
        }
        
        size_t pos = 0;
        while (pos < size) {
            // Skip non-printable characters
            while (pos < size && !isAsciiChar(data[pos])) {
                ++pos;
            }
            
            if (pos >= size) break;
            
            // Start of potential string
            size_t start = pos;
            std::string currentString;
            
            while (pos < size && isAsciiChar(data[pos])) {
                currentString += static_cast<char>(data[pos]);
                ++pos;
                
                // Check for null terminator
                if (pos < size && data[pos] == 0) {
                    ++pos;  // Skip null terminator
                    break;
                }
            }
            
            // Check minimum length requirement
            if (currentString.length() >= config_.minLength &&
                currentString.length() <= config_.maxLength) {
                // Check printable ratio
                float printableRatio = calculatePrintableRatio(currentString);
                if (printableRatio >= config_.printableRatioThreshold) {
                    StringEntry entry;
                    entry.address = start;  // Would need virtual address mapping
                    entry.value = currentString;
                    entry.encoding = StringEntry::Encoding::ASCII;
                    entry.length = static_cast<uint32_t>(currentString.size());
                    entry.byteLength = static_cast<uint32_t>(currentString.size() + 1);  // +null
                    
                    if (config_.detectTypes) {
                        classifyString(entry);
                    }
                    
                    results.push_back(entry);
                }
            }
        }
        
        return results;
    }

private:
    StringExtractionConfig config_;
    
    bool isAsciiChar(uint8_t byte) const {
        if (byte == 0) return false;  // Null terminator
        
        if (config_.allowExtendedAscii && byte > 127) {
            return true;
        }
        
        return std::isprint(byte) != 0;
    }
    
    float calculatePrintableRatio(const std::string& str) const {
        if (str.empty()) return 0.0f;
        
        int printableCount = 0;
        for (char c : str) {
            if (std::isprint(static_cast<unsigned char>(c))) {
                ++printableCount;
            }
        }
        
        return static_cast<float>(printableCount) / static_cast<float>(str.size());
    }
    
    void classifyString(StringEntry& entry) const {
        // Detect common string types based on content patterns
        
        // URL detection
        if (std::regex_match(entry.value, 
            std::regex("https?://[\\w\\-./?=%&]+", std::regex::icase))) {
            entry.type = StringEntry::Type::URL;
            return;
        }
        
        // Email detection
        if (std::regex_match(entry.value,
            std::regex("[\\w.-]+@[\\w.-]+\\.\\w+", std::regex::icase))) {
            entry.type = StringEntry::Type::EMAIL;
            return;
        }
        
        // File path detection
        if ((entry.value.find('/') != std::string::npos ||
             entry.value.find('\\') != std::string::npos) &&
            entry.value.find('.') != std::string::npos) {
            entry.type = StringEntry::Type::PATH;
            return;
        }
        
        // GUID/UUID detection
        if (std::regex_match(entry.value,
            std::regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"))) {
            entry.type = StringEntry::Type::GUID;
            return;
        }
        
        // IP address detection
        if (std::regex_match(entry.value,
            std::regex("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"))) {
            entry.type = StringEntry::Type::IP_ADDRESS;
            return;
        }
        
        // Format string detection (%s, %d, etc.)
        if (entry.value.find('%') != std::string::npos &&
            std::regex_search(entry.value, std::regex("%[0-9]*[dfsxX]"))) {
            entry.type = StringEntry::Type::FORMAT_STRING;
            return;
        }
        
        // XML-like detection
        if (entry.value.find('<') == 0 && entry.value.find('>') != std::string::npos) {
            entry.type = StringEntry::Type::XML;
            return;
        }
        
        // JSON-like detection
        if ((entry.value.find('{') == 0 || entry.value.find('[') == 0) &&
            (entry.value.find('}') != std::string::npos || 
             entry.value.find(']') != std::string::npos)) {
            entry.type = StringEntry::Type::JSON;
            return;
        }
        
        // Base64 detection (mostly alphanumeric with possible padding)
        if (isBase64Like(entry.value)) {
            entry.type = StringEntry::Type::BASE64;
            return;
        }
        
        // Default: printable string
        entry.type = StringEntry::Type::PRINTABLE;
    }
    
    bool isBase64Like(const std::string& str) const {
        if (str.empty() || str.length() % 4 != 0) {
            return false;
        }
        
        int base64Count = 0;
        for (char c : str) {
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=') {
                ++base64Count;
            }
        }
        
        return base64Count == static_cast<int>(str.length());
    }
};

// ============================================================================
// Wide String (UTF-16) Extractor
// ============================================================================

class WideStringExtractor {
public:
    explicit WideStringExtractor(const StringExtractionConfig& config)
        : config_(config) {}
    
    std::vector<StringEntry> extract(const uint8_t* data, size_t size) const {
        std::vector<StringEntry> results;
        
        if (!config_.extractWideStrings || size < 2) {
            return results;
        }
        
        size_t pos = 0;
        while (pos < size - 1) {
            // Look for potential start of wide string (non-null low byte)
            uint8_t low = data[pos];
            uint8_t high = data[pos + 1];
            
            // UTF-16 LE: high byte should be 0 for ASCII range
            if (low != 0 && high == 0) {
                size_t start = pos;
                std::u16string wideStr;
                
                while (pos < size - 1) {
                    uint16_t ch = data[pos] | (data[pos + 1] << 8);
                    
                    if (ch == 0) {  // Null terminator
                        pos += 2;
                        break;
                    }
                    
                    if (ch < 256 && std::isprint(ch)) {
                        wideStr += static_cast<char16_t>(ch);
                    } else if (ch >= 0x20 && !std::iscntrl(ch)) {
                        wideStr += static_cast<char16_t>(ch);  // Unicode character
                    } else {
                        break;  // Non-printable character
                    }
                    
                    pos += 2;
                }
                
                // Convert to UTF-8 for storage
                std::string utf8Str = utf16ToUtf8(wideStr);
                
                if (utf8Str.length() >= config_.minLength &&
                    utf8Str.length() <= config_.maxLength) {
                    StringEntry entry;
                    entry.address = start;
                    entry.value = utf8Str;
                    entry.encoding = StringEntry::Encoding::UTF16_LE;
                    entry.length = static_cast<uint32_t>(wideStr.length());
                    entry.byteLength = static_cast<uint32_t>((wideStr.length() + 1) * 2);
                    entry.type = StringEntry::Type::WIDE;
                    
                    results.push_back(entry);
                }
            } else {
                ++pos;
            }
        }
        
        return results;
    }

private:
    StringExtractionConfig config_;
    
    std::string utf16ToUtf8(const std::u16string& utf16) const {
        std::string utf8;
        for (char16_t ch : utf16) {
            if (ch < 0x80) {
                utf8 += static_cast<char>(ch);
            } else if (ch < 0x800) {
                utf8 += static_cast<char>(0xC0 | (ch >> 6));
                utf8 += static_cast<char>(0x80 | (ch & 0x3F));
            } else {
                utf8 += static_cast<char>(0xE0 | (ch >> 12));
                utf8 += static_cast<char>(0x80 | ((ch >> 6) & 0x3F));
                utf8 += static_cast<char>(0x80 | (ch & 0x3F));
            }
        }
        return utf8;
    }
};

// ============================================================================
// UTF-8 String Extractor
// ============================================================================

class Utf8StringExtractor {
public:
    explicit Utf8StringExtractor(const StringExtractionConfig& config)
        : config_(config) {}
    
    std::vector<StringEntry> extract(const uint8_t* data, size_t size) const {
        std::vector<StringEntry> results;
        
        if (!config_.extractUtf8 || size == 0) {
            return results;
        }
        
        size_t pos = 0;
        while (pos < size) {
            // Check for valid UTF-8 start byte
            uint8_t byte = data[pos];
            
            int expectedBytes = 0;
            if ((byte & 0x80) == 0) {
                expectedBytes = 1;  // ASCII
            } else if ((byte & 0xE0) == 0xC0) {
                expectedBytes = 2;
            } else if ((byte & 0xF0) == 0xE0) {
                expectedBytes = 3;
            } else if ((byte & 0xF8) == 0xF0) {
                expectedBytes = 4;
            } else {
                ++pos;  // Invalid UTF-8 start byte, skip
                continue;
            }
            
            // Check if we have enough bytes
            if (pos + expectedBytes > size) {
                break;
            }
            
            // Validate continuation bytes
            bool valid = true;
            for (int i = 1; i < expectedBytes; ++i) {
                if ((data[pos + i] & 0xC0) != 0x80) {
                    valid = false;
                    break;
                }
            }
            
            if (!valid) {
                ++pos;
                continue;
            }
            
            // Extract UTF-8 sequence
            size_t start = pos;
            std::string utf8Str;
            
            while (pos < size) {
                byte = data[pos];
                
                // Check for null terminator or invalid sequence
                if (byte == 0) {
                    ++pos;
                    break;
                }
                
                // Try to decode as UTF-8
                int seqLen = getUtf8SequenceLength(data + pos, size - pos);
                if (seqLen == 0) {
                    break;
                }
                
                // Add characters to string
                for (int i = 0; i < seqLen; ++i) {
                    utf8Str += static_cast<char>(data[pos + i]);
                }
                pos += seqLen;
            }
            
            // Check length requirements
            if (utf8Str.length() >= config_.minLength &&
                utf8Str.length() <= config_.maxLength) {
                StringEntry entry;
                entry.address = start;
                entry.value = utf8Str;
                entry.encoding = StringEntry::Encoding::UTF8;
                entry.length = static_cast<uint32_t>(utf8Str.length());
                entry.byteLength = static_cast<uint32_t>(utf8Str.length() + 1);
                entry.type = StringEntry::Type::UNICODE;
                
                results.push_back(entry);
            }
        }
        
        return results;
    }

private:
    StringExtractionConfig config_;
    
    int getUtf8SequenceLength(const uint8_t* data, size_t maxSize) const {
        if (maxSize == 0) return 0;
        
        uint8_t byte = data[0];
        
        if ((byte & 0x80) == 0) return 1;
        if ((byte & 0xE0) == 0xC0) return maxSize >= 2 ? 2 : 0;
        if ((byte & 0xF0) == 0xE0) return maxSize >= 3 ? 3 : 0;
        if ((byte & 0xF8) == 0xF0) return maxSize >= 4 ? 4 : 0;
        
        return 0;  // Invalid start byte
    }
};

// ============================================================================
// Main String Extractor Interface
// ============================================================================

class StringExtractorImpl {
public:
    explicit StringExtractorImpl(const StringExtractionConfig& config = StringExtractionConfig{})
        : asciiExtractor_(config), wideExtractor_(config), utf8Extractor_(config),
          config_(config) {}
    
    std::vector<StringEntry> extractAll(const uint8_t* data, size_t size) const {
        std::vector<StringEntry> allStrings;
        
        // Extract ASCII strings
        auto asciiStrings = asciiExtractor_.extract(data, size);
        allStrings.insert(allStrings.end(), asciiStrings.begin(), asciiStrings.end());
        
        // Extract wide (UTF-16) strings
        auto wideStrings = wideExtractor_.extract(data, size);
        allStrings.insert(allStrings.end(), wideStrings.begin(), wideStrings.end());
        
        // Extract UTF-8 strings (may overlap with ASCII)
        if (config_.extractUtf8) {
            auto utf8Strings = utf8Extractor_.extract(data, size);
            // Filter out strings that are already in ASCII set (simple approach)
            for (auto& str : utf8Strings) {
                bool isDuplicate = false;
                for (const auto& existing : allStrings) {
                    if (existing.address == str.address) {
                        isDuplicate = true;
                        break;
                    }
                }
                if (!isDuplicate) {
                    allStrings.push_back(str);
                }
            }
        }
        
        // Sort by address
        std::sort(allStrings.begin(), allStrings.end(),
                  [](const StringEntry& a, const StringEntry& b) {
                      return a.address < b.address;
                  });
        
        return allStrings;
    }

private:
    AsciiStringExtractor asciiExtractor_;
    WideStringExtractor wideExtractor_;
    Utf8StringExtractor utf8Extractor_;
    StringExtractionConfig config_;
};

} // namespace idapro
