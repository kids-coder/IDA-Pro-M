/**
 * IDA Pro M - Hex Utility Functions
 * Provides hex encoding/decoding, formatting, and manipulation utilities
 */

#include "idapro_engine.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace idapro {
namespace hex {

// ============================================================================
// Hex Encoding/Decoding
// ============================================================================

std::string bytesToHex(const uint8_t* data, size_t length, bool uppercase = true, 
                       char separator = ' ', size_t groupSize = 1) {
    std::ostringstream oss;
    if (uppercase) {
        oss << std::uppercase;
    }
    
    for (size_t i = 0; i < length; ++i) {
        if (i > 0 && separator && (i % groupSize == 0)) {
            oss << separator;
        }
        oss << std::hex << std::setfill('0') << std::setw(2) 
            << static_cast<unsigned>(data[i]);
    }
    
    return oss.str();
}

std::vector<uint8_t> hexToBytes(const std::string& hexString) {
    std::vector<uint8_t> bytes;
    std::istringstream iss(hexString);
    
    // Remove whitespace
    std::string clean;
    char c;
    while (iss.get(c)) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean += c;
        }
    }
    
    // Must have even number of characters
    if (clean.length() % 2 != 0) {
        return bytes;
    }
    
    for (size_t i = 0; i < clean.length(); i += 2) {
        uint8_t byte = 0;
        char high = std::toupper(static_cast<unsigned char>(clean[i]));
        char low = std::toupper(static_cast<unsigned char>(clean[i+1]));
        
        byte |= (high >= 'A' ? (high - 'A' + 10) : (high - '0')) << 4;
        byte |= (low >= 'A' ? (low - 'A' + 10) : (low - '0'));
        
        bytes.push_back(byte);
    }
    
    return bytes;
}

// ============================================================================
// Hex Dump Formatting
// ============================================================================

struct HexDumpOptions {
    int bytesPerLine = 16;
    bool showAscii = true;
    bool showOffset = true;
    bool showHex = true;
    bool uppercaseHex = true;
    char separator = ' ';
    int offsetBase = 16;  // 10 or 16
    size_t startOffset = 0;
    bool useColor = false;  // For terminal output
    
    // Colors for modified/highlighted bytes
    const char* normalColor = "\033[0m";
    const char* modifiedColor = "\033[31m";   // Red
    const char* highlightColor = "\033[33m";  // Yellow
};

class HexDumper {
public:
    explicit HexDumper(const HexDumpOptions& options = HexDumpOptions{})
        : options_(options) {}
    
    std::string dump(const uint8_t* data, size_t length, 
                     const uint8_t* highlights = nullptr,
                     const uint8_t* modifications = nullptr) {
        std::ostringstream output;
        
        for (size_t offset = 0; offset < length; offset += options_.bytesPerLine) {
            size_t lineLength = std::min(options_.bytesPerLine, length - offset);
            
            // Offset column
            if (options_.showOffset) {
                output << formatOffset(offset + options_.startOffset);
                output << "  ";
            }
            
            // Hex data columns
            if (options_.showHex) {
                for (size_t i = 0; i < options_.bytesPerLine; ++i) {
                    if (i < lineLength) {
                        size_t idx = offset + i;
                        
                        // Check for color coding
                        if (options_.useColor) {
                            if (modifications && modifications[idx]) {
                                output << options_.modifiedColor;
                            } else if (highlights && highlights[idx]) {
                                output << options_.highlightColor;
                            }
                        }
                        
                        output << formatByte(data[idx]);
                        
                        if (options_.useColor) {
                            output << options_.normalColor;
                        }
                    } else {
                        output << "  ";
                    }
                    
                    output << options_.separator;
                    
                    // Extra space in middle of line
                    if (options_.bytesPerLine == 16 && i == 7) {
                        output << " ";
                    }
                }
                
                // Space between hex and ASCII
                output << " ";
            }
            
            // ASCII column
            if (options_.showAscii) {
                for (size_t i = 0; i < lineLength; ++i) {
                    char c = static_cast<char>(data[offset + i]);
                    output << (std::isprint(static_cast<unsigned char>(c)) ? c : '.');
                }
            }
            
            output << "\n";
        }
        
        return output.str();
    }
    
private:
    HexDumpOptions options_;
    
    std::string formatOffset(size_t offset) const {
        std::ostringstream oss;
        if (options_.offsetBase == 16) {
            oss << std::hex << std::uppercase << std::setfill('0') 
                << std::setw(8) << offset;
        } else {
            oss << std::dec << std::setfill('0') << std::setw(8) << offset;
        }
        return oss.str();
    }
    
    std::string formatByte(uint8_t byte) const {
        std::ostringstream oss;
        if (options_.uppercaseHex) {
            oss << std::uppercase;
        }
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<unsigned>(byte);
        return oss.str();
    }
};

// ============================================================================
// Pattern Matching
// ============================================================================

struct HexPattern {
    std::vector<uint8_t> pattern;
    std::vector<uint8_t> mask;  // 0xFF = must match, 0x00 = wildcard
    
    static HexPattern fromString(const std::string& patternStr) {
        HexPattern result;
        std::istringstream iss(patternStr);
        std::string token;
        
        while (iss >> token) {
            if (token == "??" || token == "?") {
                result.pattern.push_back(0x00);
                result.mask.push_back(0x00);  // Wildcard
            } else if (token.size() == 2) {
                uint8_t byte = 0;
                char high = std::toupper(token[0]);
                char low = std::toupper(token[1]);
                
                if (std::isxdigit(static_cast<unsigned char>(high)) &&
                    std::isxdigit(static_cast<unsigned char>(low))) {
                    byte |= (high >= 'A' ? (high - 'A' + 10) : (high - '0')) << 4;
                    byte |= (low >= 'A' ? (low - 'A' + 10) : (low - '0'));
                    
                    result.pattern.push_back(byte);
                    result.mask.push_back(0xFF);
                }
            }
        }
        
        return result;
    }
    
    bool matchAt(const uint8_t* data, size_t dataSize, size_t position) const {
        if (position + pattern.size() > dataSize) {
            return false;
        }
        
        for (size_t i = 0; i < pattern.size(); ++i) {
            if ((mask[i] & data[position + i]) != pattern[i]) {
                return false;
            }
        }
        
        return true;
    }
    
    std::vector<size_t> findAll(const uint8_t* data, size_t dataSize) const {
        std::vector<size_t> matches;
        
        if (pattern.empty()) {
            return matches;
        }
        
        for (size_t pos = 0; pos + pattern.size() <= dataSize; ++pos) {
            if (matchAt(data, dataSize, pos)) {
                matches.push_back(pos);
            }
        }
        
        return matches;
    }
};

// ============================================================================
// Byte Manipulation
// ============================================================================

uint8_t readByte(const uint8_t* data, size_t offset) {
    return data[offset];
}

uint16_t readWordLE(const uint8_t* data, size_t offset) {
    return static_cast<uint16_t>(data[offset]) |
           (static_cast<uint16_t>(data[offset + 1]) << 8);
}

uint16_t readWordBE(const uint8_t* data, size_t offset) {
    return (static_cast<uint16_t>(data[offset]) << 8) |
           static_cast<uint16_t>(data[offset + 1]);
}

uint32_t readDwordLE(const uint8_t* data, size_t offset) {
    return static_cast<uint32_t>(data[offset]) |
           (static_cast<uint32_t>(data[offset + 1]) << 8) |
           (static_cast<uint32_t>(data[offset + 2]) << 16) |
           (static_cast<uint32_t>(data[offset + 3]) << 24);
}

uint32_t readDwordBE(const uint8_t* data, size_t offset) {
    return (static_cast<uint32_t>(data[offset]) << 24) |
           (static_cast<uint32_t>(data[offset + 1]) << 16) |
           (static_cast<uint32_t>(data[offset + 2]) << 8) |
           static_cast<uint32_t>(data[offset + 3]);
}

uint64_t readQwordLE(const uint8_t* data, size_t offset) {
    return static_cast<uint64_t>(readDwordLE(data, offset)) |
           (static_cast<uint64_t>(readDwordLE(data, offset + 4)) << 32);
}

uint64_t readQwordBE(const uint8_t* data, size_t offset) {
    return (static_cast<uint64_t>(readDwordBE(data, offset)) << 32) |
           static_cast<uint64_t>(readDwordBE(data, offset + 4));
}

void writeByte(uint8_t* data, size_t offset, uint8_t value) {
    data[offset] = value;
}

void writeWordLE(uint8_t* data, size_t offset, uint16_t value) {
    data[offset] = value & 0xFF;
    data[offset + 1] = (value >> 8) & 0xFF;
}

void writeWordBE(uint8_t* data, size_t offset, uint16_t value) {
    data[offset] = (value >> 8) & 0xFF;
    data[offset + 1] = value & 0xFF;
}

void writeDwordLE(uint8_t* data, size_t offset, uint32_t value) {
    data[offset] = value & 0xFF;
    data[offset + 1] = (value >> 8) & 0xFF;
    data[offset + 2] = (value >> 16) & 0xFF;
    data[offset + 3] = (value >> 24) & 0xFF;
}

void writeDwordBE(uint8_t* data, size_t offset, uint32_t value) {
    data[offset] = (value >> 24) & 0xFF;
    data[offset + 1] = (value >> 16) & 0xFF;
    data[offset + 2] = (value >> 8) & 0xFF;
    data[offset + 3] = value & 0xFF;
}

// ============================================================================
// Bit Operations
// ============================================================================

bool isBitSet(uint8_t value, uint8_t bit) {
    return (value & (1 << bit)) != 0;
}

bool isBitSet(uint32_t value, uint8_t bit) {
    return (value & (1ULL << bit)) != 0;
}

bool isBitSet(uint64_t value, uint8_t bit) {
    return (value & (1ULL << bit)) != 0;
}

uint8_t setBit(uint8_t value, uint8_t bit) {
    return value | (1 << bit);
}

uint8_t clearBit(uint8_t value, uint8_t bit) {
    return value & ~(1 << bit);
}

uint8_t toggleBit(uint8_t value, uint8_t bit) {
    return value ^ (1 << bit);
}

uint8_t extractBits(uint8_t value, uint8_t high, uint8_t low) {
    uint8_t mask = ((1 << (high - low + 1)) - 1) << low;
    return (value & mask) >> low;
}

uint32_t extractBits(uint32_t value, uint8_t high, uint8_t low) {
    uint32_t mask = ((1ULL << (high - low + 1)) - 1) << low;
    return (value & mask) >> low;
}

uint64_t extractBits(uint64_t value, uint8_t high, uint8_t low) {
    uint64_t mask = ((1ULL << (high - low + 1)) - 1) << low;
    return (value & mask) >> low;
}

int countSetBits(uint8_t value) {
    int count = 0;
    while (value) {
        count += value & 1;
        value >>= 1;
    }
    return count;
}

int countSetBits(uint32_t value) {
    int count = 0;
    while (value) {
        count += value & 1;
        value >>= 1;
    }
    return count;
}

int countSetBits(uint64_t value) {
    int count = 0;
    while (value) {
        count += value & 1;
        value >>= 1;
    }
    return count;
}

// ============================================================================
// Endian Conversion
// ============================================================================

uint16_t swapEndian16(uint16_t value) {
    return (value << 8) | (value >> 8);
}

uint32_t swapEndian32(uint32_t value) {
    return ((value & 0x000000FF) << 24) |
           ((value & 0x0000FF00) << 8) |
           ((value & 0x00FF0000) >> 8) |
           ((value & 0xFF000000) >> 24);
}

uint64_t swapEndian64(uint64_t value) {
    return ((value & 0x00000000000000FFULL) << 56) |
           ((value & 0x000000000000FF00ULL) << 40) |
           ((value & 0x0000000000FF0000ULL) << 24) |
           ((value & 0x00000000FF000000ULL) << 8) |
           ((value & 0x000000FF00000000ULL) >> 8) |
           ((value & 0x0000FF0000000000ULL) >> 24) |
           ((value & 0x00FF000000000000ULL) >> 40) |
           ((value & 0xFF00000000000000ULL) >> 56);
}

} // namespace hex
} // namespace idapro
