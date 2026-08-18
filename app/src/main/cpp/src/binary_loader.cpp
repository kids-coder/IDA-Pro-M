/**
 * IDA Pro M - Binary Loader
 * Handles loading binary files into memory for analysis
 */

#include "idapro_engine.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>

namespace idapro {

// ============================================================================
// Binary Loader Implementation
// ============================================================================

class BinaryLoaderImpl {
public:
    // Load file from path
    bool loadFromFile(const std::string& filePath, std::vector<uint8_t>& buffer) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return false;
        }
        
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        if (size > 512 * 1024 * 1024) {  // 512 MB limit
            return false;
        }
        
        buffer.resize(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            return false;
        }
        
        return true;
    }
    
    // Load from memory buffer
    bool loadFromBuffer(const uint8_t* data, size_t size, std::vector<uint8_t>& buffer) {
        if (data == nullptr || size == 0 || size > 512 * 1024 * 1024) {
            return false;
        }
        
        buffer.assign(data, data + size);
        return true;
    }
    
    // Validate loaded data
    bool validateData(const uint8_t* data, size_t size, BinaryInfo& info) {
        if (data == nullptr || size == 0) {
            return false;
        }
        
        info.fileSize = size;
        
        // Compute hashes
        info.md5Hash = computeMD5(data, size);
        info.sha256Hash = computeSHA256(data, size);
        
        return true;
    }
    
    // Create memory regions from sections
    std::vector<MemoryRegion> createMemoryRegions(const BinaryInfo& info,
                                                   const std::vector<uint8_t>& fileData) {
        std::vector<MemoryRegion> regions;
        
        for (const auto& section : info.sections) {
            MemoryRegion region;
            region.startAddress = section.virtualAddress;
            region.endAddress = section.virtualAddress + section.virtualSize;
            
            // Determine access permissions
            region.readable = section.readable;
            region.writable = section.writable;
            region.executable = section.executable;
            
            // Copy data
            if (section.fileOffset + section.fileSize <= fileData.size() &&
                !section.data.empty()) {
                region.data = section.data;
            }
            
            region.name = section.name;
            regions.push_back(region);
        }
        
        return regions;
    }

private:
    // Simple hash implementations (would use proper crypto library in production)
    std::string computeMD5(const uint8_t* data, size_t size) {
        // Simplified MD5 placeholder
        (void)data; (void)size;
        return "md5_" + std::to_string(size);
    }
    
    std::string computeSHA256(const uint8_t* data, size_t size) {
        // Simplified SHA256 placeholder
        (void)data; (void)size;
        return "sha256_" + std::to_string(size);
    }
};

// ============================================================================
// Memory Region Structure
// ============================================================================

struct MemoryRegion {
    uint64_t startAddress = 0;
    uint64_t endAddress = 0;
    std::vector<uint8_t> data;
    std::string name;
    
    bool readable = false;
    bool writable = false;
    bool executable = false;
    
    enum class Type : uint8_t {
        CODE = 0,
        DATA = 1,
        BSS = 2,
        HEAP = 3,
        STACK = 4,
        MAPPED = 5,
        UNKNOWN = 255
    } type = Type::UNKNOWN;
    
    size_t size() const { return endAddress - startAddress; }
    bool contains(uint64_t addr) const {
        return addr >= startAddress && addr < endAddress;
    }
    
    const uint8_t* getDataAt(uint64_t offset) const {
        if (offset < data.size()) {
            return &data[offset];
        }
        return nullptr;
    }
};

// ============================================================================
// Disassembler Engine - File Loading Implementation
// ============================================================================

bool DisassemblerEngine::loadFile(const std::string& filePath) {
    BinaryLoaderImpl loader;
    
    if (!loader.loadFromFile(filePath, fileData_)) {
        return false;
    }
    
    binaryInfo_.fileName = filePath.substr(filePath.find_last_of("/\\") + 1);
    binaryInfo_.fullPath = filePath;
    
    if (!loader.validateData(fileData_.data(), fileData_.size(), binaryInfo_)) {
        return false;
    }
    
    loaded_ = true;
    analyzed_ = false;
    
    return true;
}

bool DisassemblerEngine::loadBuffer(const uint8_t* data, size_t size, const std::string& name) {
    BinaryLoaderImpl loader;
    
    if (!loader.loadFromBuffer(data, size, fileData_)) {
        return false;
    }
    
    binaryInfo_.fileName = name.empty() ? "buffer" : name;
    binaryInfo_.fullPath = "memory_buffer";
    
    if (!loader.validateData(fileData_.data(), fileData_.size(), binaryInfo_)) {
        return false;
    }
    
    loaded_ = true;
    analyzed_ = false;
    
    return true;
}

void DisassemblerEngine::unload() {
    fileData_.clear();
    binaryInfo_ = BinaryInfo();
    lastResult_ = AnalysisResult();
    loaded_ = false;
    analyzed_ = false;
}

} // namespace idapro
