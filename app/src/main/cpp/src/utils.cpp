/**
 * @file utils.cpp
 * @brief Utility Functions Implementation
 * 
 * Provides:
 * - String conversion helpers (UTF-8, modified UTF-8)
 * - Hex formatting utilities
 * - Memory-mapped file I/O (mmap/munmap)
 * - Hash/checksum implementations
 * - Simple thread pool for parallel processing
 * 
 * @version 3.0.0
 */

#include "ida_pro_native.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <queue>
#include <functional>
#include <future>
#include <chrono>
#include <cstring>

#if defined(__ANDROID__) || defined(ANDROID)
    #include <sys/mman.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <errno.h>
#endif

namespace ida {

// ============================================================================
// String/Hex Conversion Utilities
// ============================================================================

namespace Utils {

std::string toHex(std::span<const std::byte> data, bool uppercase) noexcept {
    std::string result;
    result.reserve(data.size() * 2);
    
    for (const auto byte : data) {
        uint8_t val = static_cast<uint8_t>(byte);
        char hi = byteToHexChar(val >> 4, uppercase);
        char lo = byteToHexChar(val & 0x0F, uppercase);
        result.push_back(hi);
        result.push_back(lo);
    }
    
    return result;
}

std::string toHexSpaced(std::span<const std::byte> data, bool uppercase) noexcept {
    std::string result;
    result.reserve(data.size() * 3);  // Account for spaces
    
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0) result.push_back(' ');
        
        uint8_t val = static_cast<uint8_t>(data[i]);
        char hi = byteToHexChar(val >> 4, uppercase);
        char lo = byteToHexChar(val & 0x0F, uppercase);
        result.push_back(hi);
        result.push_back(lo);
    }
    
    return result;
}

AnalysisResult<std::vector<uint8_t>> fromHex(std::string_view hex) noexcept {
    // Remove whitespace
    std::string clean;
    clean.reserve(hex.size());
    for (char c : hex) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean.push_back(c);
        }
    }
    
    // Must have even number of characters
    if (clean.size() % 2 != 0) {
        return std::unexpected(AnalysisError::ParseError);
    }
    
    std::vector<uint8_t> result(clean.size() / 2);
    
    for (size_t i = 0; i < clean.size(); i += 2) {
        char hi = clean[i];
        char lo = clean[i + 1];
        
        auto hexVal = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0xFF;  // Invalid
        };
        
        uint8_t high = hexVal(hi);
        uint8_t low = hexVal(lo);
        
        if (high == 0xFF || low == 0xFF) {
            return std::unexpected(AnalysisError::ParseError);
        }
        
        result[i / 2] = static_cast<uint8_t>((high << 4) | low);
    }
    
    return result;
}

size_t safeStrCopy(char* dest, std::string_view src, size_t maxSize) noexcept {
    if (!dest || maxSize == 0) return 0;
    
    size_t copyLen = std::min(src.length(), maxSize - 1);
    std::memcpy(dest, src.data(), copyLen);
    dest[copyLen] = '\0';
    
    return copyLen;
}

std::string toModifiedUTF8(std::string_view utf8) {
    // Convert standard UTF-8 to JNI modified UTF-8
    // Main difference: null bytes are encoded as 0xC0 0x80
    std::string result;
    result.reserve(utf8.length());
    
    for (size_t i = 0; i < utf8.length(); ++i) {
        unsigned char c = static_cast<unsigned char>(utf8[i]);
        
        if (c == 0) {
            // Encode null as overlong UTF-8: 0xC0 0x80
            result.push_back('\xC0');
            result.push_back('\x80');
        } else {
            result.push_back(static_cast<char>(c));
        }
    }
    
    return result;
}

std::string fromModifiedUTF8(std::string_view mutf8) {
    // Convert JNI modified UTF-8 to standard UTF-8
    std::string result;
    result.reserve(mutf8.length());
    
    for (size_t i = 0; i < mutf8.length(); ++i) {
        unsigned char c = static_cast<unsigned char>(mutf8[i]);
        
        if (c == 0xC0 && i + 1 < mutf8.length()) {
            unsigned char next = static_cast<unsigned char>(mutf8[i + 1]);
            if (next == 0x80) {
                // Overlong null encoding -> actual null
                result.push_back('\0');
                ++i;  // Skip next byte
            } else {
                result.push_back(static_cast<char>(c));
            }
        } else {
            result.push_back(static_cast<char>(c));
        }
    }
    
    return result;
}

} // namespace Utils

// ============================================================================
// File Mapping Utilities
// ============================================================================

namespace Utils {

AnalysisResult<MappedFile> mapFile(const std::filesystem::path& path) noexcept {
    MappedFile mapped{};
    
#if defined(__ANDROID__) || defined(ANDROID)
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            return std::unexpected(AnalysisError::FileNotFound);
        } else if (errno == EACCES) {
            return std::unexpected(AnalysisError::FileAccessDenied);
        }
        return std::unexpected(AnalysisError::UnknownError);
    }
    
    // Get file size
    struct stat st {};
    if (fstat(fd, &st) < 0) {
        close(fd);
        return std::unexpected(AnalysisError::UnknownError);
    }
    
    if (st.st_size == 0) {
        close(fd);
        return std::unexpected(AnalysisError::CorruptFile);
    }
    
    // Map file into memory
    void* addr = mmap(nullptr, static_cast<size_t>(st.st_size), 
                      PROT_READ, MAP_PRIVATE, fd, 0);
    
    if (addr == MAP_FAILED) {
        close(fd);
        return std::unexpected(AnalysisError::OutOfMemory);
    }
    
    mapped.data = addr;
    mapped.size = static_cast<size_t>(st.st_size);
    mapped.fd = fd;
    mapped.owned = true;
    
    // Advise sequential access pattern
    madvise(addr, static_cast<size_t>(st.st_size), MADV_SEQUENTIAL);
    
#else
    // Fallback: read file into memory buffer
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return std::unexpected(AnalysisError::FileNotFound);
    }
    
    auto size = file.tellg();
    if (size <= 0) {
        return std::unexpected(AnalysisError::CorruptFile);
    }
    
    file.seekg(0, std::ios::beg);
    
    auto* buffer = new (std::nothrow) std::byte[static_cast<size_t>(size)];
    if (!buffer) {
        return std::unexpected(AnalysisError::OutOfMemory);
    }
    
    if (!file.read(reinterpret_cast<char*>(buffer), size)) {
        delete[] buffer;
        return std::unexpected(AnalysisError::UnknownError);
    }
    
    mapped.data = buffer;
    mapped.size = static_cast<size_t>(size);
    mapped.fd = -1;
    mapped.owned = true;
#endif
    
    return mapped;
}

void unmapFile(MappedFile& mapped) noexcept {
    if (!mapped.isValid()) return;
    
#if defined(__ANDROID__) || defined(ANDROID)
    if (mapped.data != nullptr && mapped.size > 0) {
        munmap(mapped.data, mapped.size);
    }
    if (mapped.fd >= 0) {
        close(mapped.fd);
    }
#else
    if (mapped.data != nullptr) {
        delete[] reinterpret_cast<std::byte*>(mapped.data);
    }
#endif
    
    mapped.data = nullptr;
    mapped.size = 0;
    mapped.fd = -1;
}

} // namespace Utils

// ============================================================================
// Hash and Checksum Utilities
// ============================================================================

namespace Utils {

std::array<uint8_t, 32> computeSHA256(std::span<const std::byte> data) noexcept {
    // Placeholder implementation - in production, use a real crypto library
    // like OpenSSL's SHA256 or BoringSSL on Android
    
    std::array<uint8_t, 32> hash{};
    
    // Use FNV-1a as a simple placeholder hash
    // This is NOT cryptographically secure!
    uint64_t fnvHash = 14695981039346656037ULL;
    
    for (const auto byte : data) {
        fnvHash ^= static_cast<uint8_t>(byte);
        fnvHash *= 1099511628211ULL;
    }
    
    // Spread the 64-bit hash across 32 bytes
    for (int i = 0; i < 32; ++i) {
        // Simple mixing based on position
        uint64_t mixed = fnvHash ^ (static_cast<uint64_t>(i) * 0x517CC1B727220A95ULL);
        mixed ^= mixed >> 32;
        mixed *= 0x85EBCA6C82BD6FBFULL;
        mixed ^= mixed >> 33;
        mixed *= 0xC4CEB9FE1A85EC53ULL;
        mixed ^= mixed >> 33;
        
        hash[static_cast<size_t>(i)] = static_cast<uint8_t>(mixed);
        hash[static_cast<size_t>(i)] ^= static_cast<uint8_t>(mixed >> 8);
    }
    
    // Mark first byte to indicate this is a placeholder hash
    hash[0] |= 0x80;
    
    return hash;
}

uint32_t computeCRC32(std::span<const std::byte> data) noexcept {
    // CRC-32 (IEEE 802.3) polynomial: 0xEDB88320 (reversed)
    constexpr uint32_t polynomial = 0xEDB88320;
    
    // Build lookup table (computed at compile time in C++23 ideally)
    static const uint32_t crcTable[] = []() constexpr {
        std::array<uint32_t, 256> table{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t crc = i;
            for (uint8_t j = 0; j < 8; ++j) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ polynomial;
                } else {
                    crc >>= 1;
                }
            }
            table[i] = crc;
        }
        return table;
    }();
    
    uint32_t crc = 0xFFFFFFFF;
    
    for (const auto byte : data) {
        uint8_t index = static_cast<uint8_t>((crc ^ static_cast<uint8_t>(byte)) & 0xFF);
        crc = (crc >> 8) ^ crcTable[index];
    }
    
    return crc ^ 0xFFFFFFFF;
}

} // namespace Utils

// ============================================================================
// Binary Detection Utilities
// ============================================================================

namespace BinaryUtils {

BinaryFormat detectFormat(std::span<const std::byte> header) noexcept {
    if (header.size() < 16) {
        return BinaryFormat::Unknown;
    }
    
    auto bytes = reinterpret_cast<const uint8_t*>(header.data());
    
    // ELF magic: 0x7F 'E' 'L' 'F'
    if (bytes[0] == 0x7F && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F') {
        return BinaryFormat::ELF;
    }
    
    // PE magic: "MZ" at offset 0, "PE\0\0" at PE header offset
    if (bytes[0] == 'M' && bytes[1] == 'Z') {
        // Check for PE signature at offset stored in header
        if (header.size() >= 512) {  // Minimum for DOS stub
            uint32_t peOffset = Utils::readU32LE(header.data() + 0x3C);
            if (peOffset + 4 <= header.size()) {
                auto peBytes = reinterpret_cast<const uint8_t*>(header.data() + peOffset);
                if (peBytes[0] == 'P' && peBytes[1] == 'E' && 
                    peBytes[2] == '\0' && peBytes[3] == '\0') {
                    return BinaryFormat::PE;
                }
            }
        }
        return BinaryFormat::PE;  // Assume PE even without full validation
    }
    
    // Mach-O magic values
    uint32_t magic = Utils::readU32LE(header.data());
    switch (magic) {
        case 0xFEEDFACE:  // Mach-O 32-bit (big-endian)
        case 0xCEFAEDFE:  // Mach-O 32-bit (little-endian)
        case 0xFEEDFACF:  // Mach-O 64-bit (big-endian)
        case 0xCFFAEDFE:  // Mach-O 64-bit (little-endian)
            return BinaryFormat::MachO;
        default:
            break;
    }
    
    // Additional Mach-O fat binary magic
    if (magic == 0xBEBAFECA || magic == 0xCAFEBABE) {
        return BinaryFormat::MachO;
    }
    
    return BinaryFormat::RawBinary;
}

Architecture detectArchitecture(std::span<const std::byte> header, BinaryFormat fmt) noexcept {
    if (header.size() < 20) {
        return Architecture::Unknown;
    }
    
    switch (fmt) {
        case BinaryFormat::ELF: {
            // Architecture is in e_machine field (offset 18 for ELF)
            if (header.size() < 52) break;  // Need full ELF header
            
            uint16_t machine = Utils::readU16LE(header.data() + 18);
            
            switch (machine) {
                case 0x0003: return Architecture::X86;       // EM_386
                case 0x003E: return Architecture::X86_64;     // EM_X86_64
                case 0x0028: return Architecture::ARM;        // EM_ARM
                case 0xB7:   return Architecture::AArch64;     // EM_AARCH64
                case 0xF3:   return Architecture::RISCV;      // EM_RISCV
                case 0x0008: return Architecture::MIPS;       // EM_MIPS
                case 0x000A: return Architecture::MIPS64;     // EM_MIPS_RS3_LE
                default: break;
            }
            break;
        }
        
        case BinaryFormat::PE: {
            // Architecture is in Machine field of COFF header
            if (header.size() < 68) break;
            
            uint16_t machine = Utils::readU16LE(header.data() + 4);  // Offset varies
            
            switch (machine) {
                case 0x014C: return Architecture::X86;      // IMAGE_FILE_MACHINE_I386
                case 0x8664: return Architecture::X86_64;    // IMAGE_FILE_MACHINE_AMD64
                case 0x01C0: return Architecture::ARM;       // IMAGE_FILE_MACHINE_ARM
                case 0xAA64: return Architecture::AArch64;   // IMAGE_FILE_MACHINE_ARM64
                default: break;
            }
            break;
        }
        
        case BinaryFormat::MachO: {
            // CPU type is at offset 4 in Mach-O header
            if (header.size() < 8) break;
            
            uint32_t cpuType = Utils::readU32LE(header.data() + 4);
            
            switch (cpuType) {
                case 7:    return Architecture::X86;         // CPU_TYPE_X86
                case 0x01000007: return Architecture::X86_64;  // CPU_TYPE_X86_64
                case 12:   return Architecture::ARM;         // CPU_TYPE_ARM
                case 0x0100000C: return Architecture::AArch64; // CPU_TYPE_ARM64
                default: break;
            }
            break;
        }
        
        default:
            break;
    }
    
    return Architecture::Unknown;
}

bool detectThumbMode(std::span<const std::byte> elfHeader) noexcept {
    // Check ELF flags for Thumb mode indication
    if (elfHeader.size() < 52) return false;
    
    uint32_t flags = Utils::readU32LE(elfHeader.data() + 36);
    
    // EF_ARM_ABI_FLOAT_SOFT/HARD don't indicate thumb directly
    // But we can check processor-specific flags
    
    // For now, default to ARM mode unless we find evidence otherwise
    // In practice, this would need more sophisticated detection
    
    return false;  // Default to ARM mode
}

} // namespace BinaryUtils

// ============================================================================
// Thread Pool Implementation
// ============================================================================

class SimpleThreadPool::Impl {
public:
    explicit Impl(size_t numThreads) : stop_(false) {
        // Determine thread count
        size_t threads = numThreads;
        if (threads == 0) {
            // Use hardware concurrency minus one (for main thread)
            unsigned hwThreads = std::thread::hardware_concurrency();
            threads = (hwThreads > 1) ? (hwThreads - 1) : 1;
        }
        
        workers_.reserve(threads);
        
        for (size_t i = 0; i < threads; ++i) {
            workers_.emplace_back([this]() {
                workerLoop();
            });
        }
    }
    
    ~Impl() {
        shutdown();
    }
    
    void submit(Task task) {
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            tasks_.push(std::move(task));
        }
        condition_.notify_one();
    }
    
    void waitForAll() {
        std::unique_lock<std::mutex> lock(completeMutex_);
        completeVar_.wait(lock, [this]() {
            std::lock_guard<std::mutex> qLock(queueMutex_);
            return tasks_.empty() && activeTasks_ == 0;
        });
    }
    
    [[nodiscard]] size_t threadCount() const noexcept {
        return workers_.size();
    }
    
    [[nodiscard]] bool isRunning() const noexcept {
        return !stop_;
    }
    
private:
    void workerLoop() {
        while (true) {
            Task task;
            
            {
                std::unique_lock<std::mutex> lock(queueMutex_);
                condition_.wait(lock, [this]() {
                    return stop_ || !tasks_.empty();
                });
                
                if (stop_ && tasks_.empty()) {
                    return;
                }
                
                task = std::move(tasks_.front());
                tasks_.pop();
                ++activeTasks_;
            }
            
            // Execute task outside of lock
            task();
            
            {
                std::lock_guard<std::mutex> lock(queueMutex_);
                --activeTasks_;
            }
            
            // Notify anyone waiting for completion
            completeVar_.notify_all();
        }
    }
    
    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            stop_ = true;
        }
        
        condition_.notify_all();
        
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        
        workers_.clear();
    }
    
    std::vector<std::thread> workers_;
    std::queue<Task> tasks_;
    
    std::mutex queueMutex_;
    std::condition_variable condition_;
    
    std::mutex completeMutex_;
    std::condition_variable completeVar_;
    
    std::atomic<bool> stop_{false};
    std::atomic<size_t> activeTasks_{0};
};

// ============================================================================
// SimpleThreadPool Implementation
// ============================================================================

SimpleThreadPool::SimpleThreadPool(size_t numThreads) 
    : impl_(std::make_unique<Impl>(numThreads)) {}

SimpleThreadPool::~SimpleThreadPool() {
    shutdownGlobal();
}

void SimpleThreadPool::submit(Task task) {
    if (impl_) {
        impl_->submit(std::move(task));
    }
}

void SimpleThreadPool::waitForAll() {
    if (impl_) {
        impl_->waitForAll();
    }
}

size_t SimpleThreadPool::threadCount() const noexcept {
    return impl_ ? impl_->threadCount() : 0;
}

bool SimpleThreadPool::isRunning() const noexcept {
    return impl_ ? impl_->isRunning() : false;
}

// Static members
std::unique_ptr<SimpleThreadPool> SimpleThreadPool::globalInstance_{nullptr};
std::mutex SimpleThreadPool::globalMutex_;

void SimpleThreadPool::initializeGlobal(size_t numThreads) {
    std::lock_guard<std::mutex> lock(globalMutex_);
    
    if (!globalInstance_) {
        globalInstance_ = std::make_unique<SimpleThreadPool>(numThreads);
    }
}

void SimpleThreadPool::shutdownGlobal() {
    std::lock_guard<std::mutex> lock(globalMutex_);
    globalInstance_.reset();
}

SimpleThreadPool* SimpleThreadPool::global() noexcept {
    return globalInstance_.get();
}

} // namespace ida
