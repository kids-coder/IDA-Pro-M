/**
 * @file jni_bridge.cpp
 * @brief JNI Bridge for IDA Pro M Native Library
 * 
 * Provides Java Native Interface bindings for the BinaryAnalyzer class.
 * Thread-safe implementation with proper JNI reference management.
 * 
 * @version 3.0.0
 */

#include "ida_pro_native.h"
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <sstream>
#include <iomanip>

#if defined(__ANDROID__) || defined(ANDROID)

namespace ida {

// ============================================================================
// Global State Management
// ============================================================================

/// Global mutex for thread-safe access to analyzer instances
static std::mutex g_analyzerMutex;

/// Storage for analyzer instances (handle -> unique_ptr)
static std::unordered_map<jlong, std::unique_ptr<BinaryAnalyzer>> g_analyzers;

/// Next available handle counter
static std::atomic<jlong> g_nextHandle{1};

/// Flag indicating if JNI has been initialized
static std::atomic<bool> g_initialized{false};

/// Thread pool initialized flag
static std::atomic<bool> g_threadPoolInitialized{false};

// ============================================================================
// Helper Functions
// ============================================================================

namespace {

/// Generate new unique handle for analyzer instance
[[nodiscard]] jlong generateHandle() noexcept {
    return g_nextHandle.fetch_add(1, std::memory_order_relaxed);
}

/// Validate handle and return analyzer pointer
[[nodiscard]] BinaryAnalyzer* getAnalyzer(jlong handle) noexcept {
    std::lock_guard<std::mutex> lock(g_analyzerMutex);
    auto it = g_analyzers.find(handle);
    if (it != g_analyzers.end()) {
        return it->second.get();
    }
    return nullptr;
}

/// Safe conversion of jstring to std::string
[[nodiscard]] std::string jstringToString(JNIEnv* env, jstring jstr) {
    if (!env || !jstr) return {};
    
    const char* chars = env->GetStringUTFChars(jstr, nullptr);
    if (!chars) return {};
    
    std::string result(chars);
    env->ReleaseStringUTFChars(jstr, chars);
    return result;
}

/// Create jstring from std::string (handles null/empty)
[[nodiscard]] jstring stringToJstring(JNIEnv* env, const std::string& str) {
    if (!env) return nullptr;
    return env->NewStringUTF(str.c_str());
}

/// Convert AnalysisError to descriptive message
[[nodiscard]] std::string errorToMessage(AnalysisError err) {
    return std::string(errorToString(err));
}

/// Log message to Android logcat
void logInfo(std::string_view msg) noexcept {
    __android_log_print(ANDROID_LOG_INFO, "IDAProNative", "%.*s", 
                        static_cast<int>(msg.length()), msg.data());
}

void logError(std::string_view msg) noexcept {
    __android_log_print(ANDROID_LOG_ERROR, "IDAProNative", "%.*s",
                        static_cast<int>(msg.length()), msg.data());
}

/// Format function info as JSON
[[nodiscard]] std::string formatFunctionJson(const Function& func, int index) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"index\":" << index << ",";
    oss << "\"startAddress\":\"0x" << std::hex << func.startAddress << "\",";
    oss << "\"endAddress\":\"0x" << func.endAddress << "\",";
    oss << "\"size\":" << std::dec << func.size << ",";
    oss << "\"name\":\"" << escapeJson(func.name) << "\",";
    
    const char* typeStr = "unknown";
    switch (func.type) {
        case Function::Type::Normal:  typeStr = "normal"; break;
        case Function::Type::Thunk:   typeStr = "thunk"; break;
        case Function::Type::Import:  typeStr = "import"; break;
        case Function::Type::Export:  typeStr = "export"; break;
        case Function::Type::Stub:    typeStr = "stub"; break;
        default: break;
    }
    oss << "\"type\":\"" << typeStr << "\",";
    oss << "\"instructionCount\":" << func.instructions.size();
    oss << "}";
    return oss.str();
}

/// Format symbol info as JSON
[[nodiscard]] std::string formatSymbolJson(const SymbolEntry& sym, int index) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"index\":" << index << ",";
    oss << "\"address\":\"0x" << std::hex << sym.address << "\",";
    oss << "\"size\":" << std::dec << sym.size << ",";
    oss << "\"name\":\"" << escapeJson(sym.name) << "\",";
    
    const char* typeStr = "none";
    switch (sym.type) {
        case SymbolEntry::Type::Object:   typeStr = "object"; break;
        case SymbolEntry::Type::Function: typeStr = "function"; break;
        case SymbolEntry::Type::Section:  typeStr = "section"; break;
        case SymbolEntry::Type::File:     typeStr = "file"; break;
        case SymbolEntry::Type::Common:   typeStr = "common"; break;
        case SymbolEntry::Type::TLS:      typeStr = "tls"; break;
        default: break;
    }
    oss << "\"type\":\"" << typeStr << "\",";
    
    const char* bindStr = "local";
    switch (sym.binding) {
        case SymbolEntry::Binding::Global:    bindStr = "global"; break;
        case SymbolEntry::Binding::Weak:      bindStr = "weak"; break;
        case SymbolEntry::Binding::GNUUnique: bindStr = "gnu_unique"; break;
        default: break;
    }
    oss << "\"binding\":\"" << bindStr << "\",";
    oss << "\"isDefined\":" << (sym.isDefined() ? "true" : "false");
    oss << "}";
    return oss.str();
}

/// Format instruction as JSON
[[nodiscard]] std::string formatInstructionJson(const Instruction& insn) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"address\":\"0x" << std::hex << insn.address << "\",";
    oss << "\"offset\":" << std::dec << insn.offset << ",";
    oss << "\"size\":" << insn.size << ",";
    oss << "\"mnemonic\":\"" << escapeJson(insn.mnemonic) << "\",";
    oss << "\"operands\":\"" << escapeJson(insn.operands) << "\",";
    oss << "\"bytes\":\"" << insn.bytes << "\",";
    oss << "\"isBranch\":" << (insn.isBranch ? "true" : "false") << ",";
    oss << "\"isCall\":" << (insn.isCall ? "true" : "false") << ",";
    oss << "\"isReturn\":" << (insn.isReturn ? "true" : "false");
    
    if (insn.branchTarget.has_value()) {
        oss << ",\"branchTarget\":\"0x" << std::hex << *insn.branchTarget << "\"";
    }
    if (insn.referenceName.has_value()) {
        oss << ",\"referenceName\":\"" << escapeJson(*insn.referenceName) << "\"";
    }
    oss << "}";
    return oss.str();
}

/// Format section header as JSON
[[nodiscard]] std::string formatSectionJson(const SectionHeader& sec, int index) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"index\":" << index << ",";
    oss << "\"name\":\"" << escapeJson(sec.name) << "\",";
    oss << "\"type\":\"0x" << std::hex << sec.type << "\",";
    oss << "\"flags\":\"0x" << sec.flags << "\",";
    oss << "\"virtualAddr\":\"0x" << sec.virtualAddr << "\",";
    oss << "\"fileOffset\":" << std::dec << sec.fileOffset << ",";
    oss << "\"size\":" << sec.size << ",";
    oss << "\"isExecutable\":" << (sec.isExecutable() ? "true" : "false") << ",";
    oss << "\"isWritable\":" << (sec.isWritable() ? "true" : "false") << ",";
    oss << "\"isAllocated\":" << (sec.isAllocated() ? "true" : "false");
    oss << "}";
    return oss.str();
}

/// Escape special characters for JSON strings
[[nodiscard]] std::string escapeJson(std::string_view str) {
    std::string result;
    result.reserve(str.length());
    for (char c : str) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    std::ostringstream oss;
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') 
                        << static_cast<int>(static_cast<unsigned char>(c));
                    result += oss.str();
                } else {
                    result += c;
                }
                break;
        }
    }
    return result;
}

} // anonymous namespace

// ============================================================================
// JNI Method Implementations
// ============================================================================

extern "C" {

/**
 * JNI_OnLoad - Called when library is loaded
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)reserved;
    
    if (!vm) {
        logError("JNI_OnLoad: Null JavaVM pointer");
        return JNI_ERR;
    }
    
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        logError("JNI_OnLoad: Failed to get JNIEnv");
        return JNI_ERR;
    }
    
    // Initialize global thread pool
    if (!g_threadPoolInitialized.load(std::memory_order_acquire)) {
        SimpleThreadPool::initializeGlobal();
        g_threadPoolInitialized.store(true, std::memory_order_release);
        logInfo("Thread pool initialized");
    }
    
    // Register native methods
    if (jni::registerNatives(env) < 0) {
        logError("JNI_OnLoad: Failed to register natives");
        return JNI_ERR;
    }
    
    g_initialized.store(true, std::memory_order_release);
    logInfo("IDA Pro Native library loaded successfully (v3.0.0)");
    
    return JNI_VERSION_1_6;
}

/**
 * JNI_OnUnload - Called when library is unloaded
 */
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved) {
    (void)reserved;
    
    logInfo("IDA Pro Native library unloading...");
    
    // Cleanup all analyzer instances
    {
        std::lock_guard<std::mutex> lock(g_analyzerMutex);
        g_analyzers.clear();
    }
    
    // Shutdown thread pool
    if (g_threadPoolInitialized.load(std::memory_order_acquire)) {
        SimpleThreadPool::shutdownGlobal();
        g_threadPoolInitialized.store(false, std::memory_order_release);
    }
    
    g_initialized.store(false, std::memory_order_release);
    logInfo("IDA Pro Native library unloaded");
}

// ============================================================================
// Native Method Implementations
// ============================================================================

/**
 * Create a new BinaryAnalyzer instance
 * Returns: Handle to the instance (jlong)
 */
JNIEXPORT jlong JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeCreate(
    JNIEnv* env, 
    jclass clazz
) {
    (void)clazz;
    
    try {
        auto analyzer = std::make_unique<BinaryAnalyzer>();
        if (!analyzer) {
            logError("Failed to create BinaryAnalyzer instance");
            return 0;
        }
        
        jlong handle = generateHandle();
        
        {
            std::lock_guard<std::mutex> lock(g_analyzerMutex);
            g_analyzers[handle] = std::move(analyzer);
        }
        
        logInfo("Created analyzer instance: " + std::to_string(handle));
        return handle;
        
    } catch (const std::exception& e) {
        logError(std::string("Exception creating analyzer: ") + e.what());
        return 0;
    }
}

/**
 * Destroy a BinaryAnalyzer instance
 */
JNIEXPORT void JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeDestroy(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)env;
    (void)clazz;
    
    if (handle == 0) return;
    
    std::lock_guard<std::mutex> lock(g_analyzerMutex);
    auto it = g_analyzers.find(handle);
    if (it != g_analyzers.end()) {
        g_analyzers.erase(it);
        logInfo("Destroyed analyzer instance: " + std::to_string(handle));
    }
}

/**
 * Load a binary file for analysis
 * Returns: Error message on failure, null on success
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeLoadFile(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jstring path
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer) {
        return stringToJstring(env, "Invalid analyzer handle");
    }
    
    if (!path) {
        return stringToJstring(env, "Null path provided");
    }
    
    std::string filePath = jstringToString(env, path);
    if (filePath.empty()) {
        return stringToJstring(env, "Empty path provided");
    }
    
    logInfo("Loading file: " + filePath);
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    auto result = analyzer->loadFile(filePath);
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    
    if (result) {
        logInfo("File loaded successfully in " + std::to_string(durationMs) + "ms");
        return nullptr;  // Success
    }
    
    std::string errorMsg = errorToMessage(result.error());
    logError("Failed to load file: " + errorMsg);
    return stringToJstring(env, errorMsg);
}

/**
 * Get binary format string
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetFormat(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer) {
        return stringToJstring(env, "Unknown");
    }
    
    auto fmt = analyzer->getFormat();
    return stringToJstring(env, std::string(formatToString(fmt)));
}

/**
 * Get architecture string
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetArchitecture(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer) {
        return stringToJstring(env, "Unknown");
    }
    
    auto arch = analyzer->getArchitecture();
    return stringToJstring(env, std::string(archToString(arch)));
}

/**
 * Get entry point address
 */
JNIEXPORT jlong JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetEntryPoint(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)env;
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer) {
        return 0;
    }
    
    return static_cast<jlong>(analyzer->getEntryPoint());
}

/**
 * Analyze the loaded binary
 * Returns: Error message on failure, null on success
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeAnalyze(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer) {
        return stringToJstring(env, "Invalid analyzer handle");
    }
    
    if (!analyzer->isLoaded()) {
        return stringToJstring(env, "No file loaded");
    }
    
    logInfo("Starting analysis...");
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    auto result = analyzer->analyze();
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    
    if (result) {
        logInfo("Analysis completed in " + std::to_string(durationMs) + "ms");
        return nullptr;
    }
    
    std::string errorMsg = errorToMessage(result.error());
    logError("Analysis failed: " + errorMsg);
    return stringToJstring(env, errorMsg);
}

/**
 * Check if a file is loaded
 */
JNIEXPORT jboolean JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeIsLoaded(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)env;
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    return analyzer && analyzer->isLoaded() ? JNI_TRUE : JNI_FALSE;
}

/**
 * Get number of detected functions
 */
JNIEXPORT jint JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetFunctionCount(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)env;
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer || !analyzer->isAnalyzed()) {
        return 0;
    }
    
    return static_cast<jint>(analyzer->getFunctions().size());
}

/**
 * Get function information as JSON
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetFunctionInfo(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jint index
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer || !analyzer->isAnalyzed()) {
        return stringToJstring(env, "{\"error\":\"Not analyzed\"}");
    }
    
    auto functions = analyzer->getFunctions();
    if (index < 0 || index >= static_cast<jint>(functions.size())) {
        return stringToJstring(env, "{\"error\":\"Index out of range\"}");
    }
    
    std::string json = formatFunctionJson(functions[index], index);
    return stringToJstring(env, json);
}

/**
 * Get all functions as JSON array
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetAllFunctions(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer || !analyzer->isAnalyzed()) {
        return stringToJstring(env, "[]");
    }
    
    auto functions = analyzer->getFunctions();
    std::ostringstream oss;
    oss << "[";
    
    for (size_t i = 0; i < functions.size(); ++i) {
        if (i > 0) oss << ",";
        oss << formatFunctionJson(functions[i], static_cast<int>(i));
    }
    
    oss << "]";
    return stringToJstring(env, oss.str());
}

/**
 * Get number of symbols
 */
JNIEXPORT jint JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetSymbolCount(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)env;
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer || !analyzer->isAnalyzed()) {
        return 0;
    }
    
    return static_cast<jint>(analyzer->getSymbols().size());
}

/**
 * Get symbol information as JSON
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetSymbolInfo(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jint index
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer || !analyzer->isAnalyzed()) {
        return stringToJstring(env, "{\"error\":\"Not analyzed\"}");
    }
    
    auto symbols = analyzer->getSymbols();
    if (index < 0 || index >= static_cast<jint>(symbols.size())) {
        return stringToJstring(env, "{\"error\":\"Index out of range\"}");
    }
    
    std::string json = formatSymbolJson(symbols[index], index);
    return stringToJstring(env, json);
}

/**
 * Get all symbols as JSON array
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetAllSymbols(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer || !analyzer->isAnalyzed()) {
        return stringToJstring(env, "[]");
    }
    
    auto symbols = analyzer->getSymbols();
    std::ostringstream oss;
    oss << "[";
    
    for (size_t i = 0; i < symbols.size(); ++i) {
        if (i > 0) oss << ",";
        oss << formatSymbolJson(symbols[i], static_cast<int>(i));
    }
    
    oss << "]";
    return stringToJstring(env, oss.str());
}

/**
 * Disassemble address range
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeDisassemble(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jlong startAddress,
    jlong size
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer || !analyzer->isAnalyzed()) {
        return stringToJstring(env, "{\"error\":\"Not analyzed\"}");
    }
    
    if (size <= 0 || size > 1024 * 1024) {  // Limit to 1MB max
        return stringToJstring(env, "{\"error\":\"Invalid size\"}");
    }
    
    auto result = analyzer->disassemble(
        static_cast<uint64_t>(startAddress),
        static_cast<uint64_t>(size)
    );
    
    if (!result) {
        return stringToJstring(env, 
            "{\"error\":\"" + errorToMessage(result.error()) + "\"}");
    }
    
    const auto& instructions = *result;
    std::ostringstream oss;
    oss << "[";
    
    for (size_t i = 0; i < instructions.size(); ++i) {
        if (i > 0) oss << ",";
        oss << formatInstructionJson(instructions[i]);
    }
    
    oss << "]";
    return stringToJstring(env, oss.str());
}

/**
 * Get sections as JSON array
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetSections(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer || !analyzer->isAnalyzed()) {
        return stringToJstring(env, "[]");
    }
    
    auto sections = analyzer->getSections();
    std::ostringstream oss;
    oss << "[";
    
    for (size_t i = 0; i < sections.size(); ++i) {
        if (i > 0) oss << ",";
        oss << formatSectionJson(sections[i], static_cast<int>(i));
    }
    
    oss << "]";
    return stringToJstring(env, oss.str());
}

/**
 * Get file hash (SHA-256) as hex string
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetFileHash(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer || !analyzer->isLoaded()) {
        return stringToJstring(env, "");
    }
    
    auto hash = analyzer->getFileHash();
    
    // Convert to hex string
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : hash) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    
    return stringToJstring(env, oss.str());
}

/**
 * Get analysis statistics as JSON
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetStatistics(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer) {
        return stringToJstring(env, "{\"error\":\"Invalid handle\"}");
    }
    
    auto stats = analyzer->getStatistics();
    
    std::ostringstream oss;
    oss << "{";
    oss << "\"totalFunctions\":" << stats.totalFunctions << ",";
    oss << "\"totalInstructions\":" << stats.totalInstructions << ",";
    oss << "\"totalSymbols\":" << stats.totalSymbols << ",";
    oss << "\"codeSections\":" << stats.codeSections << ",";
    oss << "\"codeSize\":" << stats.codeSize << ",";
    oss << std::fixed << std::setprecision(2);
    oss << "\"analysisTimeMs\":" << stats.analysisTimeMs;
    oss << "}";
    
    return stringToJstring(env, oss.str());
}

/**
 * Close and cleanup analyzer
 */
JNIEXPORT void JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeClose(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)env;
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (analyzer) {
        analyzer->close();
        logInfo("Closed analyzer: " + std::to_string(handle));
    }
}

/**
 * Find symbol by address
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeFindSymbolByAddress(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jlong address
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer || !analyzer->isAnalyzed()) {
        return stringToJstring(env, "");
    }
    
    std::string name = analyzer->getSymbolName(static_cast<uint64_t>(address));
    return stringToJstring(env, name);
}

/**
 * Disassemble function by address
 */
JNIEXPORT jstring JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeDisassembleFunctionAt(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jlong address
) {
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer || !analyzer->isAnalyzed()) {
        return stringToJstring(env, "{\"error\":\"Not analyzed\"}");
    }
    
    const Function* func = analyzer->findFunction(static_cast<uint64_t>(address));
    if (!func) {
        return stringToJstring(env, "{\"error\":\"Function not found at address\"}");
    }
    
    auto result = analyzer->disassembleFunction(*func);
    if (!result) {
        return stringToJstring(env, 
            "{\"error\":\"" + errorToMessage(result.error()) + "\"}");
    }
    
    const auto& instructions = *result;
    std::ostringstream oss;
    oss << "[";
    
    for (size_t i = 0; i < instructions.size(); ++i) {
        if (i > 0) oss << ",";
        oss << formatInstructionJson(instructions[i]);
    }
    
    oss << "]";
    return stringToJstring(env, oss.str());
}

/**
 * Get image base address
 */
JNIEXPORT jlong JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetImageBase(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)env;
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer) {
        return 0;
    }
    
    return static_cast<jlong>(analyzer->getImageBase());
}

/**
 * Get image size
 */
JNIEXPORT jlong JNICALL Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetImageSize(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    (void)env;
    (void)clazz;
    
    auto* analyzer = getAnalyzer(handle);
    if (!analyzer) {
        return 0;
    }
    
    return static_cast<jlong>(analyzer->getImageSize());
}

} // extern "C"

// ============================================================================
// JNI Registration
// ============================================================================

namespace jni {

/// JNINativeMethod array for registration
static JNINativeMethod nativeMethods[] = {
    {"nativeCreate", "()J", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeCreate)},
    {"nativeDestroy", "(J)V", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeDestroy)},
    {"nativeLoadFile", "(JLjava/lang/String;)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeLoadFile)},
    {"nativeGetFormat", "(J)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetFormat)},
    {"nativeGetArchitecture", "(J)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetArchitecture)},
    {"nativeGetEntryPoint", "()J", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetEntryPoint)},
    {"nativeAnalyze", "(J)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeAnalyze)},
    {"nativeIsLoaded", "(J)Z", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeIsLoaded)},
    {"nativeGetFunctionCount", "(J)I", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetFunctionCount)},
    {"nativeGetFunctionInfo", "(JI)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetFunctionInfo)},
    {"nativeGetAllFunctions", "(J)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetAllFunctions)},
    {"nativeGetSymbolCount", "(J)I", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetSymbolCount)},
    {"nativeGetSymbolInfo", "(JI)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetSymbolInfo)},
    {"nativeGetAllSymbols", "(J)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetAllSymbols)},
    {"nativeDisassemble", "(JJJ)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeDisassemble)},
    {"nativeGetSections", "(J)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetSections)},
    {"nativeGetFileHash", "(J)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetFileHash)},
    {"nativeGetStatistics", "(J)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetStatistics)},
    {"nativeClose", "(J)V", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeClose)},
    {"nativeFindSymbolByAddress", "(JJ)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeFindSymbolByAddress)},
    {"nativeDisassembleFunctionAt", "(JJ)Ljava/lang/String;", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeDisassembleFunctionAt)},
    {"nativeGetImageBase", "()J", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetImageBase)},
    {"nativeGetImageSize", "()J", reinterpret_cast<void*>(Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetImageSize)}
};

[[nodiscard]] jint registerNatives(JNIEnv* env) {
    if (!env) {
        return -1;
    }
    
    jclass clazz = env->FindClass(NATIVE_ANALYZER_CLASS.data());
    if (!clazz) {
        logError("Failed to find class: " + std::string(NATIVE_ANALYZER_CLASS));
        return -1;
    }
    
    jint result = env->RegisterNatives(clazz, nativeMethods, 
                                        sizeof(nativeMethods) / sizeof(nativeMethods[0]));
    
    if (result < 0) {
        logError("Failed to register native methods");
    } else {
        logInfo("Registered " + std::to_string(sizeof(nativeMethods) / sizeof(nativeMethods[0])) + 
                " native methods");
    }
    
    env->DeleteLocalRef(clazz);
    return result;
}

// Static implementations of JNI interface functions

jlong createAnalyzer() {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeCreate(nullptr, nullptr);
}

void destroyAnalyzer(jlong handle) {
    Java_com_idapro_native_NativeBinaryAnalyzer_nativeDestroy(nullptr, nullptr, handle);
}

jstring jniLoadFile(jlong handle, JNIEnv* env, jstring path) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeLoadFile(env, nullptr, handle, path);
}

jstring jniGetFormat(jlong handle, JNIEnv* env) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetFormat(env, nullptr, handle);
}

jstring jniGetArchitecture(jlong handle, JNIEnv* env) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetArchitecture(env, nullptr, handle);
}

jlong jniGetEntryPoint(jlong handle) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetEntryPoint(nullptr, nullptr, handle);
}

jint jniGetFunctionCount(jlong handle) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetFunctionCount(nullptr, nullptr, handle);
}

jstring jniGetFunctionInfo(jlong handle, JNIEnv* env, jint index) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetFunctionInfo(env, nullptr, handle, index);
}

jint jniGetSymbolCount(jlong handle) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetSymbolCount(nullptr, nullptr, handle);
}

jstring jniGetSymbolInfo(jlong handle, JNIEnv* env, jint index) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetSymbolInfo(env, nullptr, handle, index);
}

jstring jniDisassemble(jlong handle, JNIEnv* env, jlong startAddr, jlong size) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeDisassemble(env, nullptr, handle, startAddr, size);
}

jstring jniGetSections(jlong handle, JNIEnv* env) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetSections(env, nullptr, handle);
}

jstring jniGetFileHash(jlong handle, JNIEnv* env) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetFileHash(env, nullptr, handle);
}

jstring jniGetStatistics(jlong handle, JNIEnv* env) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeGetStatistics(env, nullptr, handle);
}

jboolean jniAnalyze(jlong handle, JNIEnv* env) {
    jstring err = Java_com_idapro_native_NativeBinaryAnalyzer_nativeAnalyze(env, nullptr, handle);
    return err == nullptr ? JNI_TRUE : JNI_FALSE;
}

jboolean jniIsLoaded(jlong handle) {
    return Java_com_idapro_native_NativeBinaryAnalyzer_nativeIsLoaded(nullptr, nullptr, handle);
}

void jniClose(jlong handle) {
    Java_com_idapro_native_NativeBinaryAnalyzer_nativeClose(nullptr, nullptr, handle);
}

} // namespace jni

#endif // __ANDROID__ || ANDROID

} // namespace ida
