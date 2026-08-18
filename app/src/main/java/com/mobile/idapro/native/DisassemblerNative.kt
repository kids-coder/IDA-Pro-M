package com.mobile.idapro.native

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * IDA Pro M - Native Disassembly Engine Bridge
 * 
 * Provides Kotlin/Java interface to the C++ native disassembly engine.
 * Handles JNI calls, memory management, and data conversion.
 */

private const val TAG = "DisassemblerNative"

/**
 * Native engine handle (opaque pointer from C++).
 */
class DisassemblerEngineHandle(private val nativePtr: Long) {
    internal fun getNativePointer(): Long = nativePtr
    
    /**
     * Release native resources.
     */
    external fun release()
}

/**
 * Main interface to the native disassembly engine.
 */
@Singleton
class DisassemblerNative @Inject constructor() {
    
    // Handle to native engine instance
    private var engineHandle: DisassemblerEngineHandle? = null
    
    // Track if engine is initialized
    @Volatile
    private var isInitialized = false
    
    companion object {
        init {
            try {
                System.loadLibrary("idapro_engine")
                Log.i(TAG, "Native disassembly engine loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native library: ${e.message}")
            }
        }
    }
    
    /**
     * Initialize the native disassembly engine.
     * Must be called before any other operations.
     */
    suspend fun initialize(): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            if (isInitialized && engineHandle != null) {
                return@withContext Result.success(Unit)
            }
            
            val ptr = nativeCreateEngine()
            if (ptr == 0L) {
                return@withContext Result.failure(RuntimeException("Failed to create native engine"))
            }
            
            engineHandle = DisassemblerEngineHandle(ptr)
            isInitialized = true
            
            Log.i(TAG, "Native engine initialized successfully (handle=$ptr)")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Error initializing native engine", e)
            Result.failure(e)
        }
    }
    
    /**
     * Load a binary file for analysis.
     *
     * @param filePath Absolute path to the binary file
     * @return Success with file info, or Failure with error message
     */
    suspend fun loadFile(filePath: String): Result<NativeBinaryInfo> = withContext(Dispatchers.IO) {
        ensureInitialized()
        
        val handle = engineHandle ?: return@withContext Result.failure(
            IllegalStateException("Engine not initialized")
        )
        
        try {
            val result = nativeLoadFile(handle.getNativePointer(), filePath)
            if (!result.success) {
                return@withContext Result.failure(
                    RuntimeException(result.errorMessage ?: "Unknown error loading file")
                )
            }
            
            Log.i(TAG, "File loaded successfully: $filePath")
            Result.success(result.binaryInfo!!)
        } catch (e: Exception) {
            Log.e(TAG, "Error loading file", e)
            Result.failure(e)
        }
    }
    
    /**
     * Load binary data from memory buffer.
     *
     * @param data Raw binary data
     * @param name Optional name for the buffer
     * @return Success with file info, or Failure with error message
     */
    suspend fun loadBuffer(data: ByteArray, name: String = "buffer"): Result<NativeBinaryInfo> = withContext(Dispatchers.IO) {
        ensureInitialized()
        
        val handle = engineHandle ?: return@withContext Result.failure(
            IllegalStateException("Engine not initialized")
        )
        
        try {
            val result = nativeLoadBuffer(handle.getNativePointer(), data, name)
            if (!result.success) {
                return@withContext Result.failure(
                    RuntimeException(result.errorMessage ?: "Unknown error loading buffer")
                )
            }
            
            Log.i(TAG, "Buffer loaded successfully (${data.size} bytes)")
            Result.success(result.binaryInfo!!)
        } catch (e: Exception) {
            Log.e(TAG, "Error loading buffer", e)
            Result.failure(e)
        }
    }
    
    /**
     * Perform full analysis on loaded binary.
     *
     * @param options Analysis options
     * @return Complete analysis result
     */
    suspend fun analyze(options: AnalysisOptions = AnalysisOptions()): Result<NativeAnalysisResult> = withContext(Dispatchers.Default) {
        ensureInitialized()
        
        val handle = engineHandle ?: return@withContext Result.failure(
            IllegalStateException("Engine not initialized")
        )
        
        try {
            Log.i(TAG, "Starting analysis with options: $options")
            
            val result = nativeAnalyze(
                handle.getNativePointer(),
                autoAnalyze = options.autoAnalyze,
                deepScan = options.deepScan,
                buildCFG = options.buildCFG,
                extractStrings = options.extractStrings,
                resolveXrefs = options.resolveXrefs,
                identifyFunctions = options.identifyFunctions,
                detectPatterns = options.detectPatterns,
                followThunks = options.followThunkFunctions,
                analyzeSwitches = options.analyzeSwitchStatements,
                recoverBoundaries = options.recoverFunctionBoundaries,
                minStringLength = options.minStringLength,
                maxStringLength = options.maxStringLength
            )
            
            if (!result.success) {
                return@withContext Result.failure(
                    RuntimeException(result.errorMessage ?: "Analysis failed")
                )
            }
            
            Log.i(TAG, "Analysis completed in ${result.analysisTimeMs}ms")
            Log.d(TAG, "  Instructions: ${result.totalInstructions}")
            Log.d(TAG, "  Functions: ${result.totalFunctions}")
            Log.d(TAG, "  Strings: ${result.totalStrings}")
            Log.d(TAG, "  XRefs: ${result.totalXrefs}")
            
            Result.success(result)
        } catch (e: Exception) {
            Log.e(TAG, "Error during analysis", e)
            Result.failure(e)
        }
    }
    
    /**
     * Get disassembled instructions in address range.
     *
     * @param startAddress Start of range
     * @param endAddress End of range
     * @return List of disassembled instructions
     */
    suspend fun getDisassemblyRange(startAddress: Long, endAddress: Long): Result<List<NativeInstruction>> = withContext(Dispatchers.Default) {
        ensureInitialized()
        
        val handle = engineHandle ?: return@withContext Result.failure(
            IllegalStateException("Engine not initialized")
        )
        
        try {
            val instructions = nativeDisassembleRange(handle.getNativePointer(), startAddress, endAddress)
            Result.success(instructions)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting disassembly range", e)
            Result.failure(e)
        }
    }
    
    /**
     * Get instruction at specific address.
     */
    suspend fun getInstructionAt(address: Long): Result<NativeInstruction?> = withContext(Dispatchers.Default) {
        ensureInitialized()
        
        val handle = engineHandle ?: return@withContext Result.failure(
            IllegalStateException("Engine not initialized")
        )
        
        try {
            val instruction = nativeGetInstructionAt(handle.getNativePointer(), address)
            Result.success(instruction)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting instruction at address", e)
            Result.failure(e)
        }
    }
    
    /**
     * Get hex dump of memory region.
     *
     * @param offset Starting offset
     * @param length Number of bytes
     * @return Formatted hex dump string
     */
    suspend fun getHexDump(offset: Long, length: Int): Result<String> = withContext(Dispatchers.Default) {
        ensureInitialized()
        
        val handle = engineHandle ?: return@withContext Result.failure(
            IllegalStateException("Engine not initialized")
        )
        
        try {
            val hexDump = nativeGetHexDump(handle.getNativePointer(), offset, length)
            Result.success(hexDump)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting hex dump", e)
            Result.failure(e)
        }
    }
    
    /**
     * Get extracted strings.
     *
     * @param filter Optional filter string
     * @return List of extracted strings
     */
    suspend fun getStrings(filter: String? = null): Result<List<NativeStringEntry>> = withContext(Dispatchers.Default) {
        ensureInitialized()
        
        val handle = engineHandle ?: return@withContext Result.failure(
            IllegalStateException("Engine not initialized")
        )
        
        try {
            val strings = nativeGetStrings(handle.getNativePointer(), filter ?: "")
            Result.success(strings)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting strings", e)
            Result.failure(e)
        }
    }
    
    /**
     * Get identified functions.
     *
     * @return List of functions
     */
    suspend fun getFunctions(): Result<List<NativeFunction>> = withContext(Dispatchers.Default) {
        ensureInitialized()
        
        val handle = engineHandle ?: return@withContext Result.failure(
            IllegalStateException("Engine not initialized")
        )
        
        try {
            val functions = nativeGetFunctions(handle.getNativePointer())
            Result.success(functions)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting functions", e)
            Result.failure(e)
        }
    }
    
    /**
     * Get binary information.
     */
    suspend fun getBinaryInfo(): Result<NativeBinaryInfo?> = withContext(Dispatchers.Default) {
        ensureInitialized()
        
        val handle = engineHandle ?: return@withContext Result.failure(
            IllegalStateException("Engine not initialized")
        )
        
        try {
            val info = nativeGetBinaryInfo(handle.getNativePointer())
            Result.success(info)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting binary info", e)
            Result.failure(e)
        }
    }
    
    /**
     * Unload current file and free resources.
     */
    suspend fun unload(): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            engineHandle?.release()
            engineHandle = null
            isInitialized = false
            Log.i(TAG, "Engine unloaded and resources released")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Error unloading engine", e)
            Result.failure(e)
        }
    }
    
    /**
     * Get engine version string.
     */
    fun getVersion(): String {
        return try { nativeGetVersion() } catch (e: Exception) { "unknown" }
    }
    
    /**
     * Get list of supported architectures.
     */
    fun getSupportedArchitectures(): List<String> {
        return try {
            nativeGetSupportedArchitectures().split(",")
        } catch (e: Exception) {
            emptyList()
        }
    }
    
    private suspend fun ensureInitialized() {
        if (!isInitialized) {
            initialize().getOrThrow()
        }
    }
    
    protected fun finalize() {
        try {
            engineHandle?.release()
        } catch (e: Exception) {
            Log.w(TAG, "Error during finalization", e)
        }
    }

    // ========================================================================
    // Native method declarations
    // ========================================================================

    private external fun nativeCreateEngine(): Long
    private external fun nativeDestroyEngine(nativePtr: Long)
    private external fun nativeLoadFile(nativePtr: Long, filePath: String): NativeResult
    private external fun nativeLoadBuffer(nativePtr: Long, data: ByteArray, name: String): NativeResult
    private external fun nativeAnalyze(
        nativePtr: Long,
        autoAnalyze: Boolean,
        deepScan: Boolean,
        buildCFG: Boolean,
        extractStrings: Boolean,
        resolveXrefs: Boolean,
        identifyFunctions: Boolean,
        detectPatterns: Boolean,
        followThunks: Boolean,
        analyzeSwitches: Boolean,
        recoverBoundaries: Boolean,
        minStringLength: Int,
        maxStringLength: Int
    ): NativeAnalysisResult
    private external fun nativeGetInstructionAt(nativePtr: Long, address: Long): NativeInstruction?
    private external fun nativeDisassembleRange(nativePtr: Long, startAddr: Long, endAddr: Long): List<NativeInstruction>
    private external fun nativeGetHexDump(nativePtr: Long, offset: Long, length: Int): String
    private external fun nativeGetStrings(nativePtr: Long, filter: String): List<NativeStringEntry>
    private external fun nativeGetFunctions(nativePtr: Long): List<NativeFunction>
    private external fun nativeGetBinaryInfo(nativePtr: Long): NativeBinaryInfo?
    private external fun nativeUnload(nativePtr: Long)
    private external fun nativeGetVersion(): String
    private external fun nativeGetSupportedArchitectures(): String
}

// ============================================================================
// Data classes for native results
// ============================================================================

/**
 * Generic result wrapper from native operations.
 */
data class NativeResult(
    val success: Boolean,
    val errorMessage: String? = null,
    val binaryInfo: NativeBinaryInfo? = null
)

/**
 * Binary information from native parser.
 */
data class NativeBinaryInfo(
    val format: String,
    val architecture: String,
    val is64Bit: Boolean,
    val isLittleEndian: Boolean,
    val entryPoint: Long,
    val imageBase: Long,
    val fileSize: Long,
    val fileName: String,
    val md5Hash: String,
    val sha256Hash: String
)

/**
 * Complete analysis result from native engine.
 */
data class NativeAnalysisResult(
    val success: Boolean,
    val errorMessage: String? = null,
    val totalInstructions: Long = 0,
    val totalFunctions: Long = 0,
    val totalStrings: Long = 0,
    val totalXrefs: Long = 0,
    val analysisTimeMs: Long = 0,
    val currentPhase: String = "",
    val progressPercent: Int = 0,
    val warnings: List<String> = emptyList(),
    val errors: List<String> = emptyList()
)

/**
 * Disassembled instruction representation.
 */
data class NativeInstruction(
    val address: Long,
    val rawBytes: ByteArray,
    val mnemonic: String,
    val operands: String,
    val size: Int,
    val isBranch: Boolean,
    val isCall: Boolean,
    val isReturn: Boolean,
    val branchTarget: Long?,
    val comment: String?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as NativeInstruction
        if (address != other.address) return false
        if (!rawBytes.contentEquals(other.rawBytes)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = address.hashCode()
        result = 31 * result + rawBytes.contentHashCode()
        return result
    }
}

/**
 * Extracted string entry.
 */
data class NativeStringEntry(
    val address: Long,
    val value: String,
    val encoding: String,
    val length: Int,
    val byteLength: Int,
    val type: String
)

/**
 * Identified function.
 */
data class NativeFunction(
    val id: Long,
    val startAddress: Long,
    val endAddress: Long,
    val size: Long,
    val name: String,
    val demangledName: String?,
    val type: String,
    val instructionCount: Int,
    val cyclomaticComplexity: Int
)

/**
 * Analysis configuration options.
 */
data class AnalysisOptions(
    val autoAnalyze: Boolean = true,
    val deepScan: Boolean = false,
    val buildCFG: Boolean = true,
    val extractStrings: Boolean = true,
    val resolveXrefs: Boolean = true,
    val identifyFunctions: Boolean = true,
    val detectPatterns: Boolean = true,
    val followThunkFunctions: Boolean = true,
    val analyzeSwitchStatements: Boolean = true,
    val recoverFunctionBoundaries: Boolean = true,
    val minStringLength: Int = 4,
    val maxStringLength: Int = 4096
)
