package com.mobile.idapro.native

import com.mobile.idapro.data.model.*

/**
 * Native Binary Analyzer Interface (Merged from both projects) - v3.0
 * 
 * JNI bridge to C++23 native code providing:
 * - Binary file loading and analysis (IDA Pro Mobile)
 * - ELF parsing (KTIMAZ-REV)
 * - ARM disassembly (KTIMAZ-REV)
 * - Function detection (IDA Pro Mobile)
 * - Checksum calculation (IDA Pro Mobile)
 * 
 * Security enhancements:
 * - Null-safe operations
 * - Exception handling
 * - Resource cleanup
 */
class NativeBinaryAnalyzer private constructor() {

    // Prevent direct instantiation - use companion object methods
    
    // === Core Operations ===
    
    external fun loadBinary(filePath: String): Boolean
    
    external fun getFileInfo(filePath: String): Array<String>
    
    external fun cleanup()

    // === Disassembly Operations ===
    
    external fun disassemble(startAddress: Long, count: Int): Array<DisassemblyData>
    
    // KTIMAZ-REV specific operations
    external fun disassembleSection(sectionName: String, baseAddress: Long, isThumbMode: Boolean): Array<DisassemblyData>
    
    external fun getSectionNames(): Array<String>
    
    external fun getSymbols(): Array<SymbolData>

    // === Function Detection ===
    
    external fun detectFunctions(): Array<FunctionData>

    // === Data Reading ===
    
    external fun readBytes(address: Long, size: Int): ByteArray
    
    external fun getBinaryData(): ByteArray
    
    external fun getSectionHexDump(sectionName: String, offset: Long, length: Int): ByteArray

    // === Security/Integrity ===
    
    external fun calculateChecksum(filePath: String): String

    companion object {
        @Volatile
        private var INSTANCE: NativeBinaryAnalyzer? = null
        
        @Volatile
        private var isInitialized = false
        
        private val lock = Any()
        
        /**
         * Get singleton instance with lazy initialization
         */
        fun getInstance(): NativeBinaryAnalyzer {
            return INSTANCE ?: synchronized(lock) {
                INSTANCE ?: NativeBinaryAnalyzer().also { 
                    INSTANCE = it
                    initializeNative()
                }
            }
        }
        
        // Public constructor that also initializes native library
        operator fun invoke(): NativeBinaryAnalyzer = getInstance()
        
        private fun initializeNative() {
            if (!isInitialized) {
                synchronized(lock) {
                    if (!isInitialized) {
                        try {
                            System.loadLibrary("ida_pro_native")
                            isInitialized = true
                        } catch (e: UnsatisfiedLinkError) {
                            // Library not available - will use fallback mode
                            e.printStackTrace()
                        }
                    }
                }
            }
        }
        
        /**
         * Reset the instance (for testing purposes)
         */
        fun resetInstance() {
            synchronized(lock) {
                INSTANCE?.cleanup()
                INSTANCE = null
                isInitialized = false
            }
        }
    }
}

/**
 * Data class for passing disassembly information from native code
 */
data class DisassemblyData(
    val address: Long,
    val bytes: ByteArray,
    val mnemonic: String,
    val operands: String,
    val isFunction: Boolean = false,
    val isJump: Boolean = false,
    val isBranch: Boolean = false,
    val jumpTarget: Long = 0,
    val branchTarget: Long = 0,
    val rawBytes: Long = 0,
    val byteLength: Int = 4,
    val comment: String = ""
) {
    fun toDisassemblyInstruction(): DisassemblyInstruction {
        return DisassemblyInstruction(
            address = address,
            bytes = bytes,
            mnemonic = mnemonic,
            operands = if (operands.isNotEmpty()) operands.split(", ") else emptyList(),
            isFunction = isFunction,
            isJump = isJump,
            isBranch = isBranch,
            jumpTarget = if (jumpTarget != 0L) jumpTarget else null,
            branchTarget = branchTarget,
            rawBytes = rawBytes,
            byteLength = byteLength,
            comment = comment.ifBlank { null }
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as DisassemblyData
        if (address != other.address) return false
        if (!bytes.contentEquals(other.bytes)) return false
        if (mnemonic != other.mnemonic) return false
        if (operands != other.operands) return false
        return true
    }

    override fun hashCode(): Int {
        var result = address.hashCode()
        result = 31 * result + bytes.contentHashCode()
        result = 31 * result + mnemonic.hashCode()
        result = 31 * result + operands.hashCode()
        return result
    }
}

/**
 * Data class for function information from native code
 */
data class FunctionData(
    val name: String,
    val address: Long,
    val size: Int,
    val signature: String,
    val isExported: Boolean,
    val isImported: Boolean
) {
    fun toFunction(): Function = Function(
        name = name,
        address = address,
        size = size,
        signature = signature,
        isExported = isExported,
        isImported = isImported
    )
}

/**
 * Data class for symbol information from native code (KTIMAZ-REV)
 */
data class SymbolData(
    val name: String,
    val value: Long,
    val size: Long,
    val sectionName: String,
    val type: Int = 0
) {
    fun toSymbol(): Symbol = Symbol(
        name = name,
        value = value,
        size = size,
        sectionName = sectionName,
        type = SymbolType.fromInt(type)
    )
}
