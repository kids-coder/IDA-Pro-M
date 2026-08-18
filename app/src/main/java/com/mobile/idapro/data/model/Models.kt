package com.mobile.idapro.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey
import kotlinx.serialization.Serializable

/**
 * IDA Pro M - Data Models
 * 
 * Room entities for local database storage of analysis results,
 * file metadata, and user preferences.
 */

// ============================================================================
// File/Project Models
// ============================================================================

/**
 * Represents a loaded binary file for analysis.
 */
@Entity(tableName = "loaded_files")
@Serializable
data class LoadedFile(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val fileName: String,
    val filePath: String,
    val fileSize: Long,
    val md5Hash: String,
    val sha256Hash: String,
    val format: BinaryFormat = BinaryFormat.UNKNOWN,
    val architecture: Architecture = Architecture.UNKNOWN,
    val is64Bit: Boolean = false,
    val isLittleEndian: Boolean = true,
    val entryPoint: Long = 0L,
    val imageBase: Long = 0L,
    val loadTimestamp: Long = System.currentTimeMillis(),
    val lastAccessed: Long = System.currentTimeMillis(),
    var analysisStatus: AnalysisStatus = AnalysisStatus.NOT_STARTED,
    var analysisProgress: Int = 0,
    var analysisId: Long? = null
) {
    /**
     * Get human-readable format name.
     */
    fun getFormatDisplayName(): String {
        return when (format) {
            BinaryFormat.ELF -> "ELF Binary"
            BinaryFormat.PE -> "PE Executable"
            BinaryFormat.MACH_O -> "Mach-O Binary"
            BinaryFormat.DEX -> "DEX (Android)"
            BinaryFormat.RAW -> "Raw Binary"
            BinaryFormat.COFF -> "COFF"
            BinaryFormat.OLE -> "OLE/COM"
        }
    }
    
    /**
     * Get human-readable architecture name.
     */
    fun getArchDisplayName(): String {
        return when (architecture) {
            Architecture.ARM32 -> "ARM 32-bit"
            Architecture.ARM64 -> "ARM 64-bit (AArch64)"
            Architecture.THUMB -> "Thumb/Thumb-2"
            Architecture.X86_32 -> "x86 32-bit"
            Architecture.X86_64 -> "x86-64"
            Architecture.MIPS -> "MIPS"
            Architecture.MIPS64 -> "MIPS64"
            Architecture.UNKNOWN -> "Unknown"
        }
    }
    
    /**
     * Get formatted file size string.
     */
    fun getFormattedSize(): String {
        val kb = fileSize / 1024.0
        val mb = kb / 1024.0
        val gb = mb / 1024.0
        
        return when {
            gb >= 1.0 -> String.format("%.2f GB", gb)
            mb >= 1.0 -> String.format("%.2f MB", mb)
            kb >= 1.0 -> String.format("%.1f KB", kb)
            else -> "$fileSize bytes"
        }
    }
}

/**
 * Supported binary formats.
 */
enum class BinaryFormat {
    UNKNOWN,
    ELF,
    PE,
    MACH_O,
    DEX,
    RAW,
    COFF,
    OLE
}

/**
 * Supported CPU architectures.
 */
enum class Architecture {
    UNKNOWN,
    ARM32,
    ARM64,
    THUMB,
    X86_32,
    X86_64,
    MIPS,
    MIPS64
}

/**
 * Analysis status enumeration.
 */
enum class AnalysisStatus {
    NOT_STARTED,
    IN_PROGRESS,
    COMPLETED,
    FAILED,
    CANCELLED,
    PARTIAL
}

// ============================================================================
// Analysis Result Models
// ============================================================================

/**
 * Complete analysis result for a binary file.
 */
@Entity(tableName = "analysis_results")
@Serializable
data class AnalysisResult(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val fileId: Long,
    
    // Statistics
    val totalInstructions: Long = 0L,
    val totalFunctions: Long = 0L,
    val totalStrings: Long = 0L,
    val totalXrefs: Long = 0L,
    
    // Timing
    val analysisTimeMs: Long = 0L,
    val startTime: Long = System.currentTimeMillis(),
    val endTime: Long = 0L,
    
    // Status
    val status: AnalysisStatus = AnalysisStatus.NOT_STARTED,
    val currentPhase: String = "",
    val progressPercent: Int = 0,
    
    // Warnings and errors
    val warnings: List<String> = emptyList(),
    val errors: List<String> = emptyList()
)

/**
 * Disassembled instruction representation.
 */
@Serializable
data class Instruction(
    val address: Long,
    val rawBytes: ByteArray,
    val mnemonic: String,
    val operands: String,
    val size: Int,
    val architecture: Architecture = Architecture.UNKNOWN,
    val isBranch: Boolean = false,
    val isCall: Boolean = false,
    val isReturn: Boolean = false,
    val branchTarget: Long? = null,
    val comment: String? = null,
    val label: String? = null,
    val functionId: Int = -1,
    val basicBlockId: Int = -1
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        
        other as Instruction
        
        if (address != other.address) return false
        if (!rawBytes.contentEquals(other.rawBytes)) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = address.hashCode()
        result = 31 * result + rawBytes.contentHashCode()
        return result
    }
    
    /**
     * Format instruction as disassembly line.
     */
    fun toDisassemblyLine(): String {
        val addrStr = "0x${address.toString(16).padStart(16, '0')}"
        val hexStr = rawBytes.joinToString(" ") { 
            "%02X".format(it) 
        }.padEnd(24)
        
        return "$addrStr  $hexStr  $mnemonic $operands".trimEnd()
    }
    
    companion object {
        /**
         * Create placeholder instruction for display.
         */
        fun placeholder(address: Long): Instruction {
            return Instruction(
                address = address,
                rawBytes = byteArrayOf(),
                mnemonic = "???",
                operands = "",
                size = 0
            )
        }
    }
}

/**
 * Function information extracted from binary.
 */
@Entity(tableName = "functions")
@Serializable
data class Function(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val fileId: Long,
    val startAddress: Long,
    val endAddress: Long,
    val size: Long,
    val name: String,
    val demangledName: String? = null,
    val type: FunctionType = FunctionType.NORMAL,
    val callingConvention: CallingConvention = CallingConvention.UNKNOWN,
    val instructionCount: Int = 0,
    val cyclomaticComplexity: Int = 0,
    val hasVariableArgs: Boolean = false,
    val isNoreturn: Boolean = false,
    val comment: String? = null
) {
    /**
     * Get display name (demangled if available).
     */
    fun getDisplayName(): String {
        return demangledName ?: name.ifEmpty { "sub_${startAddress.toString(16)}" }
    }
    
    /**
     * Get function size as formatted string.
     */
    fun getFormattedSize(): String {
        return "${size} bytes (${instructionCount} instructions)"
    }
}

/**
 * Function type classification.
 */
enum class FunctionType {
    NORMAL,
    THUNK,
    LIBRARY,
    IMPORTED,
    EXPORTED,
    WEAK,
    STATIC,
    INLINE
}

/**
 * Calling convention types.
 */
enum class CallingConvention {
    UNKNOWN,
    AAPCS,
    AAPCS_VFP,
    AARCH64,
    CDECL,
    STDCALL,
    FASTCALL,
    THISCALL,
    SYSTEM_V_AMD64
}

/**
 * Extracted string from binary.
 */
@Entity(tableName = "strings")
@Serializable
data class StringEntry(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val fileId: Long,
    val address: Long,
    val value: String,
    val encoding: StringEncoding = StringEncoding.ASCII,
    val length: Int = 0,
    val byteLength: Int = 0,
    val type: StringType = StringType.PRINTABLE,
    val isReferenced: Boolean = false
) {
    /**
     * Get escaped string value for safe display.
     */
    fun getEscapedValue(): String {
        return buildString {
            append("\"")
            for (c in value) {
                when (c) {
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    '"' -> append("\\\"")
                    '\\' -> append("\\\\")
                    else -> if (c.code in 32..127) append(c) else append("\\x%02X".format(c.code))
                }
            }
            append("\"")
        }
    }
}

/**
 * String encoding types.
 */
enum class StringEncoding {
    ASCII,
    UTF8,
    UTF16_LE,
    UTF16_BE,
    UTF32_LE,
    UTF32_BE
}

/**
 * String classification types.
 */
enum class StringType {
    UNKNOWN,
    PRINTABLE,
    WIDE,
    UNICODE,
    C_STRING,
    JAVA_STRING,
    PATH,
    URL,
    EMAIL,
    IP_ADDRESS,
    GUID,
    REGEX,
    XML,
    JSON,
    BASE64,
    HEX,
    FORMAT_STRING
}

/**
 * Cross-reference between addresses.
 */
@Serializable
data class Xref(
    val from: Long,
    val to: Long,
    val type: XrefType = XrefType.UNDEFINED,
    val context: String = ""
) {
    override fun toString(): String {
        return "0x${from.toString(16).padStart(8, '0')} -> 0x${to.toString(16).padStart(8, '0')} [${type.name}]"
    }
}

/**
 * Cross-reference types.
 */
enum class XrefType {
    DATA,
    CODE,
    CALL,
    STRING,
    IMPORT,
    EXPORT,
    READ,
    WRITE,
    UNDEFINED
}

/**
 * Section/header information from binary format.
 */
@Serializable
data class SectionInfo(
    val name: String,
    val virtualAddress: Long,
    val virtualSize: Long,
    val fileOffset: Long,
    val fileSize: Long,
    val type: SectionType = SectionType.UNKNOWN,
    val executable: Boolean = false,
    val writable: Boolean = false,
    val readable: Boolean = false
)

/**
 * Section types.
 */
enum class SectionType {
    CODE,
    DATA,
    RODATA,
    BSS,
    HEAP,
    STACK,
    IMPORT,
    EXPORT,
    RESOURCE,
    DEBUG,
    EXCEPTION,
    TLS,
    GNU_EH_FRAME,
    GNU_HASH,
    DYNAMIC,
    DYNSTR,
    DYNSYM,
    GOT,
    PLT,
    REL,
    UNKNOWN
}

// ============================================================================
// User Preference Models
// ============================================================================

/**
 * User settings/preferences.
 */
@Entity(tableName = "user_settings")
@Serializable
data class UserSettings(
    @PrimaryKey
    val id: Int = 1,
    
    // Display settings
    val themeMode: ThemeModeValue = ThemeModeValue.SYSTEM,
    val fontSize: FontSize = FontSize.MEDIUM,
    val syntaxHighlighting: Boolean = true,
    
    // Analysis settings
    val autoAnalyzeOnOpen: Boolean = true,
    val deepScanMode: Boolean = false,
    val minStringLength: Int = 4,
    val maxStringLength: Int = 4096,
    val defaultArchitecture: Architecture = Architecture.AUTO_DETECT,
    
    // Editor settings
    val hexEditorGroupBy: Int = 1,  // Bytes per group
    val showAsciiColumn: Boolean = true,
    val wordWrap: Boolean = false,
    
    // Advanced settings
    val maxMemoryUsageMB: Int = 512,
    val enableLogging: Boolean = false,
    val checkForUpdates: Boolean = true
)

/**
 * Theme mode values for persistence.
 */
enum class ThemeModeValue {
    LIGHT,
    DARK,
    SYSTEM,
    AMOLED
}

/**
 * Font size options.
 */
enum class FontSize(val scale: Float) {
    SMALL(0.85f),
    MEDIUM(1.0f),
    LARGE(1.15f),
    EXTRA_LARGE(1.3f)
}
