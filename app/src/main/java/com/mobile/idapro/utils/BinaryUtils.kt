package com.mobile.idapro.utils

/**
 * Binary Analysis Utilities (Merged from both projects) - v3.0
 * Helper functions for binary data manipulation and display
 */
object BinaryUtils {

    /**
     * Convert byte array to hex string with formatting
     */
    fun bytesToHex(bytes: ByteArray, bytesPerRow: Int = 16): String {
        return buildString {
            bytes.forEachIndexed { index, byte ->
                append(String.format("%02X", byte))
                if ((index + 1) % bytesPerRow == 0) {
                    append('\n')
                } else {
                    append(' ')
                }
            }
        }
    }

    /**
     * Convert byte array to ASCII representation (printable chars only)
     */
    fun toAsciiString(bytes: ByteArray): String {
        return buildString(bytes.size) { index ->
            val b = bytes[index]
            append(if (b in 32..126) b.toChar() else '.')
        }
    }

    /**
     * Convert long address to hex string
     */
    fun toHexString(address: Long): String = String.format("0x%08X", address)

    /**
     * Convert raw bytes to hex string for display
     */
    fun toRawBytesHexString(rawBytes: Long, byteLength: Int): String {
        return buildString {
            for (i in 0 until byteLength) {
                val shift = (byteLength - 1 - i) * 8
                val byteVal = (rawBytes shr shift) and 0xFF
                append(String.format("%02X", byteVal))
                if (i < byteLength - 1) append(' ')
            }
        }
    }

    /**
     * Calculate simple checksum (for verification)
     */
    fun calculateSimpleChecksum(data: ByteArray): Long {
        var checksum = 0L
        data.forEach { byte ->
            checksum = (checksum * 31 + (byte.toInt() and 0xFF)) and 0xFFFFFFFFFFFFFFFF
        }
        return checksum
    }

    /**
     * Detect architecture from magic bytes
     */
    fun detectArchitecture(magicBytes: ByteArray): String {
        return when {
            magicBytes.size < 4 -> "Unknown"
            magicBytes[0] == 0x7F.toByte() && 
            magicBytes[1] == 'E'.code.toByte() && 
            magicBytes[2] == 'L'.code.toByte() && 
            magicBytes[3] == 'F'.code.toByte() -> "ELF"
            magicBytes[0] == 'M'.code.toByte() && magicBytes[1] == 'Z'.code.toByte() -> "PE/DOS"
            magicBytes[0] == 0xCE.toByte() && magicBytes[1] == 0xFA.toByte() && 
            magicBytes[2] == 0xED.toByte() && magicBytes[3] == 0xFE.toByte() -> "Mach-O"
            else -> "Unknown"
        }
    }

    /**
     * Validate ELF header
     */
    fun isValidELF(data: ByteArray): Boolean {
        return data.size >= 4 &&
               data[0] == 0x7F.toByte() &&
               data[1] == 'E'.code.toByte() &&
               data[2] == 'L'.code.toByte() &&
               data[3] == 'F'.code.toByte()
    }
    
    /**
     * Validate PE/DOS header
     */
    fun isValidPE(data: ByteArray): Boolean {
        return data.size >= 2 &&
               data[0] == 'M'.code.toByte() && 
               data[1] == 'Z'.code.toByte()
    }
    
    /**
     * Format address for display (with optional base prefix)
     */
    fun formatAddress(address: Long, showPrefix: Boolean = true): String {
        return if (showPrefix) "0x${address.toString(16).uppercase().padStart(8, '0')}"
               else address.toString(16).uppercase().padStart(8, '0')
    }
    
    /**
     * Parse hex string to long
     */
    fun parseHexString(hexStr: String): Long? {
        return runCatching {
            hexStr.removePrefix("0x").removePrefix("0X").toLong(16)
        }.getOrNull()
    }
    
    /**
     * Check if an address looks like a function start (heuristic)
     */
    fun isLikelyFunctionStart(instructions: List<Any>, index: Int): Boolean {
        // This is a simplified heuristic - real implementation would be more sophisticated
        return index > 0 && index < instructions.size
    }
}
