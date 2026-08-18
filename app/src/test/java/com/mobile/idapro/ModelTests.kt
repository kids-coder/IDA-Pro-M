package com.mobile.idapro

import org.junit.Test
import org.junit.Assert.*
import com.mobile.idapro.data.model.*

/**
 * IDA Pro M - Unit Tests
 * 
 * Comprehensive unit tests for data models, utilities,
 * and business logic components.
 */
class ModelTests {
    
    // ========================================================================
    // LoadedFile Tests
    // ========================================================================
    
    @Test
    fun `test LoadedFile default values`() {
        val file = LoadedFile(
            fileName = "test.bin",
            filePath = "/data/local/tmp/test.bin",
            fileSize = 1024,
            md5Hash = "abc123",
            sha256Hash = "def456"
        )
        
        assertEquals("test.bin", file.fileName)
        assertEquals("/data/local/tmp/test.bin", file.filePath)
        assertEquals(1024L, file.fileSize)
        assertEquals(AnalysisStatus.NOT_STARTED, file.analysisStatus)
        assertFalse(file.is64Bit)
        assertTrue(file.isLittleEndian)
    }
    
    @Test
    fun `test LoadedFile format display names`() {
        assertEquals("ELF Binary", BinaryFormat.ELF.getDisplayName())
        assertEquals("PE Executable", BinaryFormat.PE.getDisplayName())
        assertEquals("Mach-O Binary", BinaryFormat.MACH_O.getDisplayName())
        assertEquals("DEX (Android)", BinaryFormat.DEX.getDisplayName())
        assertEquals("Raw Binary", BinaryFormat.RAW.getDisplayName())
    }
    
    @Test
    fun `test LoadedFile architecture display names`() {
        assertEquals("ARM 32-bit", Architecture.ARM32.getDisplayName())
        assertEquals("ARM 64-bit (AArch64)", Architecture.ARM64.getDisplayName())
        assertEquals("x86 32-bit", Architecture.X86_32.getDisplayName())
        assertEquals("x86-64", Architecture.X86_64.getDisplayName())
    }
    
    @Test
    fun `test LoadedFile formatted size`() {
        val file1 = LoadedFile(fileName = "small.bin", fileSize = 512)
        assertTrue(file1.getFormattedSize().contains("512"))
        
        val file2 = LoadedFile(fileName = "kb.bin", fileSize = 1024)
        assertTrue(file2.getFormattedSize().contains("1"))
        assertTrue(file2.getFormattedSize().contains("KB"))
        
        val file3 = LoadedFile(fileName = "mb.bin", fileSize = 1048576)
        assertTrue(file3.getFormattedSize().contains("MB"))
        
        val file4 = LoadedFile(fileName = "gb.bin", fileSize = 1073741824)
        assertTrue(file4.getFormattedSize().contains("GB"))
    }
    
    // ========================================================================
    // Instruction Tests
    // ========================================================================
    
    @Test
    fun `test Instruction creation and equality`() {
        val bytes = byteArrayOf(0x01, 0x00, 0xA0, 0xE3)
        val insn1 = Instruction(
            address = 0x1000,
            rawBytes = bytes,
            mnemonic = "mov",
            operands = "r0, r1",
            size = 4
        )
        
        val insn2 = Instruction(
            address = 0x1000,
            rawBytes = bytes,
            mnemonic = "mov",
            operands = "r0, r1",
            size = 4
        )
        
        assertEquals(insn1, insn2)
        assertEquals(insn1.hashCode(), insn2.hashCode())
    }
    
    @Test
    fun `test Instruction branch detection`() {
        val branchInsn = Instruction(
            address = 0x1000,
            rawBytes = byteArrayOf(0xEA, 0xFF, 0xFF, 0xFE),
            mnemonic = "b",
            operands = "0x2000",
            size = 4,
            isBranch = true,
            branchTarget = 0x2000L
        )
        
        assertTrue(branchInsn.isBranch)
        assertFalse(branchInsn.isCall)
        assertFalse(branchInsn.isReturn)
        assertNotNull(branchInsn.branchTarget)
        assertEquals(0x2000L, branchInsn.branchTarget)
    }
    
    @Test
    fun `test Instruction call detection`() {
        val callInsn = Instruction(
            address = 0x1004,
            rawBytes = byteArrayOf(0xEB, 0xFF, 0xFF, 0xEE),
            mnemonic = "bl",
            operands = "0x3000",
            size = 4,
            isCall = true,
            branchTarget = 0x3000L
        )
        
        assertFalse(callInsn.isBranch)
        assertTrue(callInsn.isCall)
        assertFalse(callInsn.isReturn)
    }
    
    @Test
    fun `test Instruction return detection`() {
        val retInsn = Instruction(
            address = 0x1008,
            rawBytes = byteArrayOf(0x1E, 0xFF, 0x2F, 0xE1),
            mnemonic = "bx",
            operands = "lr",
            size = 4,
            isReturn = true
        )
        
        assertFalse(retInsn.isBranch)
        assertFalse(retInsn.isCall)
        assertTrue(retInsn.isReturn)
    }
    
    @Test
    fun `test Instruction disassembly line formatting`() {
        val insn = Instruction(
            address = 0x401000,
            rawBytes = byteArrayOf(0x00, 0x40, 0x20, 0xE3),
            mnemonic = "sub",
            operands = "sp, #0x10",
            size = 4
        )
        
        val line = insn.toDisassemblyLine()
        assertTrue(line.contains("000401000"))  // Address
        assertTrue(line.contains("004020e3"))   // Bytes
        assertTrue(line.contains("sub"))       // Mnemonic
        assertTrue(line.contains("sp, #0x10")) // Operands
    }
    
    // ========================================================================
    // Function Tests
    // ========================================================================
    
    @Test
    fun `test Function display name with demangling`() {
        val func = Function(
            fileId = 1,
            startAddress = 0x1000,
            endAddress = 0x1100,
            size = 256,
            name = "_Z4mainv",
            demangledName = "main()",
            type = FunctionType.NORMAL
        )
        
        assertEquals("main()", func.getDisplayName())
    }
    
    @Test
    fun `test Function display name without demangling`() {
        val func = Function(
            fileId = 1,
            startAddress = 0x2000,
            endAddress = 0x2100,
            size = 256,
            name = "",
            type = FunctionType.NORMAL
        )
        
        assertTrue(func.getDisplayName().startsWith("sub_"))
        assertTrue(func.getDisplayName().contains("2000"))
    }
    
    @Test
    fun `test Function formatted size`() {
        val func = Function(
            fileId = 1,
            startAddress = 0x1000,
            endAddress = 0x1100,
            size = 256,
            instructionCount = 64,
            name = "test_func"
        )
        
        val sizeStr = func.getFormattedSize()
        assertTrue(sizeStr.contains("256"))
        assertTrue(sizeStr.contains("64"))
    }
    
    // ========================================================================
    // StringEntry Tests
    // ========================================================================
    
    @Test
    fun `test StringEntry escaped value for special chars`() {
        val strWithNewline = StringEntry(
            fileId = 1,
            address = 0x4000,
            value = "Hello\nWorld",
            encoding = StringEncoding.ASCII
        )
        
        val escaped = strWithNewline.getEscapedValue()
        assertTrue(escaped.contains("\\n"))
        assertTrue(escaped.contains("Hello"))
        assertTrue(escaped.contains("World"))
    }
    
    @Test
    fun `test StringEntry escaped value for quotes`() {
        val strWithQuotes = StringEntry(
            fileId = 1,
            address = 0x4010,
            value = "Say \"Hello\"",
            encoding = StringEncoding.ASCII
        )
        
        val escaped = strWithQuotes.getEscapedValue()
        assertTrue(escaped.contains("\\\""))
    }
    
    // ========================================================================
    // Xref Tests
    // ========================================================================
    
    @Test
    fun `test Xref string representation`() {
        val xref = Xref(
            from = 0x1000,
            to = 0x2000,
            type = XrefType.CALL
        )
        
        val str = xref.toString()
        assertTrue(str.contains("00001000"))  // From address
        assertTrue(str.contains("00002000"))  // To address
        assertTrue(str.contains("CALL"))     // Type
        assertTrue(str.contains("->"))        // Arrow
    }
    
    // ========================================================================
    // AnalysisResult Tests
    // ========================================================================
    
    @Test
    fun `test AnalysisResult completion status`() {
        val result = com.mobile.idapro.data.model.AnalysisResult(
            fileId = 1,
            totalInstructions = 1500,
            totalFunctions = 45,
            totalStrings = 230,
            totalXrefs = 890,
            analysisTimeMs = 5000,
            status = AnalysisStatus.COMPLETED
        )
        
        assertEquals(AnalysisStatus.COMPLETED, result.status)
        assertEquals(1500L, result.totalInstructions)
        assertEquals(45L, result.totalFunctions)
        assertEquals(230L, result.totalStrings)
        assertEquals(890L, result.totalXrefs)
        assertEquals(5000L, result.analysisTimeMs)
    }
}

/**
 * Utility tests for hex operations and conversions.
 */
class UtilityTests {
    
    @Test
    fun `test hex conversion utilities`() {
        // Test that our hex parsing works correctly
        val hexString = "DEADBEEF"
        val expectedLong = 0xDEADBEEFL
        
        try {
            val parsed = hexString.toLong(16)
            assertEquals(expectedLong, parsed)
        } catch (e: NumberFormatException) {
            fail("Failed to parse valid hex string")
        }
    }
    
    @Test
    fun `test address formatting`() {
        val addr = 0x401234L
        val expectedPadded = "000401234"
        
        val formatted = "%016X".format(addr)
        assertEquals(expectedPadded, formatted)
    }
}
