package com.mobile.idapro.viewmodel

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.mobile.idapro.IdaProApplication
import com.mobile.idapro.data.database.AppDatabase
import com.mobile.idapro.data.database.entities.*
import com.mobile.idapro.data.model.*
import com.mobile.idapro.data.repository.BinaryAnalysisRepository
import com.mobile.idapro.native.NativeBinaryAnalyzer
import com.mobile.idapro.utils.BinaryUtils
import com.mobile.idapro.utils.FileUtils
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Main ViewModel (Merged from both projects) - Modernized for IDA Pro M v3.0
 * 
 * Central state management for IDA Pro M combining:
 * - File management (IDA Pro Mobile)
 * - Disassembly analysis (both projects)
 * - Bookmarks (KTIMAZ-REV - now persistent via Room)
 * - Search/Filter with debouncing (KTIMAZ-REV)
 * - Navigation state management
 * - Thread-safe operations
 */
class MainViewModel(private val database: AppDatabase) : ViewModel() {

    private val repository = BinaryAnalysisRepository(database)
    private val nativeAnalyzer = NativeBinaryAnalyzer()

    // === State Flows (Thread-safe) ===

    // File management state
    private val _binaryFiles = MutableStateFlow<List<BinaryFileEntity>>(emptyList())
    val binaryFiles: StateFlow<List<BinaryFileEntity>> = _binaryFiles.asStateFlow()

    private val _selectedBinaryFile = MutableStateFlow<BinaryFileEntity?>(null)
    val selectedBinaryFile: StateFlow<BinaryFileEntity?> = _selectedBinaryFile.asStateFlow()

    // Analysis data states
    private val _instructions = MutableStateFlow<List<DisassemblyInstruction>>(emptyList())
    val instructions: StateFlow<List<DisassemblyInstruction>> = _instructions.asStateFlow()

    private val _functions = MutableStateFlow<List<Function>>(emptyList())
    val functions: StateFlow<List<Function>> = _functions.asStateFlow()

    private val _symbols = MutableStateFlow<List<Symbol>>(emptyList())
    val symbols: StateFlow<List<Symbol>> = _symbols.asStateFlow()

    private val _sectionNames = MutableStateFlow<List<String>>(emptyList())
    val sectionNames: StateFlow<List<String>> = _sectionNames.asStateFlow()

    private val _hexData = MutableStateFlow<ByteArray>(byteArrayOf())
    val hexData: StateFlow<ByteArray> = _hexData.asStateFlow()

    // UI State
    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    private val _currentTab = MutableStateFlow(AppTab.Files)
    val currentTab: StateFlow<AppTab> = _currentTab.asStateFlow()

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    private val _showMenu = MutableStateFlow(false)
    val showMenu: StateFlow<Boolean> = _showMenu.asStateFlow()

    // Bookmarks (from KTIMAZ-REV - now persistent)
    private val _bookmarks = MutableStateFlow<List<Bookmark>>(emptyList())
    val bookmarks: StateFlow<List<Bookmark>> = _bookmarks.asStateFlow()

    // Cache for performance
    private val instructionCache = ConcurrentHashMap<Long, DisassemblyInstruction>()
    private val operationCounter = AtomicLong(0)

    // Filtered instructions based on search query (with debounce-like behavior)
    val filteredInstructions: StateFlow<List<DisassemblyInstruction>> =
        combine(_instructions, _searchQuery) { instructions, query ->
            if (query.isBlank()) {
                instructions
            } else {
                val q = query.lowercase()
                instructions.filter {
                    it.mnemonic.lowercase().contains(q) ||
                    it.operands.any { op -> op.lowercase().contains(q) } ||
                    it.comment?.lowercase()?.contains(q) == true ||
                    BinaryUtils.toHexString(it.address).lowercase().contains(q)
                }
            }
        }.stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )

    init {
        loadBinaryFiles()
        loadBookmarks()
    }

    // === File Operations ===

    private fun loadBinaryFiles() {
        viewModelScope.launch {
            repository.getAllBinaryFiles().collect { files ->
                _binaryFiles.value = files
            }
        }
    }

    fun showFilePicker(context: Context) {
        // This will be handled by the Activity's file picker launcher
        // The activity should call loadBinaryFile() after file selection
    }

    fun loadBinaryFile(context: Context, uri: Uri) {
        val currentOperationId = operationCounter.incrementAndGet()
        
        viewModelScope.launch {
            try {
                _isLoading.value = true
                _errorMessage.value = null

                // Copy file to app storage securely
                val fileName = FileUtils.getFileName(context, uri) ?: "unknown_binary_${System.currentTimeMillis()}"
                val localFile = FileUtils.copyToAppStorage(context, uri, fileName)

                if (localFile == null || !localFile.exists()) {
                    _errorMessage.value = "Failed to copy file to app storage"
                    return@launch
                }

                // Validate file size
                if (localFile.length() == 0L) {
                    _errorMessage.value = "Selected file is empty"
                    return@launch
                }

                // Check if this is a duplicate
                val existingFile = _binaryFiles.value.find { it.path == localFile.absolutePath }
                if (existingFile != null) {
                    selectBinaryFile(existingFile)
                    return@launch
                }

                // Analyze file with native code (with fallback)
                var fileInfo = emptyArray<String>()
                var checksum: String? = null
                
                if (IdaProApplication.isFullFunctionalAvailable()) {
                    runCatching {
                        fileInfo = nativeAnalyzer.getFileInfo(localFile.absolutePath)
                        checksum = nativeAnalyzer.calculateChecksum(localFile.absolutePath)
                    }.onFailure { e ->
                        // Native analysis failed, continue with basic info
                        e.printStackTrace()
                    }
                }

                // Create and save BinaryFile entity
                val binaryFile = BinaryFileEntity(
                    id = java.util.UUID.randomUUID().toString(),
                    name = fileName,
                    path = localFile.absolutePath,
                    size = localFile.length(),
                    architecture = fileInfo.getOrElse(0) { "Unknown" },
                    fileType = fileInfo.getOrElse(1) { "Unknown" },
                    entryPoint = runCatching { 
                        fileInfo.getOrElse(2) { "0" }.toLongOrNull() ?: 0L 
                    }.getOrDefault(0L),
                    checksum = checksum.ifBlank { null }
                )

                repository.insertBinaryFile(binaryFile)

                // Load native binary for analysis
                if (IdaProApplication.isFullFunctionalAvailable()) {
                    runCatching {
                        if (nativeAnalyzer.loadBinary(localFile.absolutePath)) {
                            loadAnalysisData(binaryFile.id)
                        }
                    }.onFailure { e ->
                        e.printStackTrace()
                    }
                }

                // Select the newly loaded file
                _selectedBinaryFile.value = binaryFile
                repository.updateLastAccessed(binaryFile.id)

            } catch (e: SecurityException) {
                _errorMessage.value = "Security error: ${e.message}"
            } catch (e: OutOfMemoryError) {
                _errorMessage.value = "File too large for available memory"
            } catch (e: Exception) {
                _errorMessage.value = "Error loading binary file: ${e.message}"
            } finally {
                // Only stop loading if this is still the current operation
                if (operationCounter.get() == currentOperationId) {
                    _isLoading.value = false
                }
            }
        }
    }

    private fun loadAnalysisData(fileId: String) {
        viewModelScope.launch {
            try {
                // Load section names (ELF specific)
                runCatching {
                    val sections = nativeAnalyzer.getSectionNames()
                    if (sections.isNotEmpty()) {
                        _sectionNames.value = sections.toList()
                    }
                }

                // Load symbols (ELF specific)
                runCatching {
                    val symbolData = nativeAnalyzer.getSymbols()
                    if (symbolData.isNotEmpty()) {
                        _symbols.value = symbolData.map { it.toSymbol() }
                    }
                }

                // Detect functions
                runCatching {
                    val functionData = nativeAnalyzer.detectFunctions()
                    if (functionData.isNotEmpty()) {
                        _functions.value = functionData.map { it.toFunction() }
                    }
                }

            } catch (e: Exception) {
                // Non-critical error, log but don't fail
                e.printStackTrace()
            }
        }
    }

    fun selectBinaryFile(file: BinaryFileEntity) {
        viewModelScope.launch {
            _selectedBinaryFile.value = file
            
            // Clear previous data and cache
            _instructions.value = emptyList()
            _functions.value = emptyList()
            _symbols.value = emptyList()
            _sectionNames.value = emptyList()
            _hexData.value = byteArrayOf()
            instructionCache.clear()
            _errorMessage.value = null

            // Reload analysis data
            if (IdaProApplication.isFullFunctionalAvailable()) {
                runCatching {
                    if (nativeAnalyzer.loadBinary(file.path)) {
                        loadAnalysisData(file.id)
                    }
                }
            }

            repository.updateLastAccessed(file.id)
        }
    }

    fun deleteBinaryFile(fileId: String) {
        viewModelScope.launch {
            try {
                if (_selectedBinaryFile.value?.id == fileId) {
                    _selectedBinaryFile.value = null
                    clearAllData()
                }
                
                repository.deleteBinaryFile(fileId)
            } catch (e: Exception) {
                _errorMessage.value = "Error deleting file: ${e.message}"
            }
        }
    }

    // === Disassembly Operations ===

    fun loadDisassembly(fileId: String, startAddress: Long = 0, count: Int = 500) {
        viewModelScope.launch {
            try {
                _isLoading.value = true
                
                if (!IdaProApplication.isFullFunctionalAvailable()) {
                    // Generate placeholder data when native is not available
                    generatePlaceholderInstructions(startAddress, count)
                    return@launch
                }
                
                val disassemblyData = nativeAnalyzer.disassemble(startAddress, count)
                
                val instructions = disassemblyData.map { data ->
                    data.toDisassemblyInstruction().also { instr ->
                        if (instr.address != 0L) {
                            instructionCache[instr.address] = instr
                        }
                    }
                }
                
                _instructions.value = instructions

            } catch (e: Exception) {
                _errorMessage.value = "Error loading disassembly: ${e.message}"
            } finally {
                _isLoading.value = false
            }
        }
    }
    
    private fun generatePlaceholderInstructions(startAddress: Long, count: Int) {
        val instructions = (0 until count).map { i ->
            val address = startAddress + (i * 4)
            DisassemblyInstruction(
                address = address,
                bytes = ByteArray(4) { ((address shr (24 - it * 8)) and 0xFF).toByte() },
                mnemonic = ".word",
                operands = listOf("0x${String.format("%08X", address)}"),
                comment = "Native library not loaded",
                byteLength = 4
            )
        }
        _instructions.value = instructions
    }

    fun loadDisassemblyForSection(sectionName: String, baseAddress: Long, isThumbMode: Boolean = false) {
        viewModelScope.launch {
            try {
                _isLoading.value = true
                
                if (!IdaProApplication.isFullFunctionalAvailable()) {
                    _errorMessage.value = "Native library not available for section analysis"
                    return@launch
                }
                
                val disassemblyData = nativeAnalyzer.disassembleSection(sectionName, baseAddress, isThumbMode)
                _instructions.value = disassemblyData.map { it.toDisassemblyInstruction() }
                
                // Also load hex dump for this section
                val hexDump = nativeAnalyzer.getSectionHexDump(sectionName, 0, 4096)
                _hexData.value = hexDump ?: byteArrayOf()

            } catch (e: Exception) {
                _errorMessage.value = "Error loading section disassembly: ${e.message}"
            } finally {
                _isLoading.value = false
            }
        }
    }

    // === Hex Data Operations ===

    fun loadHexData(fileId: String) {
        viewModelScope.launch {
            try {
                _isLoading.value = true
                
                if (!IdaProApplication.isFullFunctionalAvailable()) {
                    _errorMessage.value = "Native library not available"
                    return@launch
                }
                
                val hexData = nativeAnalyzer.getBinaryData()
                _hexData.value = hexData ?: byteArrayOf()
            } catch (e: Exception) {
                _errorMessage.value = "Error loading hex data: ${e.message}"
            } finally {
                _isLoading.value = false
            }
        }
    }

    // === Function Operations ===

    fun loadFunctions(fileId: String) {
        viewModelScope.launch {
            try {
                _isLoading.value = true
                
                if (!IdaProApplication.isFullFunctionalAvailable()) {
                    _errorMessage.value = "Native library not available"
                    return@launch
                }
                
                val functionData = nativeAnalyzer.detectFunctions()
                _functions.value = functionData.map { it.toFunction() }
            } catch (e: Exception) {
                _errorMessage.value = "Error analyzing functions: ${e.message}"
            } finally {
                _isLoading.value = false
            }
        }
    }

    // === Bookmark Operations (from KTIMAZ-REV - now persistent) ===

    private fun loadBookmarks() {
        viewModelScope.launch {
            repository.getAllBookmarks().collect { bookmarkEntities ->
                _bookmarks.value = bookmarkEntities.map { entity ->
                    Bookmark(
                        uid = entity.uid,
                        fileId = entity.fileId,
                        address = entity.address,
                        name = entity.name,
                        comment = entity.comment
                    )
                }.sortedBy { it.address }
            }
        }
    }

    fun addBookmark(address: Long, name: String, comment: String) {
        viewModelScope.launch {
            val fileId = _selectedBinaryFile.value?.id ?: return@launch
            
            val bookmarkEntity = BookmarkEntity(
                fileId = fileId,
                address = address,
                name = name.ifBlank { "Bookmark @ ${BinaryUtils.toHexString(address)}" },
                comment = comment
            )
            
            repository.insertBookmark(bookmarkEntity)
        }
    }

    fun removeBookmark(bookmark: Bookmark) {
        viewModelScope.launch {
            repository.deleteBookmarkById(bookmark.uid)
        }
    }

    // === UI Operations ===

    fun selectTab(tab: AppTab) {
        _currentTab.value = tab
        
        // Auto-load data when switching tabs
        val file = _selectedBinaryFile.value
        when (tab) {
            AppTab.Disassembly -> {
                if (_instructions.value.isEmpty() && file != null) {
                    loadDisassembly(file.id)
                }
            }
            AppTab.HexView -> {
                if (_hexData.value.isEmpty() && file != null) {
                    loadHexData(file.id)
                }
            }
            AppTab.Functions -> {
                if (_functions.value.isEmpty() && file != null) {
                    loadFunctions(file.id)
                }
            }
            else -> {}
        }
    }

    fun updateSearchQuery(query: String) {
        _searchQuery.value = query
    }

    fun toggleMenu(show: Boolean?) {
        _showMenu.value = show ?: !_showMenu.value
    }

    fun clearError() {
        _errorMessage.value = null
    }

    private fun clearAllData() {
        _instructions.value = emptyList()
        _functions.value = emptyList()
        _symbols.value = emptyList()
        _sectionNames.value = emptyList()
        _hexData.value = byteArrayOf()
        _errorMessage.value = null
        instructionCache.clear()
    }

    override fun onCleared() {
        super.onCleared()
        runCatching { nativeAnalyzer.cleanup() }
        instructionCache.clear()
    }
}

/**
 * Factory for creating MainViewModel instances
 */
class MainViewModelFactory(private val database: AppDatabase) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(MainViewModel::class.java)) {
            return MainViewModel(database) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class: ${modelClass.name}")
    }
}

/**
 * Application tabs enum (Merged from both projects)
 */
enum class AppTab(val title: String) {
    Files("Files"),
    Disassembly("Disasm"),
    HexView("Hex"),
    Functions("Functions"),
    Symbols("Symbols"),
    Bookmarks("Bookmarks"),
    GraphView("Graph")
}
