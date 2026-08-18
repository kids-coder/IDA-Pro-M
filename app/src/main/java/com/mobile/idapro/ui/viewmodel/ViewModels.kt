package com.mobile.idapro.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mobile.idapro.data.model.*
import com.mobile.idapro.data.repository.*
import com.mobile.idapro.native.DisassemblerNative
import com.mobile.idapro.native.AnalysisOptions
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * IDA Pro M - ViewModels
 * 
 * ViewModel classes for managing UI state and business logic.
 */

// ============================================================================
// Home Screen ViewModel
// ============================================================================

@HiltViewModel
class HomeViewModel @Inject constructor(
    private val fileRepository: FileRepository,
    private val disassemblerNative: DisassemblerNative
) : ViewModel() {
    
    // UI State
    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()
    
    // Recent files list
    private val _recentFiles = MutableStateFlow<List<LoadedFile>>(emptyList())
    val recentFiles: StateFlow<List<LoadedFile>> = _recentFiles.asStateFlow()
    
    // Loading states
    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()
    
    // Error messages
    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()
    
    init {
        loadRecentFiles()
    }
    
    /**
     * Load recent files from database.
     */
    fun loadRecentFiles() {
        viewModelScope.launch {
            _isLoading.value = true
            when (val result = fileRepository.getRecentFiles()) {
                is Result.Success -> {
                    _recentFiles.value = result.getOrNull() ?: emptyList()
                    _uiState.value = _uiState.value.copy(
                        hasRecentFiles = _recentFiles.value.isNotEmpty(),
                        recentFileCount = _recentFiles.value.size
                    )
                }
                is Result.Failure -> {
                    _error.value = result.exceptionOrNull()?.message ?: "Failed to load files"
                }
            }
            _isLoading.value = false
        }
    }
    
    /**
     * Import and load a new binary file.
     */
    fun importFile(filePath: String) {
        viewModelScope.launch {
            _isLoading.value = true
            _error.value = null
            
            // Initialize native engine if needed
            disassemblerNative.initialize()
            
            // Load file in native engine
            when (val result = disassemblerNative.loadFile(filePath)) {
                is Result.Success -> {
                    val nativeInfo = result.getOrNull()!!
                    
                    // Create local file record
                    val loadedFile = LoadedFile(
                        fileName = nativeInfo.fileName,
                        filePath = filePath,
                        fileSize = nativeInfo.fileSize,
                        md5Hash = nativeInfo.md5Hash,
                        sha256Hash = nativeInfo.sha256Hash,
                        format = BinaryFormat.valueOf(nativeInfo.format),
                        architecture = Architecture.valueOf(nativeInfo.architecture),
                        is64Bit = nativeInfo.is64Bit,
                        entryPoint = nativeInfo.entryPoint,
                        imageBase = nativeInfo.imageBase
                    )
                    
                    // Save to database
                    when (val saveResult = fileRepository.saveFile(loadedFile)) {
                        is Result.Success -> {
                            _uiState.value = _uiState.value.copy(
                                lastImportedFileId = saveResult.getOrNull() ?: 0L,
                                importSuccess = true
                            )
                            // Refresh recent files list
                            loadRecentFiles()
                        }
                        is Result.Failure -> {
                            _error.value = "Failed to save file record"
                        }
                    }
                }
                is Result.Failure -> {
                    _error.value = result.exceptionOrNull()?.message ?: "Failed to import file"
                }
            }
            
            _isLoading.value = false
        }
    }
    
    /**
     * Delete a file from history.
     */
    fun deleteFile(fileId: Long) {
        viewModelScope.launch {
            when (val result = fileRepository.deleteFile(fileId)) {
                is Result.Success -> {
                    loadRecentFiles()
                }
                is Result.Failure -> {
                    _error.value = "Failed to delete file"
                }
            }
        }
    }
    
    /**
     * Clear error message.
     */
    fun clearError() {
        _error.value = null
    }
    
    /**
     * Reset import success flag.
     */
    fun resetImportStatus() {
        _uiState.value = _uiState.value.copy(importSuccess = false, lastImportedFileId = 0L)
    }
}

/**
 * UI state for home screen.
 */
data class HomeUiState(
    val hasRecentFiles: Boolean = false,
    val recentFileCount: Int = 0,
    val lastImportedFileId: Long = 0L,
    val importSuccess: Boolean = false,
    val showWelcome: Boolean = true
)

// ============================================================================
// Disassembly Screen ViewModel
// ============================================================================

@HiltViewModel
class DisassemblyViewModel @Inject constructor(
    private val analysisRepository: AnalysisRepository,
    private val fileRepository: FileRepository,
    private val disassemblerNative: DisassemblerNative
) : ViewModel() {
    
    // Current file info
    private val _fileInfo = MutableStateFlow<LoadedFile?>(null)
    val fileInfo: StateFlow<LoadedFile?> = _fileInfo.asStateFlow()
    
    // Instructions for current view
    private val _instructions = MutableStateFlow<List<com.mobile.idapro.data.model.Instruction>>(emptyList())
    val instructions: StateFlow<List<com.mobile.idapro.data.model.Instruction>> = _instructions.asStateFlow()
    
    // Functions list
    private val _functions = MutableStateFlow<List<Function>>(emptyList())
    val functions: StateFlow<List<Function>> = _functions.asStateFlow()
    
    // Analysis status
    private val _analysisStatus = MutableStateFlow(AnalysisStatus.NOT_STARTED)
    val analysisStatus: StateFlow<AnalysisStatus> = _analysisStatus.asStateFlow()
    
    // Progress information
    private val _progress = MutableStateFlow(AnalysisProgress())
    val progress: StateFlow<AnalysisProgress> = _progress.asStateFlow()
    
    // Current address (for navigation)
    private val _currentAddress = MutableStateFlow(0L)
    val currentAddress: StateFlow<Long> = _currentAddress.asStateFlow()
    
    // Error handling
    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()
    
    // Statistics
    private val _statistics = MutableStateFlow(AnalysisStatistics())
    val statistics: StateFlow<AnalysisStatistics> = _statistics.asStateFlow()
    
    /**
     * Load file data for disassembly view.
     */
    fun loadFile(fileId: Long) {
        viewModelScope.launch {
            _error.value = null
            
            when (val result = fileRepository.getFileById(fileId)) {
                is Result.Success -> {
                    _fileInfo.value = result.getOrNull()
                    result.getOrNull()?.let { file ->
                        // Check if analysis exists
                        when (val analysisResult = analysisRepository.getAnalysisResult(fileId)) {
                            is Result.Success -> {
                                analysisResult.getOrNull()?.let { analysis ->
                                    if (analysis.status == AnalysisStatus.COMPLETED) {
                                        _analysisStatus.value = AnalysisStatus.COMPLETED
                                        _statistics.value = AnalysisStatistics(
                                            totalInstructions = analysis.totalInstructions,
                                            totalFunctions = analysis.totalFunctions,
                                            totalStrings = analysis.totalStrings,
                                            totalXrefs = analysis.totalXrefs,
                                            analysisTimeMs = analysis.analysisTimeMs
                                        )
                                    }
                                }
                            }
                        }
                        
                        // Load functions
                        when (val funcResult = analysisRepository.getFunctions(fileId)) {
                            is Result.Success -> {
                                _functions.value = funcResult.getOrNull() ?: emptyList()
                            }
                        }
                    }
                }
                is Result.Failure -> {
                    _error.value = "Failed to load file"
                }
            }
        }
    }
    
    /**
     * Start or resume analysis.
     */
    fun startAnalysis(options: AnalysisOptions = AnalysisOptions()) {
        viewModelScope.launch {
            val file = _fileInfo.value ?: return@launch
            
            _analysisStatus.value = AnalysisStatus.IN_PROGRESS
            _progress.value = AnalysisProgress(currentPhase = "Initializing...")
            
            try {
                // Run analysis in native engine
                when (val result = disassemblerNative.analyze(options)) {
                    is Result.Success -> {
                        val nativeResult = result.getOrNull()!!
                        
                        // Save results to database
                        val analysisRecord = com.mobile.idapro.data.model.AnalysisResult(
                            fileId = file.id,
                            totalInstructions = nativeResult.totalInstructions,
                            totalFunctions = nativeResult.totalFunctions,
                            totalStrings = nativeResult.totalStrings,
                            totalXrefs = nativeResult.totalXrefs,
                            analysisTimeMs = nativeResult.analysisTimeMs,
                            status = AnalysisStatus.COMPLETED,
                            progressPercent = 100
                        )
                        analysisRepository.createAnalysisResult(analysisRecord)
                        
                        // Update UI state
                        _analysisStatus.value = AnalysisStatus.COMPLETED
                        _progress.value = AnalysisProgress(progressPercent = 100, currentPhase = "Complete")
                        _statistics.value = AnalysisStatistics(
                            totalInstructions = nativeResult.totalInstructions,
                            totalFunctions = nativeResult.totalFunctions,
                            totalStrings = nativeResult.totalStrings,
                            totalXrefs = nativeResult.totalXrefs,
                            analysisTimeMs = nativeResult.analysisTimeMs
                        )
                        
                        // Reload functions after analysis
                        when (val funcResult = analysisRepository.getFunctions(file.id)) {
                            is Result.Success -> {
                                _functions.value = funcResult.getOrNull() ?: emptyList()
                            }
                        }
                    }
                    is Result.Failure -> {
                        _analysisStatus.value = AnalysisStatus.FAILED
                        _error.value = result.exceptionOrNull()?.message ?: "Analysis failed"
                    }
                }
            } catch (e: Exception) {
                _analysisStatus.value = AnalysisStatus.FAILED
                _error.value = e.message ?: "Analysis error"
            }
        }
    }
    
    /**
     * Navigate to specific address.
     */
    fun navigateToAddress(address: Long) {
        _currentAddress.value = address
        
        // Load instructions around this address
        viewModelScope.launch {
            val rangeSize = 100L // Number of instructions to load
            when (val result = disassemblerNative.getDisassemblyRange(address, address + rangeSize * 16)) {
                is Result.Success -> {
                    val nativeInstructions = result.getOrNull() ?: emptyList()
                    _instructions.value = nativeInstructions.map { native ->
                        com.mobile.idapro.data.model.Instruction(
                            address = native.address,
                            rawBytes = native.rawBytes,
                            mnemonic = native.mnemonic,
                            operands = native.operands,
                            size = native.size,
                            isBranch = native.isBranch,
                            isCall = native.isCall,
                            isReturn = native.isReturn,
                            branchTarget = native.branchTarget,
                            comment = native.comment
                        )
                    }
                }
                is.Result.Failure -> {
                    _error.value = "Failed to load instructions at address"
                }
            }
        }
    }
    
    /**
     * Get function containing address.
     */
    fun getFunctionContaining(address: Long): Function? {
        return runBlocking {
            val fileId = _fileInfo.value?.id ?: return@runBlocking null
            when (val result = analysisRepository.getFunctionContainingAddress(fileId, address)) {
                is Result.Success -> result.getOrNull()
                else -> null
            }
        }
    }
}

/**
 * Analysis progress information.
 */
data class AnalysisProgress(
    val progressPercent: Int = 0,
    val currentPhase: String = "",
    val elapsedTimeMs: Long = 0L
)

/**
 * Analysis statistics.
 */
data class AnalysisStatistics(
    val totalInstructions: Long = 0L,
    val totalFunctions: Long = 0L,
    val totalStrings: Long = 0L,
    val totalXrefs: Long = 0L,
    val analysisTimeMs: Long = 0L
)

// ============================================================================
// Hex Editor ViewModel
// ============================================================================

@HiltViewModel
class HexEditorViewModel @Inject constructor(
    private val fileRepository: FileRepository,
    private val disassemblerNative: DisassemblerNative
) : ViewModel() {
    
    private val _hexData = MutableStateFlow<HexEditorData>(HexEditorData.Empty)
    val hexData: StateFlow<HexEditorData> = _hexData.asStateFlow()
    
    private val _selectedOffset = MutableStateFlow(0L)
    val selectedOffset: StateFlow<Long> = _selectedOffset.asStateFlow()
    
    private val _editMode = MutableStateFlow(false)
    val editMode: StateFlow<Boolean> = _editMode.asStateFlow()
    
    private val _modifications = MutableStateFlow(setOf<Long>())
    val modifications: StateFlow<Set<Long>> = _modifications.asStateLoop()
    
    fun loadHexData(fileId: Long, startOffset: Long = 0L) {
        viewModelScope.launch {
            when (val result = disassemblerNative.getHexDump(startOffset, 4096)) {
                is Result.Success -> {
                    _hexData.value = HexEditorData.Loaded(
                        hexDump = result.getOrNull() ?: "",
                        startOffset = startOffset,
                        bytesPerRow = 16
                    )
                }
                is.Result.Failure -> {
                    _hexData.value = HexEditorData.Error("Failed to load hex data")
                }
            }
        }
    }
    
    fun selectOffset(offset: Long) {
        _selectedOffset.value = offset
    }
    
    fun toggleEditMode() {
        _editMode.value = !_editMode.value
    }
}

sealed class HexEditorData {
    object Empty : HexEditorData()
    data class Loaded(val hexDump: String, val startOffset: Long, val bytesPerRow: Int) : HexEditorData()
    data class Error(val message: String) : HexEditorData()
}

// ============================================================================
// Strings View Model
// ============================================================================

@HiltViewModel
class StringsViewModel @Inject constructor(
    private val analysisRepository: AnalysisRepository
) : ViewModel() {
    
    private val _strings = MutableStateFlow<List<StringEntry>>(emptyList())
    val strings: StateFlow<List<StringEntry>> = _strings.asStateFlow()
    
    private val _filter = MutableStateFlow("")
    val filter: StateFlow<String> = _filter.asStateFlow()
    
    private val _totalCount = MutableStateFlow(0)
    val totalCount: StateFlow<Int> = _totalCount.asStateLoop()
    
    private val _filteredCount = MutableStateFlow(0)
    val filteredCount: StateFlow<Int> = _filteredCount.asStateLoop()
    
    fun loadStrings(fileId: Long) {
        viewModelScope.launch {
            when (val result = analysisRepository.getStrings(fileId)) {
                is Result.Success -> {
                    _strings.value = result.getOrNull() ?: emptyList()
                    _totalCount.value = _strings.value.size
                    applyFilter()
                }
                is.Result.Failure -> {
                    _strings.value = emptyList()
                }
            }
        }
    }
    
    fun setFilter(query: String) {
        _filter.value = query
        applyFilter()
    }
    
    private fun applyFilter() {
        val query = _filter.value
        if (query.isEmpty()) {
            _filteredCount.value = _totalCount.value
        } else {
            _filteredCount.value = _strings.value.count { 
                it.value.contains(query, ignoreCase = true) 
            }
        }
    }
}

// ============================================================================
// Settings View Model
// ============================================================================

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val settingsRepository: SettingsRepository
) : ViewModel() {
    
    private val _settings = MutableStateFlow(UserSettings())
    val settings: StateFlow<UserSettings> = _settings.asStateFlow()
    
    init {
        loadSettings()
    }
    
    private fun loadSettings() {
        viewModelScope.launch {
            when (val result = settingsRepository.getSettings()) {
                is Result.Success -> {
                    _settings.value = result.getOrNull() ?: UserSettings()
                }
                is.Result.Failure -> {
                    // Use defaults
                }
            }
        }
    }
    
    fun updateTheme(mode: ThemeModeValue) {
        viewModelScope.launch {
            _settings.value = _settings.value.copy(themeMode = mode)
            settingsRepository.saveSettings(_settings.value)
        }
    }
    
    fun updateFontSize(size: FontSize) {
        viewModelScope.launch {
            _settings.value = _settings.value.copy(fontSize = size)
            settingsRepository.saveSettings(_settings.value)
        }
    }
    
    fun toggleAutoAnalyze() {
        viewModelScope.launch {
            _settings.value = _settings.value.copy(autoAnalyzeOnOpen = !_settings.value.autoAnalyzeOnOpen)
            settingsRepository.saveSettings(_settings.value)
        }
    }
    
    fun toggleDeepScan() {
        viewModelScope.launch {
            _settings.value = _settings.value.copy(deepScanMode = !_settings.value.deepScanMode)
            settingsRepository.saveSettings(_settings.value)
        }
    }
    
    fun clearCache(): Boolean {
        var success = false
        viewModelScope.launch {
            try {
                com.mobile.idapro.IdaProApplication.getInstance().clearCache()
                success = true
            } catch (e: Exception) {
                success = false
            }
        }
        return success
    }
}
