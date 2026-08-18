package com.mobile.idapro.data.repository

import com.mobile.idapro.data.local.*
import com.mobile.idapro.data.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * IDA Pro M - Repository Layer
 * 
 * Provides clean API for data access, combining Room database
 * with native disassembly engine operations.
 */

// ============================================================================
// File Repository
// ============================================================================

@Singleton
class FileRepository @Inject constructor(
    private val fileDao: LoadedFileDao,
    private val analysisResultDao: AnalysisResultDao,
    private val functionDao: FunctionDao,
    private val stringEntryDao: StringEntryDao
) {
    
    /**
     * Get all loaded files sorted by last accessed time.
     */
    suspend fun getAllFiles(): Result<List<LoadedFile>> = withContext(Dispatchers.IO) {
        try {
            Result.success(fileDao.getAllFiles())
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get recent files (last N accessed).
     */
    suspend fun getRecentFiles(limit: Int = 10): Result<List<LoadedFile>> = withContext(Dispatchers.IO) {
        try {
            Result.success(fileDao.getRecentFiles(limit))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get a specific file by ID.
     */
    suspend fun getFileById(id: Long): Result<LoadedFile?> = withContext(Dispatchers.IO) {
        try {
            Result.success(fileDao.getFileById(id))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get a specific file by path.
     */
    suspend fun getFileByPath(path: String): Result<LoadedFile?> = withContext(Dispatchers.IO) {
        try {
            Result.success(fileDao.getFileByPath(path))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Insert or update a file record.
     */
    suspend fun saveFile(file: LoadedFile): Result<Long> = withContext(Dispatchers.IO) {
        try {
            val id = if (file.id == 0L) {
                fileDao.insertFile(file)
            } else {
                fileDao.updateFile(file)
                file.id
            }
            Result.success(id)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Delete a file and all associated data (analysis results, functions, strings).
     */
    suspend fun deleteFile(fileId: Long): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            // Delete in correct order due to foreign key constraints
            stringEntryDao.deleteStringsForFile(fileId)
            functionDao.deleteFunctionsForFile(fileId)
            analysisResultDao.deleteResultsForFile(fileId)
            fileDao.deleteFileById(fileId)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Update file's access timestamp.
     */
    suspend fun updateLastAccessed(fileId: Long): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            fileDao.updateFileStatus(
                id = fileId,
                timestamp = System.currentTimeMillis(),
                status = AnalysisStatus.NOT_STARTED,
                progress = 0
            )
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get total count of loaded files.
     */
    suspend fun getFileCount(): Result<Int> = withContext(Dispatchers.IO) {
        try {
            Result.success(fileDao.getFileCount())
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

// ============================================================================
// Analysis Repository
// ============================================================================

@Singleton
class AnalysisRepository @Inject constructor(
    private val analysisResultDao: AnalysisResultDao,
    private val functionDao: FunctionDao,
    private val stringEntryDao: StringEntryDao
) {
    
    /**
     * Get analysis result for a file.
     */
    suspend fun getAnalysisResult(fileId: Long): Result<AnalysisResult?> = withContext(Dispatchers.IO) {
        try {
            Result.success(analysisResultDao.getResultByFileId(fileId))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Create new analysis result record.
     */
    suspend fun createAnalysisResult(result: AnalysisResult): Result<Long> = withContext(Dispatchers.IO) {
        try {
            Result.success(analysisResultDao.insertResult(result))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Update analysis progress.
     */
    suspend fun updateProgress(resultId: Long, progress: Int, phase: String): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            analysisResultDao.updateProgress(resultId, progress, phase)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Save functions extracted during analysis.
     */
    suspend fun saveFunctions(functions: List<Function>): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            functionDao.insertFunctions(functions)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get all functions for a file.
     */
    suspend fun getFunctions(fileId: Long): Result<List<Function>> = withContext(Dispatchers.IO) {
        try {
            Result.success(functionDao.getFunctionsByFileId(fileId))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get function containing a specific address.
     */
    suspend fun getFunctionContainingAddress(fileId: Long, address: Long): Result<Function?> = withContext(Dispatchers.IO) {
        try {
            Result.success(functionDao.getFunctionContaining(fileId, address))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get function at exact address.
     */
    suspend fun getFunctionAtAddress(fileId: Long, address: Long): Result<Function?> = withContext(Dispatchers.IO) {
        try {
            Result.success(functionDao.getFunctionAtAddress(fileId, address))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get function by its database ID.
     */
    suspend fun getFunctionById(id: Long): Result<Function?> = withContext(Dispatchers.IO) {
        try {
            Result.success(functionDao.getFunctionById(id))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get total function count for a file.
     */
    suspend fun getFunctionCount(fileId: Long): Result<Int> = withContext(Dispatchers.IO) {
        try {
            Result.success(functionDao.getFunctionCount(fileId))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Save strings extracted during analysis.
     */
    suspend fun saveStrings(strings: List<StringEntry>): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            // Insert in batches to avoid SQLite limits
            strings.chunked(100).forEach { batch ->
                stringEntryDao.insertStrings(batch)
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get all strings for a file.
     */
    suspend fun getStrings(fileId: Long): Result<List<StringEntry>> = withContext(Dispatchers.IO) {
        try {
            Result.success(stringEntryDao.getStringsByFileId(fileId))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Search strings by value.
     */
    suspend fun searchStrings(fileId: Long, query: String): Result<List<StringEntry>> = withContext(Dispatchers.IO) {
        try {
            Result.success(stringEntryDao.searchStrings(fileId, query))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get string at specific address.
     */
    suspend fun getStringAtAddress(fileId: Long, address: Long): Result<StringEntry?> = withContext(Dispatchers.IO) {
        try {
            Result.success(stringEntryDao.getStringAtAddress(fileId, address))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get total string count for a file.
     */
    suspend fun getStringCount(fileId: Long): Result<Int> = withContext(Dispatchers.IO) {
        try {
            Result.success(stringEntryDao.getStringCount(fileId))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

// ============================================================================
// Settings Repository
// ============================================================================

@Singleton
class SettingsRepository @Inject constructor(
    private val settingsDao: UserSettingsDao
) {
    
    /**
     * Get current user settings.
     */
    suspend fun getSettings(): Result<UserSettings> = withContext(Dispatchers.IO) {
        try {
            val settings = settingsDao.getSettings() ?: UserSettings()
            Result.success(settings)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Save/update user settings.
     */
    suspend fun saveSettings(settings: UserSettings): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            settingsDao.insertSettings(settings)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Reset settings to defaults.
     */
    suspend fun resetToDefaults(): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            settingsDao.clearSettings()
            settingsDao.insertSettings(UserSettings())
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
