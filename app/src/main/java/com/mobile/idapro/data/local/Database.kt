package com.mobile.idapro.data.local

import androidx.room.*
import com.mobile.idapro.data.model.*

/**
 * IDA Pro M - Room Database
 * 
 * Local database for storing analysis results, file metadata,
 * extracted strings, functions, and user preferences.
 */

@Database(
    entities = [
        LoadedFile::class,
        AnalysisResult::class,
        Function::class,
        StringEntry::class,
        UserSettings::class
    ],
    version = 3,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    
    abstract fun loadedFileDao(): LoadedFileDao
    abstract fun analysisResultDao(): AnalysisResultDao
    abstract fun functionDao(): FunctionDao
    abstract fun stringEntryDao(): StringEntryDao
    abstract fun userSettingsDao(): UserSettingsDao
    
    companion object {
        const val DATABASE_NAME = "idapro_m_database"
    }
}

// ============================================================================
// Data Access Objects (DAOs)
// ============================================================================

/**
 * DAO for loaded files.
 */
@Dao
interface LoadedFileDao {
    
    @Query("SELECT * FROM loaded_files ORDER BY lastAccessed DESC")
    suspend fun getAllFiles(): List<LoadedFile>
    
    @Query("SELECT * FROM loaded_files WHERE id = :id")
    suspend fun getFileById(id: Long): LoadedFile?
    
    @Query("SELECT * FROM loaded_files WHERE filePath = :path")
    suspend fun getFileByPath(path: String): LoadedFile?
    
    @Query("SELECT * FROM loaded_files ORDER BY loadTimestamp DESC LIMIT :limit")
    suspend fun getRecentFiles(limit: Int = 10): List<LoadedFile>
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertFile(file: LoadedFile): Long
    
    @Update
    suspend fun updateFile(file: LoadedFile)
    
    @Delete
    suspend fun deleteFile(file: LoadedFile)
    
    @Query("DELETE FROM loaded_files WHERE id = :id")
    suspend fun deleteFileById(id: Long)
    
    @Query("UPDATE loaded_files SET lastAccessed = :timestamp, analysisStatus = :status, analysisProgress = :progress WHERE id = :id")
    suspend fun updateFileStatus(id: Long, timestamp: Long, status: AnalysisStatus, progress: Int)
    
    @Query("SELECT COUNT(*) FROM loaded_files")
    suspend fun getFileCount(): Int
    
    @Query("SELECT SUM(fileSize) FROM loaded_files")
    suspend fun getTotalSizeUsed(): Long?
}

/**
 * DAO for analysis results.
 */
@Dao
interface AnalysisResultDao {
    
    @Query("SELECT * FROM analysis_results WHERE fileId = :fileId")
    suspend fun getResultByFileId(fileId: Long): AnalysisResult?
    
    @Query("SELECT * FROM analysis_results WHERE id = :id")
    suspend fun getResultById(id: Long): AnalysisResult?
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertResult(result: AnalysisResult): Long
    
    @Update
    suspend fun updateResult(result: AnalysisResult)
    
    @Query("DELETE FROM analysis_results WHERE fileId = :fileId")
    suspend fun deleteResultsForFile(fileId: Long)
    
    @Query("UPDATE analysis_results SET progressPercent = :progress, currentPhase = :phase WHERE id = :id")
    suspend fun updateProgress(id: Long, progress: Int, phase: String)
}

/**
 * DAO for functions.
 */
@Dao
interface FunctionDao {
    
    @Query("SELECT * FROM functions WHERE fileId = :fileId ORDER BY startAddress ASC")
    suspend fun getFunctionsByFileId(fileId: Long): List<Function>
    
    @Query("SELECT * FROM functions WHERE fileId = :fileId AND startAddress <= :address AND endAddress >= :address LIMIT 1")
    suspend fun getFunctionContaining(fileId: Long, address: Long): Function?
    
    @Query("SELECT * FROM functions WHERE fileId = :fileId AND startAddress = :address LIMIT 1")
    suspend fun getFunctionAtAddress(fileId: Long, address: Long): Function?
    
    @Query("SELECT * FROM functions WHERE id = :id")
    suspend fun getFunctionById(id: Long): Function?
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertFunction(function: Function): Long
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertFunctions(functions: List<Function>)
    
    @Update
    suspend fun updateFunction(function: Function)
    
    @Delete
    suspend fun deleteFunction(function: Function)
    
    @Query("DELETE FROM functions WHERE fileId = :fileId")
    suspend fun deleteFunctionsForFile(fileId: Long)
    
    @Query("SELECT COUNT(*) FROM functions WHERE fileId = :fileId")
    suspend fun getFunctionCount(fileId: Long): Int
}

/**
 * DAO for string entries.
 */
@Dao
interface StringEntryDao {
    
    @Query("SELECT * FROM strings WHERE fileId = :fileId ORDER BY address ASC")
    suspend fun getStringsByFileId(fileId: Long): List<StringEntry>
    
    @Query("SELECT * FROM strings WHERE fileId = :fileId AND value LIKE '%' || :query || '%' ORDER BY address ASC")
    suspend fun searchStrings(fileId: Long, query: String): List<StringEntry>
    
    @Query("SELECT * FROM strings WHERE fileId = :fileId AND address = :address LIMIT 1")
    suspend fun getStringAtAddress(fileId: Long, address: Long): StringEntry?
    
    @Query("SELECT * FROM strings WHERE id = :id")
    suspend fun getStringById(id: Long): StringEntry?
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertString(string: StringEntry): Long
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertStrings(strings: List<StringEntry>)
    
    @Update
    suspend fun updateString(string: StringEntry)
    
    @Delete
    suspend fun deleteString(string: StringEntry)
    
    @Query("DELETE FROM strings WHERE fileId = :fileId")
    suspend fun deleteStringsForFile(fileId: Long)
    
    @Query("SELECT COUNT(*) FROM strings WHERE fileId = :fileId")
    suspend fun getStringCount(fileId: Long): Int
}

/**
 * DAO for user settings.
 */
@Dao
interface UserSettingsDao {
    
    @Query("SELECT * FROM user_settings WHERE id = 1")
    suspend fun getSettings(): UserSettings?
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSettings(settings: UserSettings)
    
    @Update
    suspend fun updateSettings(settings: UserSettings)
    
    @Query("DELETE FROM user_settings")
    suspend fun clearSettings()
}

// ============================================================================
// Type Converters for Room
// ============================================================================

/**
 * Type converters for complex types in Room database.
 */
class Converters {
    
    @TypeConverter
    fun fromBinaryFormat(format: BinaryFormat): String = format.name
    
    @TypeConverter
    fun toBinaryFormat(value: String): BinaryFormat = BinaryFormat.valueOf(value)
    
    @TypeConverter
    fun fromArchitecture(arch: Architecture): String = arch.name
    
    @TypeConverter
    fun toArchitecture(value: String): Architecture = Architecture.valueOf(value)
    
    @TypeConverter
    fun fromAnalysisStatus(status: AnalysisStatus): String = status.name
    
    @TypeConverter
    fun toAnalysisStatus(value: String): AnalysisStatus = AnalysisStatus.valueOf(value)
    
    @TypeConverter
    fun fromFunctionType(type: FunctionType): String = type.name
    
    @TypeConverter
    fun toFunctionType(value: String): FunctionType = FunctionType.valueOf(value)
    
    @TypeConverter
    fun fromCallingConvention(cc: CallingConvention): String = cc.name
    
    @TypeConverter
    fun toCallingConvention(value: String): CallingConvention = CallingConvention.valueOf(value)
    
    @TypeConverter
    fun fromStringEncoding(encoding: StringEncoding): String = encoding.name
    
    @TypeConverter
    fun toStringEncoding(value: String): StringEncoding = StringEncoding.valueOf(value)
    
    @TypeConverter
    fun fromStringType(type: StringType): String = type.name
    
    @TypeConverter
    fun toStringType(value: String): StringType = StringType.valueOf(value)
    
    @TypeConverter
    fun fromThemeModeValue(mode: ThemeModeValue): String = mode.name
    
    @TypeConverter
    fun toThemeModeValue(value: String): ThemeModeValue = ThemeModeValue.valueOf(value)
    
    @TypeConverter
    fun fromFontSize(size: FontSize): String = size.name
    
    @TypeConverter
    fun toFontSize(value: String): FontSize = FontSize.valueOf(value)
    
    @TypeConverter
    fun fromSectionType(type: SectionType): String = type.name
    
    @TypeConverter
    fun toSectionType(value: String): SectionType = SectionType.valueOf(value)
    
    @TypeConverter
    fun fromStringList(list: List<String>): String = list.joinToString("|||")
    
    @TypeConverter
    fun toStringList(value: String): List<String> = 
        if (value.isEmpty()) emptyList() else value.split("|||")
}
