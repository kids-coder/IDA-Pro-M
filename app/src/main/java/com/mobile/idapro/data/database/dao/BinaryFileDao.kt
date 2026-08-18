package com.mobile.idapro.data.database.dao

import androidx.room.*
import com.mobile.idapro.data.database.entities.BinaryFileEntity
import kotlinx.coroutines.flow.Flow

/**
 * DAO for Binary File operations - Enhanced for v3.0
 */
@Dao
interface BinaryFileDao {

    @Query("SELECT * FROM binary_files ORDER BY lastAccessedAt DESC")
    fun getAllFiles(): Flow<List<BinaryFileEntity>>

    @Query("SELECT * FROM binary_files WHERE id = :fileId")
    suspend fun getFileById(fileId: String): BinaryFileEntity?

    @Query("SELECT * FROM binary_files WHERE path = :path LIMIT 1")
    suspend fun getFileByPath(path: String): BinaryFileEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertFile(file: BinaryFileEntity): Long

    @Update
    suspend fun updateFile(file: BinaryFileEntity)

    @Delete
    suspend fun deleteFile(file: BinaryFileEntity)

    @Query("DELETE FROM binary_files WHERE id = :fileId")
    suspend fun deleteFileById(fileId: String)

    @Query("UPDATE binary_files SET lastAccessedAt = :timestamp WHERE id = :fileId")
    suspend fun updateLastAccessed(fileId: String, timestamp: Long = System.currentTimeMillis())

    @Query("SELECT COUNT(*) FROM binary_files")
    suspend fun getFileCount(): Int
    
    @Query("DELETE FROM binary_files WHERE uploadedAt < :timestamp")
    suspend fun deleteOlderThan(timestamp: Long): Int
}
