package com.mobile.idapro.data.database.dao

import androidx.room.*
import com.mobile.idapro.data.database.entities.AnnotationEntity
import kotlinx.coroutines.flow.Flow

/**
 * DAO for Annotation operations (from IDA Pro Mobile - enhanced) - v3.0
 */
@Dao
interface AnnotationDao {

    @Query("SELECT * FROM annotations WHERE fileId = :fileId ORDER BY address ASC")
    fun getAnnotationsForFile(fileId: String): Flow<List<AnnotationEntity>>

    @Query("SELECT * FROM annotations WHERE fileId = :fileId AND address = :address")
    suspend fun getAnnotation(fileId: String, address: Long): AnnotationEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAnnotation(annotation: AnnotationEntity): Long

    @Update
    suspend fun updateAnnotation(annotation: AnnotationEntity)

    @Delete
    suspend fun deleteAnnotation(annotation: AnnotationEntity)

    @Query("DELETE FROM annotations WHERE fileId = :fileId")
    suspend fun deleteAnnotationsForFile(fileId: String)

    @Query("SELECT COUNT(*) FROM annotations WHERE fileId = :fileId")
    suspend fun getAnnotationCount(fileId: String): Int
    
    @Query("DELETE FROM annotations WHERE uid IN (:uids)")
    suspend fun deleteAnnotationsByIds(uids: List<Long>)
}
