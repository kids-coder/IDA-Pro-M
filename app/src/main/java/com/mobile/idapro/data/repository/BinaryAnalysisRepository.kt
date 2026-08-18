package com.mobile.idapro.data.repository

import com.mobile.idapro.data.database.AppDatabase
import com.mobile.idapro.data.database.entities.*
import com.mobile.idapro.data.model.*
import kotlinx.coroutines.flow.Flow

/**
 * Binary Analysis Repository (Merged from both projects) - v3.0
 * 
 * Provides clean API for data access combining:
 * - File management (IDA Pro Mobile)
 * - Annotations (IDA Pro Mobile)  
 * - Bookmarks (KTIMAZ-REV - now persistent)
 */
class BinaryAnalysisRepository(private val database: AppDatabase) {

    // === Binary File Operations ===
    
    fun getAllBinaryFiles(): Flow<List<BinaryFileEntity>> = database.binaryFileDao().getAllFiles()
    
    suspend fun getBinaryFileById(id: String): BinaryFileEntity? = database.binaryFileDao().getFileById(id)
    
    suspend fun getBinaryFileByPath(path: String): BinaryFileEntity? = database.binaryFileDao().getFileByPath(path)
    
    suspend fun insertBinaryFile(file: BinaryFileEntity): Long = database.binaryFileDao().insertFile(file)
    
    suspend fun updateBinaryFile(file: BinaryFileEntity) = database.binaryFileDao().updateFile(file)
    
    suspend fun deleteBinaryFile(id: String) {
        // Cascade delete annotations and bookmarks
        database.annotationDao().deleteAnnotationsForFile(id)
        database.bookmarkDao().deleteBookmarksForFile(id)
        database.binaryFileDao().deleteFileById(id)
    }
    
    suspend fun updateLastAccessed(id: String) = database.binaryFileDao().updateLastAccessed(id)

    // === Annotation Operations ===
    
    fun getAnnotationsForFile(fileId: String): Flow<List<AnnotationEntity>> = 
        database.annotationDao().getAnnotationsForFile(fileId)
    
    suspend fun getAnnotation(fileId: String, address: Long): AnnotationEntity? = 
        database.annotationDao().getAnnotation(fileId, address)
    
    suspend fun insertAnnotation(annotation: AnnotationEntity): Long = 
        database.annotationDao().insertAnnotation(annotation)
    
    suspend fun updateAnnotation(annotation: AnnotationEntity) = 
        database.annotationDao().updateAnnotation(annotation)
    
    suspend fun deleteAnnotation(annotation: AnnotationEntity) = 
        database.annotationDao().deleteAnnotation(annotation)

    // === Bookmark Operations (from KTIMAZ-REV - now persistent) ===
    
    fun getAllBookmarks(): Flow<List<BookmarkEntity>> = database.bookmarkDao().getAllBookmarks()
    
    fun getBookmarksForFile(fileId: String): Flow<List<BookmarkEntity>> = 
        database.bookmarkDao().getBookmarksForFile(fileId)
    
    suspend fun insertBookmark(bookmark: BookmarkEntity): Long = 
        database.bookmarkDao().insertBookmark(bookmark)
    
    suspend fun updateBookmark(bookmark: BookmarkEntity) = 
        database.bookmarkDao().updateBookmark(bookmark)
    
    suspend fun deleteBookmark(bookmark: BookmarkEntity) = 
        database.bookmarkDao().deleteBookmark(bookmark)
    
    suspend fun deleteBookmarkById(id: Long) = database.bookmarkDao().deleteBookmarkById(id)
}
