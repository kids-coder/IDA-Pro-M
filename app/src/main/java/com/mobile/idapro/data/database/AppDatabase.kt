package com.mobile.idapro.data.database

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.mobile.idapro.data.database.dao.AnnotationDao
import com.mobile.idapro.data.database.dao.BinaryFileDao
import com.mobile.idapro.data.database.dao.BookmarkDao
import com.mobile.idapro.data.database.entities.*

/**
 * Room Database for IDA Pro M (Merged) - v3.0
 * 
 * Entities from both projects:
 * - BinaryFileEntity: File metadata (IDA Pro Mobile)
 * - AnnotationEntity: User annotations (IDA Pro Mobile)
 * - BookmarkEntity: Navigation bookmarks (KTIMAZ-REV)
 */
@Database(
    entities = [
        BinaryFileEntity::class,
        AnnotationEntity::class,
        BookmarkEntity::class
    ],
    version = 3,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    
    abstract fun binaryFileDao(): BinaryFileDao
    abstract fun annotationDao(): AnnotationDao
    abstract fun bookmarkDao(): BookmarkDao
}

/**
 * Type converters for Room database
 */
class Converters {
    // Add converters for complex types if needed in future
}
