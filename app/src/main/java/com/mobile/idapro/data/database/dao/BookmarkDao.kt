package com.mobile.idapro.data.database.dao

import androidx.room.*
import com.mobile.idapro.data.database.entities.BookmarkEntity
import kotlinx.coroutines.flow.Flow

/**
 * DAO for Bookmark operations (from KTIMAZ-REV - with persistence) - v3.0
 */
@Dao
interface BookmarkDao {

    @Query("SELECT * FROM bookmarks ORDER BY address ASC")
    fun getAllBookmarks(): Flow<List<BookmarkEntity>>

    @Query("SELECT * FROM bookmarks WHERE fileId = :fileId ORDER BY address ASC")
    fun getBookmarksForFile(fileId: String): Flow<List<BookmarkEntity>>

    @Query("SELECT * FROM bookmarks WHERE uid = :bookmarkId")
    suspend fun getBookmarkById(bookmarkId: Long): BookmarkEntity?

    @Query("SELECT * FROM bookmarks WHERE fileId = :fileId AND address = :address LIMIT 1")
    suspend fun getBookmarkAtAddress(fileId: String, address: Long): BookmarkEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertBookmark(bookmark: BookmarkEntity): Long

    @Update
    suspend fun updateBookmark(bookmark: BookmarkEntity)

    @Delete
    suspend fun deleteBookmark(bookmark: BookmarkEntity)

    @Query("DELETE FROM bookmarks WHERE uid = :bookmarkId")
    suspend fun deleteBookmarkById(bookmarkId: Long)

    @Query("DELETE FROM bookmarks WHERE fileId = :fileId")
    suspend fun deleteBookmarksForFile(fileId: String)

    @Query("SELECT COUNT(*) FROM bookmarks WHERE fileId = :fileId")
    suspend fun getBookmarkCountForFile(fileId: String): Int
}
