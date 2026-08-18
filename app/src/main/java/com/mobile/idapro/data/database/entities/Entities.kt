package com.mobile.idapro.data.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Binary File Entity (from IDA Pro Mobile - enhanced for v3.0)
 * Stores metadata about analyzed binary files
 */
@Entity(tableName = "binary_files")
data class BinaryFileEntity(
    @PrimaryKey
    val id: String,
    val name: String,
    val path: String,
    val size: Long,
    val architecture: String = "Unknown",
    val fileType: String = "Unknown",
    val entryPoint: Long = 0,
    val uploadedAt: Long = System.currentTimeMillis(),
    val checksum: String? = null,
    val lastAccessedAt: Long = System.currentTimeMillis()
)

/**
 * Annotation Entity (from IDA Pro Mobile - enhanced)
 * User annotations/comments on disassembled instructions
 */
@Entity(
    tableName = "annotations",
    foreignKeys = [
        androidx.room.ForeignKey(
            entity = BinaryFileEntity::class,
            parentColumns = ["id"],
            childColumns = ["fileId"],
            onDelete = androidx.room.ForeignKey.CASCADE
        )
    ],
    indices = [androidx.room.Index(value = ["fileId", "address"], unique = true)]
)
data class AnnotationEntity(
    @PrimaryKey(autoGenerate = true)
    val uid: Long = 0,
    val fileId: String,
    val address: Long,
    val comment: String,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
)

/**
 * Bookmark Entity (from KTIMAZ-REV - merged with persistence)
 * User bookmarks for quick navigation
 */
@Entity(
    tableName = "bookmarks",
    foreignKeys = [
        androidx.room.ForeignKey(
            entity = BinaryFileEntity::class,
            parentColumns = ["id"],
            childColumns = ["fileId"],
            onDelete = androidx.room.ForeignKey.CASCADE
        )
    ]
)
data class BookmarkEntity(
    @PrimaryKey(autoGenerate = true)
    val uid: Long = 0,
    val fileId: String,
    val address: Long,
    val name: String,
    val comment: String = "",
    val createdAt: Long = System.currentTimeMillis()
)
