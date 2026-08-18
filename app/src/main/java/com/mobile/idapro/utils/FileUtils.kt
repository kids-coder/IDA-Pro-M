package com.mobile.idapro.utils

import android.content.Context
import android.net.Uri
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.*

/**
 * File Utilities (Merged from both projects) - v3.0
 * Secure file handling for binary analysis with:
 * - Path traversal prevention
 * - Secure file copying
 * - SHA-256 checksum calculation
 */
object FileUtils {

    private const val APP_DIR = "ida_pro_analysis"
    private const val MAX_FILE_NAME_LENGTH = 255
    
    /**
     * Get file name from URI
     */
    fun getFileName(context: Context, uri: Uri): String? {
        var fileName: String? = null
        
        if (uri.scheme == "content") {
            context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (cursor.moveToFirst() && nameIndex >= 0) {
                    fileName = cursor.getString(nameIndex)
                }
            }
        }
        
        if (fileName == null) {
            fileName = uri.path?.substringAfterLast('/')
        }
        
        return fileName?.take(MAX_FILE_NAME_LENGTH) ?: "unknown_${System.currentTimeMillis()}"
    }

    /**
     * Copy file to app's internal storage securely
     * Prevents path traversal attacks
     */
    fun copyToAppStorage(context: Context, uri: Uri, fileName: String): File? {
        return try {
            val appDir = File(context.filesDir, APP_DIR)
            if (!appDir.exists()) {
                appDir.mkdirs()
            }

            // Sanitize filename to prevent path traversal
            val safeName = sanitizeFileName(fileName)
            val destFile = File(appDir, safeName)

            context.contentResolver.openInputStream(uri)?.use { inputStream ->
                FileOutputStream(destFile).use { outputStream ->
                    inputStream.copyTo(outputStream)
                }
            }

            destFile
        } catch (e: SecurityException) {
            e.printStackTrace()
            null
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
    
    /**
     * Sanitize filename to prevent path traversal attacks
     */
    private fun sanitizeFileName(fileName: String): String {
        // Remove path separators and parent directory references
        var sanitized = fileName.replace(Regex("[/\\\\]"), "_")
            .replace("^\\.+", "")
            .replace("\\.\\.[/\\\\]".toRegex(), "_")
        
        // Limit length and remove null bytes
        sanitized = sanitized
            .replace("\u0000", "")
            .take(MAX_FILE_NAME_LENGTH)
        
        // Ensure it has a valid name
        if (sanitized.isBlank()) {
            sanitized = "file_${System.currentTimeMillis()}"
        }
        
        return sanitized
    }
    
    /**
     * Calculate SHA-256 checksum of a file
     */
    fun calculateFileChecksum(file: File): String? {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().buffered(8192).use { input ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            
            // Convert to hex string
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * Get app storage directory
     */
    fun getAppStorageDir(context: Context): File {
        val dir = File(context.filesDir, APP_DIR)
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    /**
     * Delete file from app storage
     */
    fun deleteFromAppStorage(context: Context, fileName: Boolean): Boolean {
        return try {
            val file = File(context.filesDir, "$APP_DIR/$fileName")
            if (file.exists()) file.delete() else false
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Format timestamp to readable date
     */
    fun formatTimestamp(timestamp: Long): String {
        return SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault())
            .format(Date(timestamp))
    }

    /**
     * Get file size as human-readable string
     */
    fun formatFileSize(bytes: Long): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB"
        bytes < 1024 * 1024 * 1024 -> "${bytes / (1024 * 1024)} MB"
        else -> "%.2f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
    }
    
    /**
     * Validate that a file is within app storage (security check)
     */
    fun isFileInAppStorage(context: Context, file: File): Boolean {
        val appDir = getAppStorageDir(context)
        return file.canonicalPath.startsWith(appDir.canonicalPath)
    }
}
