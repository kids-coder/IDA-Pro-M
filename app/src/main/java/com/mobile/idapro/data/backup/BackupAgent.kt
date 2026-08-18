package com.mobile.idapro.data.backup

import android.app.backup.BackupAgentHelper
import android.app.backup.FileBackupHelper
import android.app.backup.SharedPreferencesBackupHelper

/**
 * IDA Pro M Backup Agent
 * 
 * Handles backup and restore of:
 * - User preferences/settings
 * - Recent files list
 * - Analysis cache data
 */
class IdaProBackupAgent : BackupAgentHelper() {

    override fun onCreate() {
        // Backup shared preferences (user settings)
        SharedPreferencesBackupHelper(
            this,
            "${packageName}_preferences"
        ).also {
            addHelper(PREFERENCES_BACKUP_KEY, it)
        }

        // Backup recent files database
        FileBackupHelper(
            this,
            "../databases/idapro_database"
        ).also {
            addHelper(DATABASE_BACKUP_KEY, it)
        }
    }

    companion object {
        const val PREFERENCES_BACKUP_KEY = "preferences_backup"
        const val DATABASE_BACKUP_KEY = "database_backup"
    }
}
