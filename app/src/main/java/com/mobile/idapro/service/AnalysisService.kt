package com.mobile.idapro.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.mobile.idapro.R

/**
 * IDA Pro M Analysis Service
 * 
 * Foreground service for long-running binary analysis operations.
 * Runs analysis tasks in the background and shows progress via notifications.
 * 
 * Type: dataSync (for background data synchronization)
 */
class AnalysisService : Service() {

    private var isAnalyzing = false
    private lateinit var notificationManager: NotificationManager

    override fun onCreate() {
        super.onCreate()
        notificationManager = getSystemService(NotificationManager::class.java)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START_ANALYSIS -> startAnalysis(intent.getStringExtra(EXTRA_FILE_PATH))
            ACTION_STOP_ANALYSIS -> stopAnalysis()
            else -> {}
        }
        return START_STICKY
    }

    override fun onBind(intent: IBinder?): IBinder? = null

    /**
     * Start binary analysis in foreground
     */
    private fun startAnalysis(filePath: String?) {
        if (isAnalyzing) return
        
        isAnalyzing = true
        startForeground(NOTIFICATION_ID, createProgressNotification(0, "Starting analysis..."))
        
        // TODO: Implement actual analysis logic
        // This would call the native disassembler and update progress
    }

    /**
     * Stop ongoing analysis
     */
    private fun stopAnalysis() {
        isAnalyzing = false
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /**
     * Update progress notification
     */
    fun updateProgress(progress: Int, message: String) {
        if (!isAnalyzing) return
        
        notificationManager.notify(
            NOTIFICATION_ID,
            createProgressNotification(progress, message)
        )
    }

    /**
     * Create notification channel for Android O+
     */
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel(
                CHANNEL_ID,
                "Analysis Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows binary analysis progress"
                setShowBadge(false)
                notificationManager.createNotificationChannel(this)
            }
        }
    }

    /**
     * Create progress notification
     */
    private fun createProgressNotification(progress: Int, message: String): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("IDA Pro M Analysis")
            .setContentText(message)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setProgress(100, progress, progress == 0)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_START_ANALYSIS = "com.mobile.idapro.action.ANALYZE"
        const val ACTION_STOP_ANALYSIS = "com.mobile.idapro.action.STOP_ANALYSIS"
        const val EXTRA_FILE_PATH = "extra_file_path"
        
        private const val CHANNEL_ID = "analysis_service_channel"
        private const val NOTIFICATION_ID = 1001
    }
}
