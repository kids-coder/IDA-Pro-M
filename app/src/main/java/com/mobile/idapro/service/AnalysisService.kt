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
import com.mobile.idapro.native.NativeBinaryAnalyzer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

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
    private val serviceScope = CoroutineScope(Dispatchers.Default + Job())
    private var analysisJob: Job? = null

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
        if (isAnalyzing || filePath == null) return
        
        isAnalyzing = true
        startForeground(NOTIFICATION_ID, createProgressNotification(0, "Starting analysis..."))
        
        // Launch analysis in background coroutine
        analysisJob = serviceScope.launch {
            try {
                val analyzer = NativeBinaryAnalyzer.getInstance()
                
                // Step 1: Load binary file
                updateProgress(10, "Loading binary file...")
                if (!analyzer.loadBinary(filePath)) {
                    updateProgress(0, "Failed to load binary file")
                    stopAnalysis()
                    return@launch
                }
                
                // Step 2: Get file info
                updateProgress(25, "Analyzing file information...")
                val fileInfo = analyzer.getFileInfo(filePath)
                
                // Step 3: Detect functions
                updateProgress(50, "Detecting functions...")
                val functions = analyzer.detectFunctions()
                
                // Step 4: Get symbols and sections
                updateProgress(75, "Extracting symbols...")
                val symbols = analyzer.getSymbols()
                val sections = analyzer.getSectionNames()
                
                // Step 5: Complete analysis
                updateProgress(100, "Analysis complete")
                
                // Cleanup
                analyzer.cleanup()
                
            } catch (e: Exception) {
                e.printStackTrace()
                updateProgress(0, "Analysis failed: ${e.message}")
            } finally {
                stopAnalysis()
            }
        }

    /**
     * Stop ongoing analysis
     */
    private fun stopAnalysis() {
        isAnalyzing = false
        analysisJob?.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        analysisJob?.cancel()
        serviceScope.coroutineContext[Job]?.cancel()
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
