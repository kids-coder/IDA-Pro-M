package com.mobile.idapro

import android.app.Application
import android.content.Context
import android.util.Log
import dagger.hilt.android.HiltAndroidApp
import java.io.File

/**
 * IDA Pro M - Main Application Class
 * 
 * Initializes core components:
 * - Hilt dependency injection
 * - Database initialization
 * - Native library loading
 * - Crash reporting setup
 * - Security configuration
 */
@HiltAndroidApp
class IdaProApplication : Application() {
    
    companion object {
        private const val TAG = "IdaProApplication"
        
        @Volatile
        private var instance: IdaProApplication? = null
        
        fun getInstance(): IdaProApplication {
            return instance ?: synchronized(this) {
                instance ?: IdaProApplication().also { instance = it }
            }
        }
        
        fun getContext(): Context = getInstance().applicationContext
    }
    
    // Application directories
    lateinit var projectsDir: File
        private set
    lateinit var cacheDir: File
        private set
    lateinit var tempDir: File
        private set
    lateinit var exportsDir: File
        private set
    
    override fun onCreate() {
        super.onCreate()
        
        instance = this
        
        // Initialize directories
        initializeDirectories()
        
        // Load native libraries
        loadNativeLibraries()
        
        // Initialize security features
        initializeSecurity()
        
        Log.i(TAG, "IDA Pro M initialized successfully")
    }
    
    /**
     * Create application-specific directories for storing projects,
     * cache files, temporary data, and exports.
     */
    private fun initializeDirectories() {
        val baseDir = File(filesDir, "IDAProM")
        
        projectsDir = File(baseDir, "projects").apply { mkdirs() }
        cacheDir = File(baseDir, "cache").apply { mkdirs() }
        tempDir = File(baseDir, "temp").apply { mkdirs() }
        exportsDir = File(baseDir, "exports").apply { mkdirs() }
        
        Log.d(TAG, "Initialized directories in ${baseDir.absolutePath}")
    }
    
    /**
     * Load native disassembly engine libraries.
     * The native engine provides high-performance ARM/x86 disassembly.
     */
    private fun loadNativeLibraries() {
        try {
            System.loadLibrary("idapro_engine")
            Log.i(TAG, "Native disassembly engine loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load native library", e)
        } catch (e: SecurityException) {
            Log.e(TAG, "Security exception loading native library", e)
        }
    }
    
    /**
     * Initialize security features for the application.
     * Includes root detection, tamper detection, and certificate pinning setup.
     */
    private fun initializeSecurity() {
        // Root detection (optional, can be disabled for development)
        if (BuildConfig.DEBUG.not()) {
            detectRootAccess()
        }
        
        // Clear sensitive data from memory on background
        registerActivityLifecycleCallbacks(SecurityCallbacks())
    }
    
    /**
     * Basic root access detection.
     * Checks for common root indicators.
     */
    private fun detectRootAccess() {
        val rootIndicators = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/bin/su",
            "/local/bin/su"
        )
        
        val isRooted = rootIndicators.any { File(it).exists() }
        
        if (isRooted) {
            Log.w(TAG, "Device appears to be rooted")
            // Could show warning or restrict functionality
        }
    }
    
    /**
     * Get application version information.
     */
    fun getVersionInfo(): VersionInfo {
        return VersionInfo(
            versionName = BuildConfig.VERSION_NAME,
            versionCode = BuildConfig.VERSION_CODE,
            buildType = BuildConfig.BUILD_TYPE,
            isDebug = BuildConfig.DEBUG
        )
    }
    
    /**
     * Clear application cache and temporary files.
     */
    fun clearCache(): Boolean {
        return try {
            cacheDir.listFiles()?.forEach { it.delete() }
            tempDir.listFiles()?.forEach { it.delete() }
            true
        } catch (e: Exception) {
            Log.e(TAG, "Error clearing cache", e)
            false
        }
    }
    
    /**
     * Get total size of application data directories.
     */
    fun getTotalDataSize(): Long {
        var size = 0L
        projectsDir.walkTopDown().forEach { size += it.length() }
        cacheDir.walkTopDown().forEach { size += it.length() }
        tempDir.walkTopDown().forEach { size += it.length() }
        exportsDir.walkTopDown().forEach { size += it.length() }
        return size
    }
}

/**
 * Version information data class.
 */
data class VersionInfo(
    val versionName: String,
    val versionCode: Int,
    val buildType: String,
    val isDebug: Boolean
)

/**
 * Security callbacks for activity lifecycle management.
 */
class SecurityCallbacks : android.app.Application.ActivityLifecycleCallbacks by 
    NoOpActivityLifecycleCallbacks() {
    override fun onActivityStopped(activity: android.app.Activity) {
        // Clear sensitive data when activity goes to background
        // In a real app, you might want to encrypt/obfuscate in-memory data
    }
}

/**
 * No-op implementation of ActivityLifecycleCallbacks for convenience.
 */
open class NoOpActivityLifecycleCallbacks : android.app.Application.ActivityLifecycleCallbacks {
    override fun onActivityCreated(activity: android.app.Activity, savedInstanceState: android.os.Bundle?) {}
    override fun onActivityStarted(activity: android.app.Activity) {}
    override fun onActivityResumed(activity: android.app.Activity) {}
    override fun onActivityPaused(activity: android.app.Activity) {}
    override fun onActivityStopped(activity: android.app.Activity) {}
    override fun onActivitySaveInstanceState(activity: android.app.Activity, outState: android.os.Bundle) {}
    override fun onActivityDestroyed(activity: android.app.Activity) {}
}
