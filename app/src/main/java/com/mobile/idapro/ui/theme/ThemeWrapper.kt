package com.mobile.idapro.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.toArgb
import androidx.core.view.WindowCompat
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.edit
import com.google.accompanist.systemuicontroller.rememberSystemUiController
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking

/**
 * Theme configuration options for IDA Pro M.
 */
enum class ThemeMode {
    LIGHT,
    DARK,
    SYSTEM,
    AMOLED;

    companion object {
        fun fromValue(value: Int): ThemeMode = entries.getOrElse(value) { SYSTEM }
        fun toValue(mode: ThemeMode): Int = mode.ordinal
    }
}

/**
 * Current theme mode state (can be persisted).
 */
var currentThemeMode by mutableStateOf(ThemeMode.SYSTEM)
    private set

/**
 * Main IDA Pro M Theme composable.
 * 
 * Applies the selected color scheme based on user preference or system setting.
 * Handles status bar and navigation bar colors for edge-to-edge display.
 */
@Composable
fun IDAProMTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    themeMode: ThemeMode = currentThemeMode,
    content: @Composable () -> Unit
) {
    val actualDarkTheme = when (themeMode) {
        ThemeMode.LIGHT -> false
        ThemeMode.DARK, ThemeMode.AMOLED -> true
        ThemeMode.SYSTEM -> darkTheme
    }
    
    val colorScheme = when {
        actualDarkTheme && themeMode == ThemeMode.AMOLED -> AmoledColorScheme
        actualDarkTheme -> DarkColorScheme
        else -> LightColorScheme
    }
    
    val systemUiController = rememberSystemUiController()
    
    // Apply status bar and navigation bar colors
    SideEffect {
        systemUiController.setStatusBarColor(
            color = colorScheme.surface,
            darkIcons = !actualDarkTheme
        )
        systemUiController.setNavigationBarColor(
            color = colorScheme.surface,
            darkIcons = !actualDarkTheme
        )
    }
    
    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        shapes = Shapes,
        content = content
    )
}

/**
 * Update the current theme mode.
 */
fun setThemeMode(mode: ThemeMode) {
    currentThemeMode = mode
}

/**
 * Custom typography for IDA Pro M.
 * Optimized for code/disassembly viewing with monospace fonts for data display.
 */
val Typography = androidx.compose.material3.Typography(
    // Use monospace font for code-like displays
)

/**
 * Custom shapes for IDA Pro M components.
 */
val Shapes = androidx.compose.material3.Shapes(
    // Rounded corners for cards and dialogs
)

/**
 * Persist theme preference to DataStore.
 */
suspend fun saveThemePreference(dataStore: DataStore<Preferences>, mode: ThemeMode) {
    dataStore.edit { preferences ->
        preferences[intPreferencesKey("theme_mode")] = ThemeMode.toValue(mode)
    }
}

/**
 * Load theme preference from DataStore.
 */
fun loadThemePreference(dataStore: DataStore<Preferences>): ThemeMode {
    return try {
        runBlocking {
            val value = dataStore.data.map { prefs ->
                prefs[intPreferencesKey("theme_mode")] ?: ThemeMode.SYSTEM.ordinal
            }.first()
            ThemeMode.fromValue(value)
        }
    } catch (e: Exception) {
        ThemeMode.SYSTEM
    }
}
