package com.mobile.idapro.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

/**
 * IDA Pro M - Color Palette
 * 
 * Professional color scheme inspired by desktop IDA Pro,
 * optimized for mobile reverse engineering workflows.
 */

// Primary colors - IDA Pro Blue
val IDAPrimary = Color(0xFF1565C0)
val IDAOnPrimary = Color(0xFFFFFFFF)
val IDAPrimaryContainer = Color(0xFFD3E3FD)
val IDAOnPrimaryContainer = Color(0xFF001D36)

// Secondary colors
valIDASecondary = Color(0xFF5B8DD9)
val IDAOnSecondary = Color(0xFFFFFFFF)
val IDASecondaryContainer = Color(0xFFD6E3F7)
val IDAOnSecondaryContainer = Color(0xFF0C3566)

// Tertiary colors
val IDATertiary = Color(0xFF006687)
val IDAOnTertiary = Color(0xFFFFFFFF)
val IDATertiaryContainer = Color(0xFFA8EDFF)
val IDAOnTertiaryContainer = Color(0xFF001F2A)

// Error colors
val IDAError = Color(0xFFBA1A1A)
val IDAOnError = Color(0xFFFFFFFF)
val IDAErrorContainer = Color(0xFFFFDAD6)
val IDAOnErrorContainer = Color(0xFF410002)

// Background colors
val IDABackground = Color(0xFFFEF7FF)
val IDAOnBackground = Color(0xFF1D1B20)
val IDASurface = Color(0xFFFEF7FF)
val IDAOnSurface = Color(0xFF1D1B20)
val IDASurfaceVariant = Color(0xFFE7E0EC)
val IDAOnSurfaceVariant = Color(0xFF49454F)

// Disassembly syntax highlighting - Light theme
val SyntaxMnemonic = Color(0xFF0000FF)
val SyntaxRegister = Color(0xFF228B22)
val SyntaxImmediate = Color(0xFFFF8C00)
val SyntaxMemory = Color(0xFF8B008B)
val SyntaxLabel = Color(0xFF4169E1)
val SyntaxComment = Color(0xFF808080)
val SyntaxString = Color(0xFFA31515)
val SyntaxKeyword = Color(0xFF0000CD)
val SyntaxDirective = Color(0xFF800080)
val SyntaxAddress = Color(0xFF008080)

// Hex editor colors
val HexBackground = Color(0xFFFFFFFF)
val HexText = Color(0xFF212121)
val HexOffsetBg = Color(0xFFE3F2FD)
val HexOffsetText = Color(0xFF1565C0)
val HexSelection = Color(0xFFBBDEFB)
val HexModified = Color(0xFFFFCDD2)
val HexHighlight = Color(0xFFFFF9C4)

// Graph view colors
val GraphNodeFill = Color(0xFFE3F2FD)
val GraphNodeStroke = Color(0xFF1565C0)
val GraphEdgeDefault = Color(0xFF49454F)
val GraphEdgeTrue = Color(0xFF4CAF50)
val GraphEdgeFalse = Color(0xFFF44336)
val GraphEntryNode = Color(0xFFE8F5E9)
val GraphExitNode = Color(0xFFFFEBEE)
val GraphConditionalNode = Color(0xFFFFF3E0)

// Status colors
val StatusSuccess = Color(0xFF4CAF50)
val StatusWarning = Color(0xFFFF9800)
val StatusError = Color(0xFFF44336)
val StatusInfo = Color(0xFF2196F3)

/**
 * Light color scheme for IDA Pro M.
 */
val LightColorScheme = lightColorScheme(
    primary = IDAPrimary,
    onPrimary = IDAOnPrimary,
    primaryContainer = IDAPrimaryContainer,
    onPrimaryContainer = IDAOnPrimaryContainer,
    secondary = IDASecondary,
    onSecondary = IDAOnSecondary,
    secondaryContainer = IDASecondaryContainer,
    onSecondaryContainer = IDAOnSecondaryContainer,
    tertiary = IDATertiary,
    onTertiary = IDAOnTertiary,
    tertiaryContainer = IDATertiaryContainer,
    onTertiaryContainer = IDAOnTertiaryContainer,
    error = IDAError,
    onError = IDAOnError,
    errorContainer = IDAErrorContainer,
    onErrorContainer = IDAOnErrorContainer,
    background = IDABackground,
    onBackground = IDAOnBackground,
    surface = IDASurface,
    onSurface = IDAOnSurface,
    surfaceVariant = IDASurfaceVariant,
    onSurfaceVariant = IDAOnSurfaceVariant
)

/**
 * Dark color scheme for IDA Pro M.
 * Optimized for OLED displays with pure black background option.
 */
val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF90CAF9),
    onPrimary = Color(0xFF001D36),
    primaryContainer = Color(0xFF001D36),
    onPrimaryContainer = Color(0xFF90CAF9),
    secondary = Color(0xFF90CAF9),
    onSecondary = Color(0xFF0C3566),
    secondaryContainer = Color(0xFF0C3566),
    onSecondaryContainer = Color(0xFF90CAF9),
    tertiary = Color(0xFF81D4FA),
    onTertiary = Color(0xFF001F2A),
    tertiaryContainer = Color(0xFF001F2A),
    onTertiaryContainer = Color(0xFF81D4FA),
    error = Color(0xFFEF9A9A),
    onError = Color(0xFF410002),
    errorContainer = Color(0xFF410002),
    onErrorContainer = Color(0xFFEF9A9A),
    background = Color(0xFF121212),
    onBackground = Color(0xFFE6E1E5),
    surface = Color(0xFF1E1E1E),
    onSurface = Color(0xFFE6E1E5),
    surfaceVariant = Color(0xFF49454F),
    onSurfaceVariant = Color(0xFFCAC4D0)
)

// Dark theme syntax highlighting
val DarkSyntaxMnemonic = Color(0xFF569CD6)
val DarkSyntaxRegister = Color(0xFF4EC9B0)
val DarkSyntaxImmediate = Color(0xFFCE9178)
val DarkSyntaxMemory = Color(0xFFB4CEFB)
val DarkSyntaxLabel = Color(0xFFDCDCAA)
val DarkSyntaxComment = Color(0xFF6A9955)
val DarkSyntaxString = Color(0xFFCE9178)
val DarkSyntaxKeyword = Color(0xFF569CD6)
val DarkSyntaxDirective = Color(0xFFC586C0)
val DarkSyntaxAddress = Color(0xFF9CDCFE)

// Dark hex editor colors
val DarkHexBackground = Color(0xFF1E1E1E)
val DarkHexText = Color(0xFFD4D4D4)
val DarkHexOffsetBg = Color(0xFF252526)
val DarkHexOffsetText = Color(0xFF9CDCFE)
val DarkHexSelection = Color(0xFF264F78)
val DarkHexModified = Color(0xFF5A1D1D)
val DarkHexHighlight = Color(0xFF655F00)

/**
 * AMOLED-optimized black color scheme.
 * Uses pure black (#000000) for better battery life on OLED screens.
 */
val AmoledColorScheme = darkColorScheme(
    primary = Color(0xFF90CAF9),
    onPrimary = Color(0xFF000000),
    primaryContainer = Color(0xFF000000),
    onPrimaryContainer = Color(0xFF90CAF9),
    secondary = Color(0xFF90CAF9),
    onSecondary = Color(0xFF000000),
    secondaryContainer = Color(0xFF000000),
    onSecondaryContainer = Color(0xFF90CAF9),
    tertiary = Color(0xFF81D4FA),
    onTertiary = Color(0xFF000000),
    tertiaryContainer = Color(0xFF000000),
    onTertiaryContainer = Color(0xFF81D4FA),
    error = Color(0xFFEF9A9A),
    onError = Color(0xFF000000),
    errorContainer = Color(0xFF000000),
    onErrorContainer = Color(0xFFEF9A9A),
    background = Color(0xFF000000),
    onBackground = Color(0xFFE6E1E5),
    surface = Color(0xFF000000),
    onSurface = Color(0xFFE6E1E5),
    surfaceVariant = Color(0xFF1E1E1E),
    onSurfaceVariant = Color(0xFFCAC4D0)
)
