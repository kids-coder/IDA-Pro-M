package com.mobile.idapro.ui.theme

import androidx.compose.ui.graphics.Color

/**
 * Color Theme for IDA Pro M (v3.0)
 * 
 * Dark theme optimized for code analysis with:
 * - Syntax highlighting colors (IDA-style)
 * - High contrast for readability
 * - Professional dark color scheme
 */

// Primary colors - Blue accent (IDA Pro inspired)
val Primary = Color(0xFF007ACC)
val PrimaryDark = Color(0xFF005A9E)
val LightPrimary = Color(0xFF4DA6FF)

// Background colors - Dark theme
val Background = Color(0xFF1E1E1E) // VS Code dark background
val Surface = Color(0xFF252526)
val SurfaceVariant = Color(0xFF2D2D30)

// On-surface colors
val OnBackground = Color(0xFFD4D4D4)
val OnSurface = Color(0xFFCCCCCC)
val OnSurfaceVariant = Color(0xFF808080)

// Status colors
val Error = Color(0xFFC74444)
val ErrorContainer = Color(0xFF3A1D1D)
val OnError = Color(0xFFFFFFFF)
val OnErrorContainer = Color(0xFFFFCBCB)

// Success/Info colors
val Success = Color(0xFF4EC9B0)
val Info = Color(0xFF569CD6)

// === Assembly Syntax Highlighting Colors (from IDA Pro Mobile) ===

// Address column color
val AsmAddress = Color(0xFF858585)

// Mnemonic/keyword color
val AsmKeyword = Color(0xFF569CD6) // Blue

// Register color
val AsmRegister = Color(0xFF4EC9B0) // Teal/Green

// Immediate value color
val AsmImmediate = Color(0xFFCE9178) // Orange

// Comment color
val AsmComment = Color(0xFF6A9955) // Green

// String color
val AsmString = Color(0xFFCE9178) // Orange/Yellow

// Label/symbol color
val AsmLabel = Color(0xFFDCDCAA) // Yellow

// Jump target color
val AsmJumpTarget = Color(0xFFD7BA7D) // Light yellow/orange

// Branch target color  
val AsmBranchTarget = Color(0xFF569CD6) // Blue

// Function start highlight
val AsmFunctionStart = Color(0xFF264F78) // Dark blue

// Monospace font reference for assembly views
val MonospaceFont = androidx.compose.ui.text.font.FontFamily.Monospace
