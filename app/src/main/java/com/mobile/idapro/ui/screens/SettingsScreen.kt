package com.mobile.idapro.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel

/**
 * IDA Pro M - Settings Screen
 * 
 * Application settings for appearance, analysis options,
 * advanced features, and about information.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit
) {
    val viewModel: SettingsViewModel = hiltViewModel()
    
    val settings by viewModel.settings.collectAsState()
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        }
    ) { paddingValues ->
        val scrollState = rememberScrollState()
        
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(scrollState)
        ) {
            // Appearance section
            SettingsSection(title = "Appearance", icon = Icons.Default.Palette) {
                // Theme selection
                ListItem(
                    headlineContent = { Text("Theme") },
                    supportingContent = { Text(getThemeDisplayName(settings.themeMode)) },
                    leadingIcon = { Icon(Icons.Default.DarkMode, null) },
                    trailingContent = {
                        DropdownMenu(
                            expanded = false,
                            onDismissRequest = {}
                        ) {
                            // Theme options would be shown here
                        }
                        Icon(Icons.Default.ChevronRight, null)
                    }
                )
                
                HorizontalDivider(modifier = Modifier.padding(start = 56.dp))
                
                // Font size
                ListItem(
                    headlineContent = { Text("Font Size") },
                    supportingContent = { Text(getFontSizeDisplayName(settings.fontSize)) },
                    leadingIcon = { Icon(Icons.Default.TextFields, null) },
                    trailingContent = {
                        Slider(
                            value = when (settings.fontSize) {
                                com.mobile.idapro.data.model.FontSize.SMALL -> 0f
                                com.mobile.idapro.data.model.FontSize.MEDIUM -> 1f
                                com.mobile.idapro.data.model.FontSize.LARGE -> 2f
                                com.mobile.idapro.data.model.FontSize.EXTRA_LARGE -> 3f
                                else -> 1f
                            },
                            onValueChange = { /* Update font size */ },
                            modifier = Modifier.width(120.dp)
                        )
                    }
                )
                
                HorizontalDivider(modifier = Modifier.padding(start = 56.dp))
                
                // Syntax highlighting toggle
                ListItem(
                    headlineContent = { Text("Syntax Highlighting") },
                    supportingContent = { Text("Color-code instructions and data") },
                    leadingIcon = { Icon(Icons.Default.Code, null) },
                    trailingContent = {
                        Switch(
                            checked = settings.syntaxHighlighting,
                            onCheckedChange = { /* Update setting */ }
                        )
                    }
                )
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            // Analysis section
            SettingsSection(title = "Analysis Options", icon = Icons.Default.Analytics) {
                ListItem(
                    headlineContent = { Text("Auto-analyze on Open") },
                    supportingContent = { Text("Automatically start analysis when file is loaded") },
                    leadingIcon = { Icon(Icons.Default.PlayArrow, null) },
                    trailingContent = {
                        Switch(
                            checked = settings.autoAnalyzeOnOpen,
                            onCheckedChange = { viewModel.toggleAutoAnalyze() }
                        )
                    }
                )
                
                HorizontalDivider(modifier = Modifier.padding(start = 56.dp))
                
                ListItem(
                    headlineContent = { Text("Deep Scan Mode") },
                    supportingContent = { Text("More thorough but slower analysis") },
                    leadingIcon = { Icon(Icons.Default.Search, null) },
                    trailingContent = {
                        Switch(
                            checked = settings.deepScanMode,
                            onCheckedChange = { viewModel.toggleDeepScan() }
                        )
                    }
                )
                
                HorizontalDivider(modifier = Modifier.padding(start = 56.dp))
                
                ListItem(
                    headlineContent = { Text("String Extraction") },
                    supportingContent = { Text("Min: ${settings.minStringLength} • Max: ${settings.maxStringLength}") },
                    leadingIcon = { Icon(Icons.Default.TextFields, null) },
                    onClick = { /* Show string options */ }
                )
                
                HorizontalDivider(modifier = Modifier.padding(start = 56.dp))
                
                ListItem(
                    headlineContent = { Text("Default Architecture") },
                    supportingContent = { Text(settings.defaultArchitecture.name) },
                    leadingIcon = { Icon(Icons.Default.Memory, null) },
                    onClick = { /* Show architecture picker */ }
                )
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            // Advanced section
            SettingsSection(title = "Advanced", icon = Icons.Default.Settings) {
                ListItem(
                    headlineContent = { Text("Cache Management") },
                    supportingContent = { Text("Clear cached data to free space") },
                    leadingIcon = { Icon(Icons.Default.CleaningServices, null),
                    onClick = { viewModel.clearCache() }
                )
                
                HorizontalDivider(modifier = Modifier.padding(start = 56.dp))
                
                ListItem(
                    headlineContent = { Text("Logging") },
                    supportingContent = { Text(if (settings.enableLogging) "Enabled" else "Disabled") },
                    leadingIcon = { Icon(Icons.Default.BugReport, null) },
                    trailingContent = {
                        Switch(
                            checked = settings.enableLogging,
                            onCheckedChange = { /* Toggle logging */ }
                        )
                    }
                )
                
                HorizontalDivider(modifier = Modifier.padding(start = 56.dp))
                
                ListItem(
                    headlineContent = { Text("Max Memory Usage") },
                    supportingContent = { Text("${settings.maxMemoryUsageMB} MB") },
                    leadingIcon = { Icon(Icons.Default.Memory, null) },
                    onClick = { /* Show memory slider */ }
                )
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // About section
            SettingsSection(title = "About", icon = Icons.Default.Info) {
                // App info card
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            // App icon placeholder
                            Surface(
                                shape = MaterialTheme.shapes.medium,
                                color = MaterialTheme.colorScheme.primaryContainer,
                                modifier = Modifier.size(48.dp)
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Icon(Icons.Default.Memory, null, 
                                         modifier = Modifier.size(28.dp),
                                         tint = MaterialTheme.colorScheme.primary)
                                }
                            }
                            
                            Spacer(modifier = Modifier.width(16.dp))
                            
                            Column {
                                Text(
                                    text = "IDA Pro M",
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Text(
                                    text = "Version 3.0.0 (Build 300)",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Text(
                                    text = "Mobile Reverse Engineering Suite",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        }
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        // Version details
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceEvenly
                        ) {
                            VersionInfoItem(label = "Package", value = "com.mobile.idapro")
                            VersionInfoItem(label = "Min SDK", value = "24")
                            VersionInfoItem(label = "Target SDK", value = "37")
                        }
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceEvenly
                        ) {
                            VersionInfoItem(label = "Kotlin", value = "2.4")
                            VersionInfoItem(label = "AGP", value = "9.3")
                            VersionInfoItem(label = "Compose", value = "2025.09")
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                // Links
                ListItem(
                    headlineContent = { Text("GitHub Repository") },
                    supportingContent = { Text("View source code and report issues") },
                    leadingIcon = { Icon(Icons.Default.Code, null) },
                    onClick = { /* Open GitHub */ }
                )
                
                HorizontalDivider(modifier = Modifier.padding(start = 56.dp))
                
                ListItem(
                    headlineContent = { Text("Privacy Policy") },
                    leadingIcon = { Icon(Icons.Default.PrivacyTip, null) },
                    onClick = { /* Open privacy policy */ }
                )
                
                HorizontalDivider(modifier = Modifier.padding(start = 56.dp))
                
                ListItem(
                    headlineContent = { Text("Open Source Licenses") },
                    supportingContent = { Text("View third-party licenses") },
                    leadingIcon = { Icon(Icons.Default.Description, null) },
                    onClick = { /* Show licenses */ }
                )
                
                HorizontalDivider(modifier = Modifier.padding(start = 56.dp))
                
                ListItem(
                    headlineContent = { Text("Report a Bug") },
                    supportingContent = { Text("Submit issue or feedback") },
                    leadingIcon = { Icon(Icons.Default.BugReport, null) },
                    onClick = { /* Open bug reporter */ }
                )
            }
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Version info at bottom
            Text(
                text = "IDA Pro M v3.0.0\nBuilt with AGP 9.3 • Kotlin 2.4 • Compose BOM 2025.09",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.outline,
                modifier = Modifier.align(Alignment.CenterHorizontally)
            )
        }
    }
}

@Composable
private fun SettingsSection(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    content: @Composable ColumnScope.() -> Unit
) {
    Column {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
        ) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Spacer(modifier = Modifier.width(8.dp))
            Text(text = title, style = MaterialStyle.titleMedium, color = MaterialTheme.colorScheme.primary)
        }
        
        Card(
            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            content()
        }
    }
}

@Composable
private fun VersionInfoItem(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurface)
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
    }
}

private fun getThemeDisplayName(mode: com.mobile.idapro.data.model.ThemeModeValue): String {
    return when (mode) {
        com.mobile.idapro.data.model.ThemeModeValue.LIGHT -> "Light"
        com.mobile.idapro.data.model.ThemeModeValue.DARK -> "Dark"
        com.mobile.idapro.data.model.ThemeModeValue.SYSTEM -> "System Default"
        com.mobile.idapro.data.model.ThemeModeValue.AMOLED -> "Pure Black (AMOLED)"
    }
}

private fun getFontSizeDisplayName(size: com.mobile.idapro.data.model.FontSize): String {
    return when (size) {
        com.mobile.idapro.data.model.FontSize.SMALL -> "Small"
        com.mobile.idapro.data.model.FontSize.MEDIUM -> "Medium (Default)"
        com.mobile.idapro.data.model.FontSize.LARGE -> "Large"
        com.mobile.idapro.data.model.FontSize.EXTRA_LARGE -> "Extra Large"
    }
}
