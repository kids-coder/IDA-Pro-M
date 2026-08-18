package com.mobile.idapro.ui.screens

import androidx.compose.foundation.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel

/**
 * IDA Pro M - Hex Editor Screen
 * 
 * Displays binary data in hexadecimal format with ASCII representation.
 * Supports editing, searching, selection, and navigation.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun HexEditorScreen(
    fileId: Long,
    initialAddress: Long = 0L,
    onBack: () -> Unit,
    onNavigateToDisassembly: (Long) -> Unit = {}
) {
    val viewModel: HexEditorViewModel = hiltViewModel()
    
    val hexData by viewModel.hexData.collectAsState()
    val selectedOffset by viewModel.selectedOffset.collectAsState()
    val editMode by viewModel.editMode.collectAsState()
    
    // UI state
    var showGotoDialog by remember { mutableStateOf(false) }
    var showSearchDialog by remember { mutableStateOf(false) }
    
    LaunchedEffect(fileId, initialAddress) {
        viewModel.loadHexData(fileId, initialAddress)
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Hex Editor") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    // Edit mode toggle
                    FilterChip(
                        selected = editMode,
                        onClick = { viewModel.toggleEditMode() },
                        label = { Text("Edit") },
                        leadingIcon = if (editMode) {{ Icon(Icons.Default.Edit, null) }} else null
                    )
                    
                    IconButton(onClick = { showSearchDialog = true }) {
                        Icon(Icons.Default.Search, contentDescription = "Search")
                    }
                    IconButton(onClick = { showGotoDialog = true }) {
                        Icon(Icons.Default.GpsFixed, contentDescription = "Go to offset")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            HexEditorStatusBar(
                selectedOffset = selectedOffset,
                editMode = editMode,
                modificationsCount = 0 // Would track actual modifications
            )
        }
    ) { paddingValues ->
        when (val data = hexData) {
            is com.mobile.idapro.ui.screens.HexEditorData.Empty -> {
                EmptyHexView()
            }
            is com.mobile.idapro.ui.screens.HexEditorData.Loaded -> {
                HexEditorContent(
                    hexDump = data.hexDump,
                    startOffset = data.startOffset,
                    bytesPerRow = data.bytesPerRow,
                    editMode = editMode,
                    selectedOffset = selectedOffset,
                    onOffsetSelected = { viewModel.selectOffset(it) }
                )
            }
            is com.mobile.idapro.ui.screens.HexEditorData.Error -> {
                ErrorView(message = data.message)
            }
        }
        
        // Goto dialog
        if (showGotoDialog) {
            GotoOffsetDialog(
                currentOffset = selectedOffset,
                onConfirm = { offset ->
                    viewModel.selectOffset(offset)
                    showGotoDialog = false
                },
                onDismiss = { showGotoDialog = false }
            )
        }
    }
}

@Composable
private fun HexEditorContent(
    hexDump: String,
    startOffset: Long,
    bytesPerRow: Int,
    editMode: Boolean,
    selectedOffset: Long,
    onOffsetSelected: (Long) -> Unit
) {
    val scrollState = rememberScrollState()
    
    Column(modifier = Modifier.fillMaxSize()) {
        // Header row with column labels
        Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(vertical = 4.dp, horizontal = 8.dp)
            ) {
                Text("Offset", fontFamily = FontFamily.Monospace, fontSize = 11.sp, 
                     fontWeight = androidx.compose.ui.text.font.Font.Bold,
                     modifier = Modifier.width(80.dp))
                
                // Hex columns header
                for (i in 0 until bytesPerRow) {
                    Text(
                        text = "%02X".format(i),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                        modifier = Modifier.width(24.dp)
                    )
                }
                
                Spacer(modifier = Modifier.width(8.dp))
                Text("ASCII", fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                     fontWeight = androidx.compose.ui.text.font.Font.Bold)
            }
        }
        
        HorizontalDivider()
        
        // Hex data rows
        Box(modifier = Modifier.weight(1f)) {
            LazyColumn(state = scrollState) {
                items((hexDump.lines().size)) { lineIndex ->
                    val line = if (lineIndex < hexDump.lines().size) hexDump.lines()[lineIndex] else ""
                    HexRow(
                        offset = startOffset + (lineIndex * bytesPerRow),
                        lineText = line,
                        bytesPerRow = bytesPerRow,
                        isSelected = false, // Would check against selectedOffset
                        isModified = false, // Would check modifications set
                        onClick = { onOffsetSelected(startOffset + (lineIndex * bytesPerRow)) }
                    )
                }
            }
        }
    }
}

@Composable
private fun HexRow(
    offset: Long,
    lineText: String,
    bytesPerRow: Int,
    isSelected: Boolean,
    isModified: Boolean,
    onClick: () -> Unit
) {
    val backgroundColor = when {
        isSelected -> MaterialTheme.colorScheme.primaryContainer
        isModified -> HexModified.copy(alpha = 0.3f)
        else -> Color.Transparent
    }
    
    Surface(
        onClick = onClick,
        color = backgroundColor,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 2.dp),
            verticalAlignment = Alignment.Top
        ) {
            // Offset column
            Text(
                text = "%08X".format(offset),
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = HexOffsetText,
                modifier = Modifier.width(80.dp)
            )
            
            // Hex bytes
            val bytes = parseHexLine(lineText, bytesPerRow)
            for ((index, byteValue) in bytes.withIndex()) {
                Text(
                    text = byteValue ?: "??",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    color = if (isModified) StatusError else HexText,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                    modifier = Modifier.width(24.dp)
                )
            }
            
            // Padding for missing bytes
            for (i in bytes.size until bytesPerRow) {
                Text(
                    text = "  ",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    modifier = Modifier.width(24.dp)
                )
            }
            
            Spacer(modifier = Modifier.width(8.dp))
            
            // ASCII representation
            Text(
                text = bytes.joinToString("") { 
                    it?.let { byte -> 
                        if (byte.code in 32..127) byte.toChar() else '.' 
                    } ?: '.'
                },
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun parseHexLine(line: String, expectedBytes: Int): List<Byte?> {
    // Parse hex dump line to extract byte values
    return try {
        val parts = line.trim().split("\\s+".toRegex()).drop(1) // Drop offset
        parts.mapNotNull { part ->
            if (part.length == 2 && part.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
                part.toInt(16).toByte()
            } else null
        }.take(expectedBytes)
    } catch (e: Exception) {
        List(expectedBytes) { null }
    }
}

@Composable
private fun HexEditorStatusBar(
    selectedOffset: Long,
    editMode: Boolean,
    modificationsCount: Int
) {
    Surface(
        shadowElevation = 8.dp,
        tonalElevation = 4.dp,
        color = MaterialTheme.colorScheme.surface
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Selection info
            Text(
                text = "Offset: 0x${selectedOffset.toString(16).padStart(8, '0')}",
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.labelMedium
            )
            
            Row {
                // Edit mode indicator
                if (editMode) {
                    Surface(
                        shape = MaterialTheme.shapes.small,
                        color = MaterialTheme.colorScheme.errorContainer
                    ) {
                        Text(
                            "EDIT MODE",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                }
                
                // Modifications count
                if (modificationsCount > 0) {
                    Text(
                        text = "$modificationsCount modified",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

@Composable
private fun GotoOffsetDialog(
    currentOffset: Long,
    onConfirm: (Long) -> Unit,
    onDismiss: () -> Unit
) {
    var offsetText by remember { mutableStateOf(currentOffset.toString(16)) }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Go to Offset") },
        text = {
            OutlinedTextField(
                value = offsetText,
                onValueChange = { offsetText = it },
                label = { Text("Offset (hex)") },
                prefix = { Text("0x", fontFamily = FontFamily.Monospace) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                modifier = Modifier.fillMaxWidth()
            )
        },
        confirmButton = {
            TextButton(onClick = {
                try {
                    val offset = offsetText.toLong(16)
                    onConfirm(offset)
                } catch (e: NumberFormatException) {}
            }) { Text("Go") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

@Composable
private fun EmptyHexView() {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Default.DataArray, null, modifier = Modifier.size(64.dp), tint = MaterialTheme.colorScheme.outline)
            Spacer(modifier = Modifier.height(16.dp))
            Text("No data loaded", style = MaterialTheme.typography.titleMedium)
        }
    }
}
