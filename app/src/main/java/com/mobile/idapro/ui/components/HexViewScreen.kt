package com.mobile.idapro.ui.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsState
import com.mobile.idapro.utils.BinaryUtils
import com.mobile.idapro.viewmodel.MainViewModel

/**
 * Hex View Screen (from IDA Pro Mobile - enhanced for v3.0)
 * 
 * Features:
 * - Hex dump viewer with offset display
 * - ASCII column for readable characters
 * - Configurable bytes per row (8/16/32)
 * - Address navigation support
 * - Selection and copy functionality
 * - Byte highlighting for selected bytes
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun HexViewScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier,
    onNavigateToAddress: (Long) -> Unit = {}
) {
    val hexData by viewModel.hexData.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    
    var bytesPerRow by remember { mutableIntStateOf(16) }
    var showSettingsMenu by remember { mutableStateOf(false) }
    var selectedOffset by remember { mutableIntStateOf(-1) }
    var selectionStart by remember { mutableIntStateOf(-1) }
    var selectionEnd by remember { mutableIntStateOf(-1) }
    
    val listState = rememberLazyListState()
    
    // Calculate total rows
    val totalRows = if (hexData.isEmpty()) 0 else (hexData.size + bytesPerRow - 1) / bytesPerRow
    
    Column(modifier = modifier.fillMaxSize()) {
        // Top toolbar with settings
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            // File info / data size
            Text(
                text = buildString {
                    append("${hexData.size} bytes")
                    if (hexData.isNotEmpty()) {
                        append(" • ")
                        append("$totalRows rows")
                    }
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            // Bytes per row selector
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "Bytes/row:",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.width(8.dp))
                
                SegmentedButton(
                    selected = bytesPerRow == 8,
                    onClick = { bytesPerRow = 8 },
                    shape = MaterialTheme.shapes.small
                ) {
                    Text("8")
                }
                Spacer(Modifier.width(4.dp))
                SegmentedButton(
                    selected = bytesPerRow == 16,
                    onClick = { bytesPerRow = 16 },
                    shape = MaterialTheme.shapes.small
                ) {
                    Text("16")
                }
                Spacer(Modifier.width(4.dp))
                SegmentedButton(
                    selected = bytesPerRow == 32,
                    onClick = { bytesPerRow = 32 },
                    shape = MaterialTheme.shapes.small
                ) {
                    Text("32")
                }
            }
        }
        
        // Header row
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            )
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Offset header
                Text(
                    text = "OFFSET",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.width(80.dp)
                )
                
                // Hex area header (dynamic width based on bytes per row)
                Text(
                    text = buildString {
                        repeat(bytesPerRow) { index ->
                            append(String.format("%02X", index))
                            if (index < bytesPerRow - 1) append(' ')
                        }
                    },
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary,
                    fontFamily = FontFamily.Monospace,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.weight(1f)
                )
                
                // ASCII header
                Text(
                    text = "ASCII",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary,
                    fontFamily = FontFamily.Monospace,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.width(bytesPerRow.dp + 20.dp)
                )
            }
        }
        
        Spacer(Modifier.height(4.dp))
        
        // Content area
        when {
            isLoading -> {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator()
                        Spacer(Modifier.height(16.dp))
                        Text(
                            text = "Loading hex data...",
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
            
            errorMessage != null -> {
                ErrorStateCard(
                    message = errorMessage ?: "Unknown error",
                    onDismiss = { viewModel.clearError() }
                )
            }
            
            hexData.isEmpty() && !isLoading -> {
                EmptyStateCard(
                    icon = Icons.Default.DataArray,
                    title = "No Data",
                    description = "Load a binary file to view hex dump"
                )
            }
            
            else -> {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(bottom = 16.dp)
                ) {
                    itemsIndexed(
                        items = (0 until totalRows).toList(),
                        key = { _, rowIndex -> rowIndex }
                    ) { rowIndex ->
                        HexDataRow(
                            hexData = hexData,
                            rowIndex = rowIndex,
                            bytesPerRow = bytesPerRow,
                            selectedOffset = selectedOffset,
                            selectionStart = selectionStart,
                            selectionEnd = selectionEnd,
                            onByteClick = { offset -> 
                                selectedOffset = offset
                                if (selectionStart == -1) {
                                    selectionStart = offset
                                    selectionEnd = offset
                                } else {
                                    selectionEnd = offset
                                }
                            },
                            onOffsetClick = { address -> 
                                onNavigateToAddress(address.toLong())
                            },
                            onLongPress = { offset ->
                                selectionStart = offset
                                selectionEnd = offset
                            }
                        )
                    }
                }
            }
        }
        
        // Bottom info bar when selection is active
        if (selectionStart != -1 && selectionEnd != -1 && selectionStart <= selectionEnd) {
            Surface(
                color = MaterialTheme.colorScheme.primaryContainer,
                tonalElevation = 8.dp
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = buildString {
                            append("Selection: ${BinaryUtils.toHexString(selectionStart.toLong())}")
                            append(" - ${BinaryUtils.toHexString(selectionEnd.toLong())}")
                            append(" (${selectionEnd - selectionStart + 1} bytes)")
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                    
                    TextButton(onClick = { 
                        // Copy to clipboard logic here
                        selectionStart = -1
                        selectionEnd = -1
                        selectedOffset = -1
                    }) {
                        Icon(Icons.Default.ContentCopy, contentDescription = "Copy", Modifier.size(18.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Copy", color = MaterialTheme.colorScheme.onPrimaryContainer)
                    }
                }
            }
        }
    }
}

/**
 * Single hex data row showing offset, hex bytes, and ASCII representation
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun HexDataRow(
    hexData: ByteArray,
    rowIndex: Int,
    bytesPerRow: Int,
    selectedOffset: Int,
    selectionStart: Int,
    selectionEnd: Int,
    onByteClick: (Int) -> Unit,
    onOffsetClick: (Int) -> Unit,
    onLongPress: (Int) -> Unit
) {
    val baseOffset = rowIndex * bytesPerRow
    
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 2.dp),
        verticalAlignment = Alignment.Top
    ) {
        // Offset column
        Text(
            text = String.format("%08X", baseOffset),
            color = AsmAddress,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier
                .width(80.dp)
                .clickable { onOffsetClick(baseOffset) }
        )
        
        Spacer(Modifier.width(8.dp))
        
        // Hex bytes column
        Row(
            modifier = Modifier.weight(1f),
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            for (i in 0 until bytesPerRow) {
                val byteIndex = baseOffset + i
                val isSelected = byteIndex in selectionStart..selectionEnd
                val isCurrentSelected = byteIndex == selectedOffset
                
                if (byteIndex < hexData.size) {
                    val byte = hexData[byteIndex].toInt() and 0xFF
                    
                    Text(
                        text = String.format("%02X", byte),
                        color = getByteColor(byte, isSelected || isCurrentSelected),
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier
                            .combinedClickable(
                                onClick = { onByteClick(byteIndex) },
                                onLongClick = { onLongPress(byteIndex) }
                            )
                    )
                } else {
                    // Padding for incomplete last row
                    Text(
                        text = "  ",
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
        
        Spacer(Modifier.width(12.dp))
        
        // ASCII column
        Text(
            text = buildString {
                for (i in 0 until minOf(bytesPerRow, hexData.size - baseOffset)) {
                    val byte = hexData[baseOffset + i].toInt() and 0xFF
                    append(if (byte in 32..126) byte.toChar() else '.')
                }
            },
            color = OnSurfaceVariant,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.width(bytesPerRow.dp + 20.dp)
        )
    }
}

/**
 * Get color for a byte based on its value and selection state
 */
@Composable
private fun getByteColor(byteValue: Int, isSelected: Boolean): Color {
    return when {
        isSelected -> MaterialTheme.colorScheme.primary
        byteValue == 0x00 -> Color.Gray.copy(alpha = 0.5f) // Null bytes dimmed
        byteValue in 0x20..0x7E -> OnSurface // Printable ASCII
        byteValue == 0xFF -> Color.Red.copy(alpha = 0.7f) // Common padding pattern
        else -> OnSurface
    }
}

/**
 * Segmented button helper for the bytes-per-row selector
 */
@Composable
private fun SegmentedButton(
    selected: Boolean,
    onClick: () -> Unit,
    shape: androidx.compose.ui.graphics.Shape,
    content: @Composable () -> Unit
) {
    val containerColor = if (selected) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val contentColor = if (selected) {
        MaterialTheme.colorScheme.onPrimaryContainer
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }
    
    Surface(
        onClick = onClick,
        shape = shape,
        color = containerColor,
        contentColor = contentColor
    ) {
        Box(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            contentAlignment = Alignment.Center
        ) {
            CompositionLocalProvider(LocalContentStyle provides MaterialTheme.typography.labelMedium) {
                content()
            }
        }
    }
}
