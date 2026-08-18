package com.mobile.idapro.ui.components

import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsState
import com.mobile.idapro.data.model.Function
import com.mobile.idapro.utils.BinaryUtils
import com.mobile.idapro.viewmodel.MainViewModel

/**
 * Function List Screen (from IDA Pro Mobile - enhanced for v3.0)
 * 
 * Features:
 * - List of detected functions with name, address, size
 * - Export/Import status indicators
 * - Expandable details (signature, bytes, etc.)
 * - Search/filter functionality
 * - Click to navigate to function in disassembly
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FunctionListScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier,
    onFunctionClick: (Function) -> Unit = {},
    onNavigateToAddress: (Long) -> Unit = {}
) {
    val functions by viewModel.functions.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    
    var searchQuery by remember { mutableStateOf("") }
    var expandedFunctionId by remember { mutableStateOf<String?>(null) }
    var filterExported by remember { mutableStateOf(false) }
    var filterImported by remember { mutableStateOf(false) }
    
    // Filter functions based on search and filters
    val filteredFunctions = remember(searchQuery, functions, filterExported, filterImported) {
        var result = functions
        
        if (searchQuery.isNotBlank()) {
            val query = searchQuery.lowercase()
            result = result.filter { func ->
                func.name.lowercase().contains(query) ||
                func.address.toString(16).lowercase().contains(query) ||
                func.signature.lowercase().contains(query)
            }
        }
        
        if (filterExported) {
            result = result.filter { it.isExported }
        }
        
        if (filterImported) {
            result = result.filter { it.isImported }
        }
        
        // Sort: exported first, then imported, then others; by address within each group
        result.sortedWith(compareByDescending<Function> { it.isExported }
            .thenByDescending { it.isImported }
            .thenBy { it.address })
    }
    
    // Statistics
    val totalFunctions = functions.size
    val exportedCount = functions.count { it.isExported }
    val importedCount = functions.count { it.isImported }
    
    Column(modifier = modifier.fillMaxSize()) {
        // Search bar
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Search functions...") },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = "Search") },
            trailingIcon = {
                if (searchQuery.isNotEmpty()) {
                    IconButton(onClick = { searchQuery = "" }) {
                        Icon(Icons.Default.Clear, contentDescription = "Clear")
                    }
                }
            },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
        )
        
        Spacer(Modifier.height(8.dp))
        
        // Statistics and filter chips
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Stats text
            Text(
                text = buildString {
                    append("$totalFunctions functions")
                    if (exportedCount > 0) append(" • $exportedCount exported")
                    if (importedCount > 0) append(" • $importedCount imported")
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            // Filter chips row
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = filterExported,
                    onClick = { filterExported = !filterExported },
                    label = { Text("Exported") },
                    leadingIcon = if (filterExported) {
                        { Icon(Icons.Default.Upload, contentDescription = null, Modifier.size(16.dp)) }
                    } else null
                )
                
                FilterChip(
                    selected = filterImported,
                    onClick = { filterImported = !filterImported },
                    label = { Text("Imported") },
                    leadingIcon = if (filterImported) {
                        { Icon(Icons.Default.Download, contentDescription = null, Modifier.size(16.dp)) }
                    } else null
                )
            }
        }
        
        Spacer(Modifier.height(8.dp))
        
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
                            text = "Analyzing functions...",
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
            
            filteredFunctions.isEmpty() && !isLoading -> {
                EmptyStateCard(
                    icon = Icons.Default.Functions,
                    title = "No Functions Found",
                    description = if (functions.isEmpty()) {
                        "Load a binary file to detect functions"
                    } else {
                        "No functions match your search criteria"
                    }
                )
            }
            
            else -> {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(vertical = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    items(
                        items = filteredFunctions,
                        key = { "${it.name}_${it.address}" }
                    ) { function ->
                        FunctionListItem(
                            function = function,
                            isExpanded = expandedFunctionId == "${function.name}_${function.address}",
                            onToggleExpand = { id ->
                                expandedFunctionId = if (expandedFunctionId == id) null else id
                            },
                            onClick = { onFunctionClick(function) },
                            onNavigateToAddress = { onNavigateToAddress(it) }
                        )
                    }
                }
            }
        }
    }
}

/**
 * Single function list item with expandable details
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FunctionListItem(
    function: Function,
    isExpanded: Boolean,
    onToggleExpand: (String) -> Unit,
    onClick: () -> Unit,
    onNavigateToAddress: (Long) -> Unit
) {
    val itemId = "${function.name}_${function.address}"
    
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                function.isExported -> Success.copy(alpha = 0.1f)
                function.isImported -> Info.copy(alpha = 0.1f)
                else -> MaterialTheme.colorScheme.surface
            }
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .animateContentSize(
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioMediumBouncy,
                        stiffness = Spring.StiffnessLow
                    )
                )
        ) {
            // Main row - always visible
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { 
                        onToggleExpand(itemId)
                        onClick()
                    }
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Expand/collapse icon
                Icon(
                    imageVector = if (isExpanded) Icons.Default.KeyboardArrowDown 
                                   else Icons.Default.KeyboardArrowRight,
                    contentDescription = if (isExpanded) "Collapse" else "Expand",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp)
                )
                
                Spacer(Modifier.width(8.dp))
                
                // Function icon with status indicator
                Box {
                    Icon(
                        Icons.Default.Code,
                        contentDescription = "Function",
                        tint = when {
                            function.isExported -> Success
                            function.isImported -> Info
                            else -> MaterialTheme.colorScheme.primary
                        },
                        modifier = Modifier.size(24.dp)
                    )
                    
                    // Status badge
                    if (function.isExported || function.isImported) {
                        Surface(
                            shape = MaterialTheme.shapes.small,
                            color = if (function.isExported) Success else Info,
                            modifier = Modifier.align(Alignment.BottomEnd).size(10.dp)
                        ) {}
                    }
                }
                
                Spacer(Modifier.width(12.dp))
                
                // Function info column
                Column(modifier = Modifier.weight(1f)) {
                    // Function name
                    Text(
                        text = function.name.ifBlank { "<unnamed>" },
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1
                    )
                    
                    // Address and size row
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // Address (clickable to navigate)
                        Text(
                            text = function.getAddressString(),
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                            color = AsmAddress,
                            modifier = Modifier.clickable { 
                                onNavigateToAddress(function.address) 
                            }
                        )
                        
                        // Size
                        Text(
                            text = function.formattedSize,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        
                        // Export/Import badge
                        when {
                            function.isExported -> {
                                Surface(
                                    shape = MaterialTheme.shapes.extraSmall,
                                    color = Success.copy(alpha = 0.2f)
                                ) {
                                    Text(
                                        text = "EXPORTED",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = Success,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }
                            }
                            function.isImported -> {
                                Surface(
                                    shape = MaterialTheme.shapes.extraSmall,
                                    color = Info.copy(alpha = 0.2f)
                                ) {
                                    Text(
                                        text = "IMPORTED",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = Info,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }
                            }
                        }
                    }
                }
                
                // Navigate button
                IconButton(onClick = { onNavigateToAddress(function.address) }) {
                    Icon(
                        Icons.Default.OpenInNew,
                        contentDescription = "Go to address",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
            
            // Expanded details
            if (isExpanded) {
                HorizontalDivider()
                
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                ) {
                    // Signature if available
                    if (function.signature.isNotBlank()) {
                        DetailRow(label = "Signature", value = function.signature)
                        Spacer(Modifier.height(8.dp))
                    }
                    
                    // Full details
                    DetailRow(
                        label = "Start Address", 
                        value = BinaryUtils.toHexString(function.address)
                    )
                    
                    DetailRow(
                        label = "Size", 
                        value = "${function.size} bytes (${function.formattedSize})"
                    )
                    
                    DetailRow(
                        label = "End Address", 
                        value = BinaryUtils.toHexString(function.address + function.size)
                    )
                    
                    // Action buttons in expanded view
                    Spacer(Modifier.height(12.dp))
                    
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        FilledTonalButton(
                            onClick = { onNavigateToAddress(function.address) }
                        ) {
                            Icon(Icons.Default.OpenInNew, contentDescription = null, Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("View in Disassembly")
                        }
                        
                        OutlinedButton(
                            onClick = { /* Add bookmark */ }
                        ) {
                            Icon(Icons.Default.BookmarkAdd, contentDescription = null, Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Bookmark")
                        }
                    }
                }
            }
        }
    }
}

/**
 * Detail row for expanded function view
 */
@Composable
private fun DetailRow(
    label: String,
    value: String
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.width(100.dp)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = OnSurface,
            modifier = Modifier.weight(1f)
        )
    }
}
