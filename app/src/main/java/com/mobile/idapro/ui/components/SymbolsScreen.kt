package com.mobile.idapro.ui.components

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
import com.mobile.idapro.data.model.Symbol
import com.mobile.idapro.data.model.SymbolType
import com.mobile.idapro.utils.BinaryUtils
import com.mobile.idapro.viewmodel.MainViewModel

/**
 * Symbols Screen (from KTIMAZ-REV - enhanced for v3.0)
 * 
 * Features:
 * - ELF symbol table viewer
 * - Type filtering chips (All, Function, Object, Section, File)
 * - Search by name or address
 * - Symbol details with type, value, size, section
 * - Click to navigate to symbol address
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SymbolsScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier,
    onNavigateToAddress: (Long) -> Unit = {}
) {
    val symbols by viewModel.symbols.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    
    var searchQuery by remember { mutableStateOf("") }
    var selectedTypeFilter by remember { mutableStateOf<SymbolType?>(null) }
    
    // Filter symbols based on search and type filter
    val filteredSymbols = remember(searchQuery, symbols, selectedTypeFilter) {
        var result = symbols
        
        // Apply type filter
        if (selectedTypeFilter != null && selectedTypeFilter != SymbolType.UNKNOWN) {
            result = result.filter { it.type == selectedTypeFilter }
        }
        
        // Apply search filter
        if (searchQuery.isNotBlank()) {
            val query = searchQuery.lowercase()
            result = result.filter { symbol ->
                symbol.name.lowercase().contains(query) ||
                BinaryUtils.toHexString(symbol.value).lowercase().contains(query)
            }
        }
        
        // Sort by name, then by value
        result.sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.name }
            .thenBy { it.value })
    }
    
    // Symbol counts by type
    val typeCounts = remember(symbols) {
        mapOf(
            null to symbols.size,
            SymbolType.FUNCTION to symbols.count { it.type == SymbolType.FUNCTION },
            SymbolType.OBJECT to symbols.count { it.type == SymbolType.OBJECT },
            SymbolType.SECTION to symbols.count { it.type == SymbolType.SECTION },
            SymbolType.FILE to symbols.count { it.type == SymbolType.FILE }
        )
    }
    
    Column(modifier = modifier.fillMaxSize()) {
        // Search bar
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Search symbols...") },
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
        
        Spacer(Modifier.height(12.dp))
        
        // Type filter chips
        LazyRow(
            modifier = Modifier.fillMaxWidth(),
            contentPadding = PaddingValues(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            item {
                SymbolTypeChip(
                    label = "All",
                    count = typeCounts[null] ?: 0,
                    isSelected = selectedTypeFilter == null,
                    onClick = { selectedTypeFilter = null },
                    icon = Icons.Default Apps
                )
            }
            
            item {
                SymbolTypeChip(
                    label = "Function",
                    count = typeCounts[SymbolType.FUNCTION] ?: 0,
                    isSelected = selectedTypeFilter == SymbolType.FUNCTION,
                    onClick = { selectedTypeFilter = SymbolType.FUNCTION },
                    icon = Icons.Default.Functions
                )
            }
            
            item {
                SymbolTypeChip(
                    label = "Object",
                    count = typeCounts[SymbolType.OBJECT] ?: 0,
                    isSelected = selectedTypeFilter == SymbolType.OBJECT,
                    onClick = { selectedTypeFilter = SymbolType.OBJECT },
                    icon = Icons.Default.DataObject
                )
            }
            
            item {
                SymbolTypeChip(
                    label = "Section",
                    count = typeCounts[SymbolType.SECTION] ?: 0,
                    isSelected = selectedTypeFilter == SymbolType.SECTION,
                    onClick = { selectedTypeFilter = SymbolType.SECTION },
                    icon = Icons.Default.ViewModule
                )
            }
            
            item {
                SymbolTypeChip(
                    label = "File",
                    count = typeCounts[SymbolType.FILE] ?: 0,
                    isSelected = selectedTypeFilter == SymbolType.FILE,
                    onClick = { selectedTypeFilter = SymbolType.FILE },
                    icon = Icons.Default.Description
                )
            }
        }
        
        Spacer(Modifier.height(8.dp))
        
        // Results count
        Text(
            text = "${filteredSymbols.size} of ${symbols.size} symbols",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 16.dp)
        )
        
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
                            text = "Loading symbols...",
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
            
            filteredSymbols.isEmpty() && !isLoading -> {
                EmptyStateCard(
                    icon = Icons.Default.Symbol,
                    title = "No Symbols Found",
                    description = if (symbols.isEmpty()) {
                        "Load an ELF binary file to view its symbol table"
                    } else {
                        "No symbols match your search criteria"
                    }
                )
            }
            
            else -> {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(vertical = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    items(
                        items = filteredSymbols,
                        key = { "${it.name}_${it.value}" }
                    ) { symbol ->
                        SymbolListItem(
                            symbol = symbol,
                            onClick = { 
                                if (symbol.type == SymbolType.FUNCTION || symbol.type == SymbolType.OBJECT) {
                                    onNavigateToAddress(symbol.value)
                                }
                            }
                        )
                    }
                }
            }
        }
    }
}

/**
 * Type filter chip for symbol types
 */
@Composable
private fun SymbolTypeChip(
    label: String,
    count: Int,
    isSelected: Boolean,
    onClick: () -> Unit,
    icon: androidx.compose.ui.graphics.vector.ImageVector
) {
    FilterChip(
        selected = isSelected,
        onClick = onClick,
        label = {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                Icon(icon, contentDescription = null, Modifier.size(16.dp))
                Text(label)
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = if (isSelected) MaterialTheme.colorScheme.primary.copy(alpha = 0.3f)
                             else MaterialTheme.colorScheme.surfaceVariant
                ) {
                    Text(
                        text = "$count",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 1.dp)
                    )
                }
            }
        },
        leadingIcon = null
    )
}

/**
 * Single symbol list item
 */
@Composable
private fun SymbolListItem(
    symbol: Symbol,
    onClick: () -> Unit
) {
    val typeColor = when (symbol.type) {
        SymbolType.FUNCTION -> Success
        SymbolType.OBJECT -> Info
        SymbolType.SECTION -> AsmKeyword
        SymbolType.FILE -> AsmImmediate
        else -> OnSurfaceVariant
    }
    
    val typeIcon = when (symbol.type) {
        SymbolType.FUNCTION -> Icons.Default.Functions
        SymbolType.OBJECT -> Icons.Default.DataObject
        SymbolType.SECTION -> Icons.Default.ViewModule
        SymbolType.FILE -> Icons.Default.Description
        else -> Icons.Default.Symbol
    }
    
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 2.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        onClick = onClick
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Type icon
            Icon(
                icon,
                contentDescription = symbol.type.name,
                tint = typeColor,
                modifier = Modifier.size(24.dp)
            )
            
            Spacer(Modifier.width(12.dp))
            
            // Symbol info column
            Column(modifier = Modifier.weight(1f)) {
                // Symbol name
                Text(
                    text = symbol.name.ifBlank { "<unnamed>" },
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1
                )
                
                // Value and size row
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Value/address
                    Text(
                        text = BinaryUtils.toHexString(symbol.value),
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall,
                        color = AsmAddress
                    )
                    
                    // Size (if applicable)
                    if (symbol.size > 0) {
                        Text(
                            text = "${symbol.size} bytes",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    // Section name
                    if (symbol.sectionName.isNotBlank()) {
                        Text(
                            text = "[${symbol.sectionName}]",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                    
                    // Type badge
                    Surface(
                        shape = MaterialTheme.shapes.extraSmall,
                        color = typeColor.copy(alpha = 0.15f)
                    ) {
                        Text(
                            text = symbol.type.name,
                            style = MaterialTheme.typography.labelSmall,
                            color = typeColor,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 1.dp)
                        )
                    }
                }
            }
            
            // Navigate button (for functions and objects)
            if (symbol.type == SymbolType.FUNCTION || symbol.type == SymbolType.OBJECT) {
                IconButton(onClick = onClick, modifier = Modifier.size(36.dp)) {
                    Icon(
                        Icons.Default.OpenInNew,
                        contentDescription = "Go to address",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }
    }
}
