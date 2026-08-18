package com.mobile.idapro.ui.screens

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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel

/**
 * IDA Pro M - Strings Screen
 * 
 * Displays extracted strings from the binary with filtering,
 * encoding information, and navigation to string references.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StringsScreen(
    fileId: Long,
    onBack: () -> Unit,
    onNavigateToAddress: (Long) -> Unit = {}
) {
    val viewModel: StringsViewModel = hiltViewModel()
    
    val strings by viewModel.strings.collectAsState()
    val filter by viewModel.filter.collectAsState()
    val totalCount by viewModel.totalCount.collectAsState()
    val filteredCount by viewModel.filteredCount.collectAsState()
    
    // UI state
    var showFilterOptions by remember { mutableStateOf(false) }
    var selectedEncoding by remember { mutableStateOf(StringFilter.ALL) }
    
    LaunchedEffect(fileId) {
        viewModel.loadStrings(fileId)
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Strings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { showFilterOptions = true }) {
                        Icon(Icons.Default.FilterList, contentDescription = "Filter")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
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
                    Text("Total: $totalCount", style = MaterialTheme.typography.labelMedium)
                    
                    if (!filter.isEmpty()) {
                        Text("Filtered: $filteredCount", style = MaterialTheme.typography.labelMedium,
                             color = MaterialTheme.colorScheme.primary)
                    } else {
                        Text("Showing all", style = MaterialTheme.typography.labelSmall,
                             color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    ) { paddingValues ->
        Column(modifier = Modifier.padding(paddingValues)) {
            // Search bar
            OutlinedTextField(
                value = filter,
                onValueChange = { viewModel.setFilter(it) },
                placeholder = { Text("Search strings...") },
                leadingIcon = { Icon(Icons.Default.Search, null) },
                trailingIcon = {
                    if (filter.isNotEmpty()) {
                        IconButton(onClick = { viewModel.setFilter("") }) {
                            Icon(Icons.Default.Clear, contentDescription = "Clear")
                        }
                    }
                },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp)
            )
            
            // Strings list
            if (strings.isEmpty()) {
                EmptyStringsView()
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(2.dp),
                    contentPadding = PaddingValues(vertical = 4.dp, horizontal = 12.dp)
                ) {
                    items(strings.filter { 
                        if (filter.isEmpty()) true 
                        else it.value.contains(filter, ignoreCase = true) 
                    }, key = { it.id }) { string ->
                        StringItem(
                            stringEntry = string,
                            onClick = { onNavigateToAddress(string.address) }
                        )
                    }
                }
            }
        }
        
        // Filter options dialog
        if (showFilterOptions) {
            FilterOptionsDialog(
                currentEncoding = selectedEncoding,
                onEncodingSelected = { enc ->
                    selectedEncoding = enc
                    showFilterOptions = false
                },
                onDismiss = { showFilterOptions = false }
            )
        }
    }
}

@Composable
private fun StringItem(
    stringEntry: com.mobile.idapro.data.model.StringEntry,
    onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp)
        ) {
            // Header row with address and encoding
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Address
                Text(
                    text = "0x${stringEntry.address.toString(16).padStart(8, '0')}",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = SyntaxAddress
                )
                
                // Encoding badge
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = when (stringEntry.encoding) {
                        com.mobile.idapro.data.model.StringEncoding.UTF16_LE -> MaterialTheme.colorScheme.secondaryContainer
                        com.mobile.idapro.data.model.StringEncoding.UTF8 -> MaterialTheme.colorScheme.tertiaryContainer
                        else -> MaterialTheme.colorScheme.surfaceVariant
                    }
                ) {
                    Text(
                        text = stringEntry.encoding.name,
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
                
                // Type badge
                if (stringEntry.type != com.mobile.idapro.data.model.StringType.PRINTABLE &&
                    stringEntry.type != com.mobile.idapro.data.model.StringType.UNKNOWN) {
                    Surface(
                        shape = MaterialTheme.shapes.small,
                        color = MaterialTheme.colorScheme.primaryContainer
                    ) {
                        Text(
                            text = stringEntry.type.name.lowercase().replace("_", " "),
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            maxLines = 1
                        )
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(6.dp))
            
            // String value
            Text(
                text = stringEntry.getEscapedValue(),
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp,
                lineHeight = 18.sp,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
                color = SyntaxString
            )
            
            // Metadata row
            Row(
                modifier = Modifier.padding(top = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Default.TextFields,
                    contentDescription = null,
                    modifier = Modifier.size(14.dp),
                    tint = MaterialTheme.colorScheme.outline
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    text = "${stringEntry.length} chars (${stringEntry.byteLength} bytes)",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.outline
                )
                
                if (stringEntry.isReferenced) {
                    Spacer(modifier = Modifier.width(12.dp))
                    Icon(Icons.Default.CallMade, null, modifier = Modifier.size(14.dp), tint = StatusInfo)
                    Text("Referenced", style = MaterialTheme.typography.labelSmall, color = StatusInfo)
                }
            }
        }
    }
}

enum class StringFilter(val displayName: String) {
    ALL("All"),
    ASCII("ASCII"),
    WIDE("Wide"),
    UNICODE("Unicode"),
    FORMAT("Format"),
    PATH("Path/URL")
}

@Composable
private fun FilterOptionsDialog(
    currentEncoding: StringFilter,
    onEncodingSelected: (StringFilter) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("String Filters") },
        text = {
            Column {
                Text("Encoding:", style = MaterialTheme.typography.titleSmall)
                Spacer(modifier = Modifier.height(8.dp))
                
                StringFilter.entries.forEach { filter ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp)
                    ) {
                        RadioButton(
                            selected = filter == currentEncoding,
                            onClick = { onEncodingSelected(filter) }
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(filter.displayName)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Apply") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

@Composable
private fun EmptyStringsView() {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Default.TextSnippetOff, null, modifier = Modifier.size(64.dp), tint = MaterialTheme.colorScheme.outline)
            Spacer(modifier = Modifier.height(16.dp))
            Text("No strings found", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            Text("Run analysis to extract strings from binary data",
                 style = MaterialTheme.typography.bodyMedium,
                 color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
