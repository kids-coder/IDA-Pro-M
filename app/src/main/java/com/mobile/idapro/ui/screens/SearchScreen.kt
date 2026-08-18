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
 * IDA Pro M - Search Screen
 * 
 * Provides comprehensive search functionality across instructions,
 * strings, addresses, and patterns in analyzed binaries.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SearchScreen(
    fileId: Long,
    onBack: () -> Unit,
    onNavigateToAddress: (Long) -> Unit = {}
) {
    val viewModel: SearchViewModel = hiltViewModel()
    
    val searchQuery by viewModel.searchQuery.collectAsState()
    val searchType by viewModel.searchType.collectAsState()
    val searchResults by viewModel.searchResults.collectAsState()
    val isSearching by viewModel.isSearching.collectAsState()
    val resultCount by viewModel.resultCount.collectAsState()
    
    // UI state
    var showSearchOptions by remember { mutableStateOf(false) }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Search") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { showSearchOptions = true }) {
                        Icon(Icons.Default.Tune, contentDescription = "Search options")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            if (resultCount > 0) {
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
                        Text("$resultCount results found", style = MaterialTheme.typography.labelMedium)
                        
                        Button(onClick = { /* Export results */ }) {
                            Text("Export")
                        }
                    }
                }
            }
        }
    ) { paddingValues ->
        Column(modifier = Modifier.padding(paddingValues)) {
            // Search input with type selector
            SearchBar(
                query = searchQuery,
                onQueryChange = { viewModel.updateQuery(it) },
                searchType = searchType,
                onTypeChange = { viewModel.setSearchType(it) },
                onSearch = { viewModel.executeSearch() },
                isSearching = isSearching
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // Results header
            if (!isSearching && resultCount > 0) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Results", style = MaterialStyle.titleSmall)
                    
                    // Sort options
                    IconButton(onClick = { /* Toggle sort */ }) {
                        Icon(Icons.Default.Sort, contentDescription = "Sort")
                    }
                }
                
                HorizontalDivider()
            }
            
            // Search results or empty state
            if (isSearching) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator()
                        Spacer(modifier = Modifier.height(16.dp))
                        Text("Searching...", style = MaterialTheme.typography.bodyMedium)
                    }
                }
            } else if (searchResults.isEmpty() && searchQuery.isNotEmpty()) {
                EmptySearchResults(query = searchQuery)
            } else if (searchResults.isEmpty()) {
                InitialSearchPrompt(searchType = searchType)
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                    contentPadding = PaddingValues(vertical = 4.dp, horizontal = 12.dp)
                ) {
                    items(searchResults, key = it.id) { result ->
                        SearchResultItem(
                            result = result,
                            onClick = { 
                                when (result) {
                                    is SearchResult.Instruction -> onNavigateToAddress(result.address)
                                    is SearchResult.StringResult -> onNavigateToAddress(result.address)
                                    else -> {}
                                }
                            }
                        )
                    }
                }
            }
        }
        
        // Search options dialog
        if (showSearchOptions) {
            SearchOptionsDialog(
                currentType = searchType,
                onTypeSelected = { 
                    viewModel.setSearchType(it)
                    showSearchOptions = false
                },
                onDismiss = { showSearchOptions = false }
            )
        }
    }
}

@Composable
private fun SearchBar(
    query: String,
    onQueryChange: (String) -> Unit,
    searchType: SearchType,
    onTypeChange: (SearchType) -> Unit,
    onSearch: () -> Unit,
    isSearching: Boolean
) {
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Type selector chip
            FilterChip(
                selected = false,
                onClick = { /* Show type picker */ },
                label = { Text(searchType.displayName) },
                leadingIcon = { Icon(getIconForType(searchType), null, modifier = Modifier.size(18.dp)) }
            )
            
            Spacer(modifier = Modifier.width(8.dp))
            
            // Search text field
            OutlinedTextField(
                value = query,
                onValueChange = onQueryChange,
                placeholder = { Text("Enter search query...") },
                leadingIcon = { Icon(Icons.Default.Search, null) },
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { onQueryChange("") }) {
                            Icon(Icons.Default.Clear, null)
                        }
                    }
                },
                singleLine = true,
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                    keyboardType = androidx.compose.foundation.text.KeyboardType.Text,
                    imeAction = androidx.compose.foundation.text.ImeAction.Search
                ),
                keyboardActions = KeyboardActions(
                    onSearch = { onSearch() }
                ),
                modifier = Modifier.weight(1f)
            )
            
            // Search button
            IconButton(
                onClick = onSearch,
                enabled = query.isNotEmpty() && !isSearching
            ) {
                if (isSearching) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                } else {
                    Icon(Icons.Default.Search, contentDescription = "Search")
                }
            }
        }
        
        // Quick filter chips
        ScrollableRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            contentPadding = PaddingValues(vertical = 4.dp)
        ) {
            FilterChip(selected = false, onClick = {}, label = { Text("Case sensitive") })
            FilterChip(selected = false, onClick = {}, label = { Text("Whole word") })
            FilterChip(selected = false, onClick = {}, label = { Text("Regex") })
        }
    }
}

private fun getIconForType(type: SearchType): androidx.compose.ui.graphics.vector.ImageVector {
    return when (type) {
        SearchType.INSTRUCTIONS -> Icons.Default.Code
        SearchType.HEX_PATTERN -> Icons.Default.DataArray
        SearchType.STRINGS -> Icons.Default.TextFields
        SearchType.ADDRESSES -> Icons.Default.GpsFixed
    }
}

@Composable
private fun SearchResultItem(
    result: SearchResult,
    onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Result type icon
            Icon(
                imageVector = when (result) {
                    is SearchResult.Instruction -> Icons.Default.Code
                    is SearchResult.StringResult -> Icons.Default.TextFields
                    else -> Icons.Default.LocationOn
                },
                contentDescription = null,
                modifier = Modifier.size(32.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            
            Spacer(modifier = Modifier.width(12.dp))
            
            // Result details
            Column(modifier = Modifier.weight(1f)) {
                when (result) {
                    is SearchResult.Instruction -> {
                        Text(
                            text = "${result.mnemonic} ${result.operands}",
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = "0x${result.address.toString(16).padStart(8, '0')}",
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                    is SearchResult.StringResult -> {
                        Text(
                            text = result.value.take(50) + if (result.value.length > 50) "..." else "",
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = "0x${result.address.toString(16)} • ${result.encoding}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                    else -> {
                        Text("Unknown result type", color = MaterialTheme.colorScheme.error)
                    }
                }
            }
            
            // Navigate arrow
            Icon(
                Icons.Default.ChevronRight,
                contentDescription = "Navigate",
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

enum class SearchType(val displayName: String) {
    INSTRUCTIONS("Instructions"),
    HEX_PATTERN("Hex Pattern"),
    STRINGS("Strings"),
    ADDRESSES("Addresses")
}

sealed class SearchResult {
    abstract val id: Long
    abstract val address: Long
    
    data class Instruction(
        override val id: Long,
        override val address: Long,
        val mnemonic: String,
        val operands: String,
        val rawBytes: ByteArray
    ) : SearchResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Instruction
            return id == other.id && address == other.address
        }
        override fun hashCode(): Int = id.hashCode()
    }
    
    data class StringResult(
        override val id: Long,
        override val address: Long,
        val value: String,
        val encoding: String
    ) : SearchResult()
}

// ============================================================================
// Search ViewModel
// ============================================================================

@HiltViewModel
class SearchViewModel @Inject constructor() : ViewModel() {
    
    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateLoop()
    
    private val _searchType = MutableStateFlow(SearchType.INSTRUCTIONS)
    val searchType: StateFlow<SearchType> = _searchType.asStateLoop()
    
    private val _searchResults = MutableStateFlow<List<SearchResult>>(emptyList())
    val searchResults: StateFlow<List<SearchResult>> = _searchResults.asStateLoop()
    
    private val _isSearching = MutableStateFlow(false)
    val isSearching: StateFlow<Boolean> = _isSearching.asStateLoop()
    
    private val _resultCount = MutableStateFlow(0)
    val resultCount: StateFlow<Int> = _resultCount.asStateLoop()
    
    fun updateQuery(query: String) {
        _searchQuery.value = query
    }
    
    fun setSearchType(type: SearchType) {
        _searchType.value = type
    }
    
    fun executeSearch() {
        val query = _searchQuery.value
        if (query.isEmpty()) return
        
        _isSearching.value = true
        
        // Simulate search (would use native engine in real implementation)
        kotlinx.coroutines.GlobalScope.launch(kotlinx.coroutines.Dispatchers.Default) {
            kotlinx.coroutines.delay(500) // Simulate search time
            
            // Generate sample results based on search type
            val results = when (_searchType.value) {
                SearchType.INSTRUCTIONS -> generateSampleInstructionResults(query)
                SearchType.STRINGS -> generateSampleStringResults(query)
                else -> emptyList()
            }
            
            _searchResults.value = results
            _resultCount.value = results.size
            _isSearching.value = false
        }
    }
    
    private fun generateSampleInstructionResults(query: List<SearchResult>): List<SearchResult> {
        return listOf(
            SearchResult.Instruction(
                id = 1,
                address = 0x1000,
                mnemonic = "mov",
                operands = "r0, r1",
                rawBytes = byteArrayOf(0x01, 0x00, 0xA0, 0xE1)
            ),
            SearchResult.Instruction(
                id = 2,
                address = 0x1004,
                mnemonic = "add",
                operands = "r2, r3, #4",
                rawBytes = byteArrayOf(0x02, 0x00, 0x83, 0xE2)
            )
        )
    }
    
    private fun generateSampleStringResults(query: String): List<SearchResult> {
        return listOf(
            SearchResult.StringResult(
                id = 1,
                address = 0x2000,
                value = "Hello, World!",
                encoding = "ASCII"
            ),
            SearchResult.StringResult(
                id = 2,
                address = 0x2010,
                value = "/data/local/tmp/file.bin",
                encoding = "UTF-8"
            )
        )
    }
}

@Composable
private fun SearchOptionsDialog(
    currentType: SearchType,
    onTypeSelected: (SearchType) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Search Options") },
        text = {
            Column {
                Text("Search in:", style = MaterialTheme.typography.titleSmall)
                Spacer(modifier = Modifier.height(8.dp))
                
                SearchType.entries.forEach { type ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 6.dp)
                    ) {
                        RadioButton(
                            selected = type == currentType,
                            onClick = { onTypeSelected(type) }
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(type.displayName)
                    }
                }
                
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                
                Text("Options:", style = MaterialTheme.typography.titleSmall)
                Spacer(modifier = Modifier.height(8.dp))
                
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = false, onCheckedChange = {})
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Case sensitive")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = false, onCheckedChange = {})
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Match whole word only")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = false, onCheckedChange = {})
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Use regular expression")
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
private fun EmptySearchResults(query: String) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Default.SearchOff, null, modifier = Modifier.size(64.dp), tint = MaterialTheme.colorScheme.outline)
            Spacer(modifier = Modifier.height(16.dp))
            Text("No results found for \"$query\"", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            Text("Try different keywords or adjust search options",
                 style = MaterialTheme.typography.bodyMedium,
                 color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun InitialSearchPrompt(searchType: SearchType) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Default.ManageSearch, null, modifier = Modifier.size(64.dp), tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f))
            Spacer(modifier = Modifier.height(16.dp))
            Text("Search ${searchType.displayName.lowercase()}", style = MaterialTheme.typography.headlineSmall)
            Spacer(modifier = Modifier.height(8.dp))
            Text("Enter a search term above to find matching items",
                 style = MaterialTheme.typography.bodyLarge,
                 color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
