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
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.compose.collectAsState
import com.mobile.idapro.data.model.Bookmark
import com.mobile.idapro.utils.BinaryUtils
import com.mobile.idapro.viewmodel.MainViewModel

/**
 * Bookmarks Screen (from KTIMAZ-REV - enhanced for v3.0)
 * 
 * Features:
 * - Persistent bookmarks list (stored via Room database)
 * - Add new bookmark with name, address, and comment
 * - Edit existing bookmark details
 * - Delete bookmark with confirmation
 * - Navigate to bookmark address in disassembly/hex view
 * - Search and filter bookmarks
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BookmarksScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier,
    onNavigateToAddress: (Long) -> Unit = {}
) {
    val bookmarks by viewModel.bookmarks.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    
    var searchQuery by remember { mutableStateOf("") }
    var showAddDialog by remember { mutableStateOf(false) }
    var editingBookmark by remember { mutableStateOf<Bookmark?>(null) }
    var deletingBookmark by remember { mutableStateOf<Bookmark?>(null) }
    
    // Filter bookmarks based on search
    val filteredBookmarks = remember(searchQuery, bookmarks) {
        if (searchQuery.isBlank()) {
            bookmarks
        } else {
            val query = searchQuery.lowercase()
            bookmarks.filter { bookmark ->
                bookmark.name.lowercase().contains(query) ||
                bookmark.comment.lowercase().contains(query) ||
                BinaryUtils.toHexString(bookmark.address).lowercase().contains(query)
            }
        }
    }
    
    Column(modifier = modifier.fillMaxSize()) {
        // Header with title and add button
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "Bookmarks",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "${bookmarks.size} saved",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            FilledTonalButton(
                onClick = { showAddDialog = true }
            ) {
                Icon(Icons.Default.Add, contentDescription = null)
                Spacer(Modifier.width(4.dp))
                Text("Add")
            }
        }
        
        // Search bar
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Search bookmarks...") },
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
                            text = "Loading bookmarks...",
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
            
            filteredBookmarks.isEmpty() && !isLoading -> {
                EmptyStateCard(
                    icon = Icons.Default.Bookmark,
                    title = if (bookmarks.isEmpty()) "No Bookmarks" else "No Results",
                    description = if (bookmarks.isEmpty()) {
                        "Long-press on instructions or use the + button to add bookmarks"
                    } else {
                        "No bookmarks match your search"
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
                        items = filteredBookmarks,
                        key = { it.uid }
                    ) { bookmark ->
                        BookmarkListItem(
                            bookmark = bookmark,
                            onClick = { onNavigateToAddress(bookmark.address) },
                            onEditClick = { editingBookmark = bookmark },
                            onDeleteClick = { deletingBookmark = bookmark }
                        )
                    }
                }
            }
        }
    }
    
    // Add bookmark dialog
    if (showAddDialog) {
        AddEditBookmarkDialog(
            isEditing = false,
            initialName = "",
            initialAddress = "",
            initialComment = "",
            onDismiss = { showAddDialog = false },
            onSave = { name, addressStr, comment ->
                val address = BinaryUtils.parseHexString(addressStr) ?: 0L
                viewModel.addBookmark(address, name, comment)
                showAddDialog = false
            }
        )
    }
    
    // Edit bookmark dialog
    editingBookmark?.let { bookmark ->
        AddEditBookmarkDialog(
            isEditing = true,
            initialName = bookmark.name,
            initialAddress = BinaryUtils.toHexString(bookmark.address),
            initialComment = bookmark.comment,
            onDismiss = { editingBookmark = null },
            onSave = { name, _, comment ->
                // For edit, we would need an update method in ViewModel
                // For now, we delete old and add new
                viewModel.removeBookmark(bookmark)
                val newAddress = bookmark.address // Keep same address
                viewModel.addBookmark(newAddress, name, comment)
                editingBookmark = null
            }
        )
    }
    
    // Delete confirmation dialog
    deletingBookmark?.let { bookmark ->
        AlertDialog(
            onDismissRequest = { deletingBookmark = null },
            icon = {
                Icon(Icons.Default.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error)
            },
            title = { Text("Delete Bookmark") },
            text = { 
                Text("Are you sure you want to delete '${bookmark.name}'?\n\nThis action cannot be undone.")
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.removeBookmark(bookmark)
                        deletingBookmark = null
                    }
                ) {
                    Text("Delete", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { deletingBookmark = null }) {
                    Text("Cancel")
                }
            }
        )
    }
}

/**
 * Single bookmark list item
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BookmarkListItem(
    bookmark: Bookmark,
    onClick: () -> Unit,
    onEditClick: () -> Unit,
    onDeleteClick: () -> Unit
) {
    var showMenu by remember { mutableStateOf(false) }
    
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
            // Bookmark icon
            Icon(
                Icons.Default.Bookmark,
                contentDescription = "Bookmark",
                tint = AsmImmediate, // Yellow/gold color for bookmarks
                modifier = Modifier.size(24.dp)
            )
            
            Spacer(Modifier.width(12.dp))
            
            // Bookmark info column
            Column(modifier = Modifier.weight(1f)) {
                // Name
                Text(
                    text = bookmark.name.ifBlank { "<unnamed>" },
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1
                )
                
                // Address and comment row
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Address
                    Text(
                        text = bookmark.getAddressString(),
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall,
                        color = AsmAddress
                    )
                    
                    // Comment (if present)
                    if (bookmark.comment.isNotBlank()) {
                        Text(
                            text = "• ${bookmark.comment}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1
                        )
                    }
                }
            }
            
            // Menu button
            Box {
                IconButton(onClick = { showMenu = true }) {
                    Icon(
                        Icons.Default.MoreVert,
                        contentDescription = "Options",
                        modifier = Modifier.size(20.dp)
                    )
                }
                
                DropdownMenu(
                    expanded = showMenu,
                    onDismissRequest = { showMenu = false }
                ) {
                    DropdownMenuItem(
                        text = { 
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.OpenInNew, contentDescription = null, Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text("Go to Address")
                            } 
                        },
                        onClick = {
                            onClick()
                            showMenu = false
                        }
                    )
                    
                    DropdownMenuItem(
                        text = { 
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Edit, contentDescription = null, Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text("Edit")
                            } 
                        },
                        onClick = {
                            onEditClick()
                            showMenu = false
                        }
                    )
                    
                    HorizontalDivider()
                    
                    DropdownMenuItem(
                        text = { 
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Delete, contentDescription = null, Modifier.size(18.dp), tint = MaterialTheme.colorScheme.error)
                                Spacer(Modifier.width(8.dp))
                                Text("Delete", color = MaterialTheme.colorScheme.error)
                            } 
                        },
                        onClick = {
                            onDeleteClick()
                            showMenu = false
                        }
                    )
                }
            }
        }
    }
}

/**
 * Add/Edit bookmark dialog
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddEditBookmarkDialog(
    isEditing: Boolean,
    initialName: String,
    initialAddress: String,
    initialComment: String,
    onDismiss: () -> Unit,
    onSave: (name: String, address: String, comment: String) -> Unit
) {
    var name by remember(initialName) { mutableStateOf(initialName) }
    var addressStr by remember(initialAddress) { mutableStateOf(initialAddress) }
    var comment by remember(initialComment) { mutableStateOf(initialComment) }
    var addressError by remember { mutableStateOf<String?>(null) }
    
    val isValidAddress = remember(addressStr) {
        try {
            addressStr.removePrefix("0x").removePrefix("0X").toLongOrNull() != null || addressStr.isBlank()
        } catch (e: Exception) {
            false
        }
    }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = {
            Icon(
                if (isEditing) Icons.Default.Edit else Icons.Default.BookmarkAdd,
                contentDescription = null
            )
        },
        title = { 
            Text(if (isEditing) "Edit Bookmark" else "Add Bookmark")
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Name *") },
                    placeholder = { Text("Enter bookmark name...") },
                    singleLine = true,
                    isError = name.isBlank(),
                    supportingText = {
                        if (name.isBlank()) {
                            Text("Name is required", color = MaterialTheme.colorScheme.error)
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                )
                
                OutlinedTextField(
                    value = addressStr,
                    onValueChange = { 
                        addressStr = it
                        addressError = if (!isValidAddress && it.isNotBlank()) {
                            "Invalid hex address"
                        } else null
                    },
                    label = { Text("Address *") },
                    placeholder = { Text("0x00000000") },
                    prefix = { Text("0x", color = MaterialTheme.colorScheme.onSurfaceVariant) },
                    singleLine = true,
                    isError = !isValidAddress && addressStr.isNotBlank(),
                    supportingText = {
                        if (addressError != null) {
                            Text(addressError!!, color = MaterialTheme.colorScheme.error)
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                )
                
                OutlinedTextField(
                    value = comment,
                    onValueChange = { comment = it },
                    label = { Text("Comment (optional)") },
                    placeholder = { Text("Add a note...") },
                    minLines = 2,
                    maxLines = 4,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { 
                    if (name.isNotBlank() && isValidAddress) {
                        onSave(name, addressStr, comment)
                    }
                },
                enabled = name.isNotBlank() && isValidAddress
            ) {
                Text(if (isEditing) "Save" else "Add")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}
