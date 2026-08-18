package com.mobile.idapro.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
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
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsState
import com.mobile.idapro.data.model.DisassemblyInstruction
import com.mobile.idapro.ui.theme.*
import com.mobile.idapro.utils.BinaryUtils
import com.mobile.idapro.viewmodel.MainViewModel

/**
 * Disassembly Screen (from IDA Pro Mobile - enhanced for v3.0)
 * 
 * Features:
 * - Syntax-highlighted disassembled instructions (IDA-style colors)
 * - Search/filter functionality with debouncing
 * - Annotation dialog on click
 * - Bookmark creation on long-press
 * - Scroll to address support
 * - Function start highlighting
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun DisassemblyScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier,
    onNavigateToAddress: (Long) -> Unit = {}
) {
    val instructions by viewModel.filteredInstructions.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    val searchQuery by viewModel.searchQuery.collectAsState()
    
    var selectedInstruction by remember { mutableStateOf<DisassemblyInstruction?>(null) }
    var showAnnotationDialog by remember { mutableStateOf(false) }
    var showBookmarkDialog by remember { mutableStateOf(false) }
    var annotationText by remember { mutableStateOf("") }
    
    val listState = rememberLazyListState()
    
    Column(modifier = modifier.fillMaxSize()) {
        // Search bar
        SearchBar(
            query = searchQuery,
            onQueryChange = viewModel::updateSearchQuery,
            placeholder = { Text("Search instructions...") },
            leadingIcon = {
                Icon(Icons.Default.Search, contentDescription = "Search")
            },
            trailingIcon = {
                if (searchQuery.isNotEmpty()) {
                    IconButton(onClick = { viewModel.updateSearchQuery("") }) {
                        Icon(Icons.Default.Clear, contentDescription = "Clear")
                    }
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) {}
        
        Spacer(modifier = Modifier.height(8.dp))
        
        // Instructions count
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "${instructions.size} instructions",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            if (selectedInstruction != null) {
                TextButton(onClick = { 
                    showBookmarkDialog = true 
                }) {
                    Icon(
                        Icons.Default.BookmarkAdd,
                        contentDescription = "Add Bookmark",
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(4.dp))
                    Text("Bookmark")
                }
            }
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
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
                            text = "Loading disassembly...",
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
            
            instructions.isEmpty() && !isLoading -> {
                EmptyStateCard(
                    icon = Icons.Default.Code,
                    title = "No Instructions",
                    description = "Load a binary file to view disassembled instructions"
                )
            }
            
            else -> {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(vertical = 4.dp)
                ) {
                    itemsIndexed(
                        items = instructions,
                        key = { _, instr -> instr.address }
                    ) { index, instruction ->
                        val backgroundColor by animateColorAsState(
                            targetValue = if (instruction.isFunction) AsmFunctionStart.copy(alpha = 0.3f)
                                         else Color.Transparent,
                            label = "background"
                        )
                        
                        DisassemblyInstructionItem(
                            instruction = instruction,
                            isSelected = selectedInstruction?.address == instruction.address,
                            backgroundColor = backgroundColor,
                            onClick = {
                                selectedInstruction = instruction
                                showAnnotationDialog = true
                            },
                            onLongClick = {
                                selectedInstruction = instruction
                                showBookmarkDialog = true
                            },
                            onAddressClick = { onNavigateToAddress(it) }
                        )
                    }
                }
            }
        }
    }
    
    // Annotation dialog
    if (showAnnotationDialog && selectedInstruction != null) {
        AnnotationDialog(
            instruction = selectedInstruction!!,
            currentAnnotation = annotationText,
            onDismiss = { 
                showAnnotationDialog = false 
                annotationText = ""
            },
            onSave = { comment ->
                // Save annotation logic would go here
                annotationText = comment
                showAnnotationDialog = false
            }
        )
    }
    
    // Bookmark dialog
    if (showBookmarkDialog && selectedInstruction != null) {
        BookmarkDialog(
            address = selectedInstruction!!.address,
            defaultName = "Bookmark @ ${BinaryUtils.toHexString(selectedInstruction!!.address)}",
            onDismiss = { showBookmarkDialog = false },
            onSave = { name, comment ->
                viewModel.addBookmark(selectedInstruction!!.address, name, comment)
                showBookmarkDialog = false
            }
        )
    }
}

/**
 * Single disassembly instruction row with syntax highlighting
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun DisassemblyInstructionItem(
    instruction: DisassemblyInstruction,
    isSelected: Boolean,
    backgroundColor: Color,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
    onAddressClick: (Long) -> Unit
) {
    val surfaceColor = if (isSelected) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        backgroundColor
    }
    
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(surfaceColor)
            .combinedClickable(
                onClick = onClick,
                onLongClick = onLongClick
            )
            .padding(horizontal = 16.dp, vertical = 6.dp),
        verticalAlignment = Alignment.Top
    ) {
        // Address column
        Text(
            text = instruction.toHexString(),
            color = AsmAddress,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.clickable { onAddressClick(instruction.address) }
        )
        
        Spacer(Modifier.width(16.dp))
        
        // Bytes column (optional - shown for reference)
        if (instruction.bytes.isNotEmpty()) {
            Text(
                text = BinaryUtils.toRawBytesHexString(instruction.rawBytes, instruction.byteLength),
                color = OnSurfaceVariant,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.width(100.dp)
            )
            
            Spacer(Modifier.width(16.dp))
        }
        
        // Mnemonic (instruction)
        Text(
            text = instruction.mnemonic,
            color = AsmKeyword,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.width(80.dp)
        )
        
        Spacer(Modifier.width(8.dp))
        
        // Operands with syntax highlighting
        Text(
            text = buildAnnotatedOperands(instruction),
            color = OnSurface,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f)
        )
        
        // Comment if present
        instruction.comment?.let { comment ->
            Spacer(Modifier.width(8.dp))
            Text(
                text = "; $comment",
                color = AsmComment,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall
            )
        }
        
        // Jump/Branch indicators
        if (instruction.isJump || instruction.isBranch) {
            Spacer(Modifier.width(8.dp))
            Icon(
                imageVector = if (instruction.isJump) Icons.Default.ArrowForward else Icons.Default.CallMade,
                contentDescription = if (instruction.isJump) "Jump" else "Call",
                tint = if (instruction.isJump) AsmJumpTarget else AsmBranchTarget,
                modifier = Modifier.size(16.dp)
            )
        }
    }
}

/**
 * Build annotated operands string with register/immediate highlighting
 */
@Composable
private fun buildAnnotatedOperands(instruction: DisassemblyInstruction): String {
    return buildString {
        instruction.operands.forEachIndexed { index, operand ->
            if (index > 0) append(", ")
            append(operand)
        }
    }
}

/**
 * Annotation dialog for adding/editing comments on instructions
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AnnotationDialog(
    instruction: DisassemblyInstruction,
    currentAnnotation: String,
    onDismiss: () -> Unit,
    onSave: (String) -> Unit
) {
    var text by remember(currentAnnotation) { mutableStateOf(currentAnnotation) }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { 
            Text("Add Annotation")
        },
        text = {
            Column {
                Text(
                    text = "Address: ${instruction.toHexString()}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "${instruction.mnemonic} ${instruction.getOperandsString()}",
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    color = AsmKeyword
                )
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    label = { Text("Comment") },
                    placeholder = { Text("Enter your annotation...") },
                    minLines = 2,
                    maxLines = 5,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onSave(text) },
                enabled = text.isNotBlank()
            ) {
                Text("Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

/**
 * Bookmark dialog for creating bookmarks from instructions
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BookmarkDialog(
    address: Long,
    defaultName: String,
    onDismiss: () -> Unit,
    onSave: (name: String, comment: String) -> Unit
) {
    var name by remember(defaultName) { mutableStateOf(defaultName) }
    var comment by remember { mutableStateOf("") }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { 
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.BookmarkAdd, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Add Bookmark")
            }
        },
        text = {
            Column {
                Text(
                    text = "Address: ${BinaryUtils.toHexString(address)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Bookmark Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = comment,
                    onValueChange = { comment = it },
                    label = { Text("Comment (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onSave(name, comment) },
                enabled = name.isNotBlank()
            ) {
                Text("Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

/**
 * Generic empty state card component
 */
@Composable
fun EmptyStateCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    description: String,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(32.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    icon,
                    contentDescription = null,
                    modifier = Modifier.size(64.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(16.dp))
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
            }
        }
    }
}

/**
 * Error state card component
 */
@Composable
fun ErrorStateCard(
    message: String,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(32.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    Icons.Default.ErrorOutline,
                    contentDescription = null,
                    modifier = Modifier.size(64.dp),
                    tint = MaterialTheme.colorScheme.error
                )
                Spacer(Modifier.height(16.dp))
                Text(
                    text = "Error",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
                Spacer(Modifier.height(16.dp))
                FilledTonalButton(onClick = onDismiss) {
                    Text("Dismiss")
                }
            }
        }
    }
}
