package com.mobile.idapro.ui.screens

import androidx.compose.foundation.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.mobile.idapro.data.model.Instruction
import com.mobile.idapro.ui.theme.*

/**
 * IDA Pro M - Disassembly Screen
 * 
 * Displays disassembled instructions with syntax highlighting,
 * function list, navigation controls, and cross-reference information.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DisassemblyScreen(
    fileId: Long,
    onBack: () -> Unit,
    onNavigateToHexEditor: (Long) -> Unit = {},
    onNavigateToStrings: () -> Unit = {},
    onNavigateToGraph: (Int) -> Unit = {}
) {
    val viewModel: DisassemblyViewModel = hiltViewModel()
    
    // Collect state
    val fileInfo by viewModel.fileInfo.collectAsState()
    val instructions by viewModel.instructions.collectAsState()
    val functions by viewModel.functions.collectAsState()
    val analysisStatus by viewModel.analysisStatus.collectAsState()
    val progress by viewModel.progress.collectAsState()
    val statistics by viewModel.statistics.collectAsState()
    val error by viewModel.error.collectAsState()
    val currentAddress by viewModel.currentAddress.collectAsState()
    
    // UI state
    var showFunctionList by remember { mutableStateOf(false) }
    var showGotoDialog by remember { mutableStateOf(false) }
    var selectedInstruction by remember { mutableStateOf<Instruction?>(null) }
    
    LaunchedEffect(fileId) {
        viewModel.loadFile(fileId)
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { 
                    Text(
                        text = fileInfo?.fileName ?: "Disassembler",
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    ) 
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { showFunctionList = true }) {
                        Icon(Icons.Default.List, contentDescription = "Functions")
                    }
                    IconButton(onClick = { showGotoDialog = true }) {
                        Icon(Icons.Default.GpsFixed, contentDescription = "Go to address")
                    }
                    IconButton(onClick = onNavigateToStrings) {
                        Icon(Icons.Default.TextFields, contentDescription = "Strings")
                    }
                    DropdownMenu(
                        expanded = false,
                        onDismissRequest = {}
                    ) {
                        // Additional options menu
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            if (analysisStatus == com.mobile.idapro.data.model.AnalysisStatus.IN_PROGRESS) {
                AnalysisProgressBar(progress = progress)
            } else if (analysisStatus == com.mobile.idapro.data.model.AnalysisStatus.COMPLETED) {
                StatisticsBar(statistics = statistics)
            }
        },
        floatingActionButton = {
            if (analysisStatus != com.mobile.idapro.data.model.AnalysisStatus.IN_PROGRESS &&
                analysisStatus != com.mobile.idapro.data.model.AnalysisStatus.COMPLETED) {
                ExtendedFloatingActionButton(
                    onClick = { viewModel.startAnalysis() },
                    icon = { Icon(Icons.Default.PlayArrow, contentDescription = null) },
                    text = { Text("Analyze") }
                )
            }
        }
    ) { paddingValues ->
        Row(modifier = Modifier.padding(paddingValues)) {
            // Main disassembly view
            Box(modifier = Modifier.weight(1f)) {
                when (analysisStatus) {
                    com.mobile.idapro.data.model.AnalysisStatus.NOT_STARTED -> {
                        AnalysisPrompt(onStartAnalysis = { viewModel.startAnalysis() })
                    }
                    com.mobile.idapro.data.model.AnalysisStatus.IN_PROGRESS -> {
                        Box(
                            modifier = Modifier.fillMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                CircularProgressIndicator()
                                Spacer(modifier = Modifier.height(16.dp))
                                Text(text = progress.currentPhase)
                                LinearProgressIndicator(
                                    progress = { progress.progressPercent / 100f },
                                    modifier = Modifier.width(200.dp)
                                )
                            }
                        }
                    }
                    com.mobile.idapro.data.model.AnalysisStatus.COMPLETED -> {
                        if (instructions.isEmpty()) {
                            EmptyInstructionsView(onNavigate = { 
                                viewModel.navigateToAddress(currentAddress) 
                            })
                        } else {
                            SelectionContainer {
                                DisassemblyListView(
                                    instructions = instructions,
                                    currentAddress = currentAddress,
                                    onInstructionClick = { instruction ->
                                        selectedInstruction = instruction
                                        viewModel.currentAddress.value = instruction.address
                                    },
                                    onInstructionLongClick = { instruction ->
                                        // Show context menu for xrefs, comments, etc.
                                    }
                                )
                            }
                        }
                    }
                    else -> {
                        ErrorView(message = error ?: "Analysis failed")
                    }
                }
                
                // Instruction detail bottom sheet
                selectedInstruction?.let { instruction ->
                    InstructionDetailSheet(
                        instruction = instruction,
                        onDismiss = { selectedInstruction = null },
                        onViewInHex = { onNavigateToHexEditor(instruction.address) },
                        onViewXrefs = { /* Navigate to xrefs */ }
                    )
                }
            }
            
            // Function list side panel (conditional)
            if (showFunctionList && functions.isNotEmpty()) {
                Divider(
                    modifier = Modifier
                        .fillMaxHeight()
                        .width(1.dp),
                    color = MaterialTheme.colorScheme.outline
                )
                
                FunctionListPanel(
                    functions = functions,
                    onSelect = { function ->
                        viewModel.navigateToAddress(function.startAddress)
                        showFunctionList = false
                    },
                    onDismiss = { showFunctionList = false }
                )
            }
        }
        
        // Go to address dialog
        if (showGotoDialog) {
            GotoAddressDialog(
                currentAddress = currentAddress,
                onConfirm = { address ->
                    viewModel.navigateToAddress(address)
                    showGotoDialog = false
                },
                onDismiss = { showGotoDialog = false }
            )
        }
    }
}

@Composable
private fun AnalysisPrompt(onStartAnalysis: () -> Unit) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(32.dp)
        ) {
            Icon(
                Icons.Default.Code,
                contentDescription = null,
                modifier = Modifier.size(80.dp),
                tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)
            )
            Spacer(modifier = Modifier.height(24.dp))
            Text(
                text = "Ready to Analyze",
                style = MaterialTheme.typography.headlineSmall
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Start analysis to view disassembled code, functions, strings, and more.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(24.dp))
            Button(onClick = onStartAnalysis) {
                Text("Start Analysis")
            }
        }
    }
}

@Composable
private fun DisassemblyListView(
    instructions: List<Instruction>,
    currentAddress: Long,
    onInstructionClick: (Instruction) -> Unit,
    onInstructionLongClick: (Instruction) -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(vertical = 4.dp)
    ) {
        items(instructions, key = { it.address }) { instruction ->
            DisassemblyItem(
                instruction = instruction,
                isCurrentAddress = instruction.address == currentAddress,
                onClick = { onInstructionClick(instruction) },
                onLongClick = { onInstructionLongClick(instruction) }
            )
        }
    }
}

@Composable
private fun DisassemblyItem(
    instruction: Instruction,
    isCurrentAddress: Boolean,
    onClick: () -> Unit,
    onLongClick: () -> Unit
) {
    val backgroundColor = if (isCurrentAddress) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        Color.Transparent
    }
    
    Surface(
        onClick = onClick,
        onLongClick = onLongClick,
        color = backgroundColor,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 4.dp),
            verticalAlignment = Alignment.Top
        ) {
            // Address column
            Text(
                text = "0x${instruction.address.toString(16).padStart(16, '0')}",
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = SyntaxAddress,
                modifier = Modifier.width(140.dp),
                maxLines = 1
            )
            
            // Bytes column
            Text(
                text = instruction.rawBytes.joinToString(" ") { "%02X".format(it) }.padEnd(24),
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.outline,
                modifier = Modifier.width(170.dp),
                maxLines = 1
            )
            
            // Mnemonic column
            Text(
                text = instruction.mnemonic.padEnd(8),
                fontFamily = FontFamily.Monospace,
                fontWeight = if (instruction.isCall || instruction.isBranch || instruction.isReturn) 
                    androidx.compose.ui.text.font.Font.Bold else androidx.compose.ui.text.font.Font.Normal,
                color = when {
                    instruction.isCall -> StatusInfo
                    instruction.isBranch -> SyntaxKeyword
                    instruction.isReturn -> StatusWarning
                    else -> SyntaxMnemonic
                },
                modifier = Modifier.width(80.dp)
            )
            
            // Operands column
            Text(
                text = instruction.operands,
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
        }
        
        // Comment line (if present)
        instruction.comment?.let { comment ->
            if (comment.isNotEmpty()) {
                Text(
                    text = "; $comment",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = SyntaxComment,
                    modifier = Modifier
                        .padding(start = 16.dp)
                        .fillMaxWidth(),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun FunctionListPanel(
    functions: List<com.mobile.idapro.data.model.Function>,
    onSelect: (com.mobile.idapro.data.model.Function) -> Unit,
    onDismiss: () -> Unit
) {
    Surface(
        shadowElevation = 8.dp,
        tonalElevation = 4.dp,
        modifier = Modifier
            .fillMaxHeight()
            .width(280.dp)
    ) {
        Column(modifier = Modifier.fillMaxSize()) {
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Functions (${functions.size})",
                    style = MaterialTheme.typography.titleSmall
                )
                IconButton(onClick = onDismiss) {
                    Icon(Icons.Default.Close, contentDescription = "Close")
                }
            }
            
            HorizontalDivider()
            
            // Function search
            OutlinedTextField(
                value = "",
                onValueChange = { /* Filter functions */ },
                placeholder = { Text("Search functions...") },
                leadingIcon = { Icon(Icons.Default.Search, null) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                singleLine = true,
                textStyle = MaterialTheme.typography.bodyMedium
            )
            
            // Function list
            LazyColumn(
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(vertical = 4.dp)
            ) {
                items(functions, key = { it.id }) { function ->
                    FunctionListItem(
                        function = function,
                        onClick = { onSelect(function) }
                    )
                }
            }
        }
    }
}

@Composable
private fun FunctionListItem(
    function: com.mobile.idapro.data.model.Function,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Function icon based on type
            Icon(
                imageVector = when (function.type) {
                    com.mobile.idapro.data.model.FunctionType.IMPORTED -> Icons.Default.Download
                    com.mobile.idapro.data.model.FunctionType.EXPORTED -> Icons.Default.Upload
                    com.mobile.idapro.data.model.FunctionType.THUNK -> Icons.Default.SwapHoriz
                    else -> Icons.Default.Functions
                },
                contentDescription = null,
                modifier = Modifier.size(20.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            
            Spacer(modifier = Modifier.width(8.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = function.getDisplayName(),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "0x${function.startAddress.toString(16)} - ${function.instructionCount} ins",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.outline
                )
            }
            
            // Complexity indicator
            Surface(
                shape = MaterialTheme.shapes.small,
                color = when {
                    function.cyclomaticComplexity > 20 -> MaterialTheme.colorScheme.errorContainer
                    function.cyclomaticComplexity > 10 -> MaterialTheme.colorScheme.warningContainer
                    else -> MaterialTheme.colorScheme.primaryContainer
                }
            ) {
                Text(
                    text = "${function.cyclomaticComplexity}",
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                )
            }
        }
    }
}

@Composable
private fun GotoAddressDialog(
    currentAddress: Long,
    onConfirm: (Long) -> Unit,
    onDismiss: () -> Unit
) {
    var addressText by remember { mutableStateOf(currentAddress.toString(16)) }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Go to Address") },
        text = {
            Column {
                Text("Enter hexadecimal address:")
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = addressText,
                    onValueChange = { addressText = it },
                    label = { Text("Address (hex)") },
                    prefix = { Text("0x", fontFamily = FontFamily.Monospace) },
                    singleLine = true,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.foundation.text.KeyboardType.Ascii
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    try {
                        val address = addressText.toLong(16)
                        onConfirm(address)
                    } catch (e: NumberFormatException) {
                        // Invalid input
                    }
                }
            ) {
                Text("Go")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
private fun InstructionDetailSheet(
    instruction: Instruction,
    onDismiss: () -> Unit,
    onViewInHex: () -> Unit,
    onViewXrefs: () -> Unit
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            // Address header
            Text(
                text = "0x${instruction.address.toString(16).padStart(16, '0')}",
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.titleMedium
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            // Full instruction
            Card {
                SelectionContainer {
                    Text(
                        text = "${instruction.mnemonic} ${instruction.operands}".trimEnd(),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 14.sp,
                        modifier = Modifier.padding(12.dp)
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // Raw bytes
            Text("Raw bytes:", style = MaterialTheme.typography.titleSmall)
            Text(
                text = instruction.rawBytes.joinToString(" ") { "%02X".format(it) },
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.outline
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // Action buttons
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = onViewInHex,
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Default.GridView, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("View in Hex")
                }
                
                OutlinedButton(
                    onClick = onViewXrefs,
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Default.CallMade, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("XRefs")
                }
            }
            
            // Branch target info
            instruction.branchTarget?.let { target ->
                Spacer(modifier = Modifier.height(12.dp))
                Text("Branch target: 0x${target.toString(16)}", fontFamily = FontFamily.Monospace)
            }
        }
    }
}

@Composable
private fun AnalysisProgressBar(progress: AnalysisProgress) {
    Surface(
        shadowElevation = 8.dp,
        tonalElevation = 4.dp,
        color = MaterialTheme.colorScheme.surface
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(progress.currentPhase, style = MaterialTheme.typography.labelMedium)
                Text("${progress.progressPercent}%", style = MaterialTheme.typography.labelMedium)
            }
            Spacer(modifier = Modifier.height(4.dp))
            LinearProgressIndicator(
                progress = { progress.progressPercent / 100f },
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

@Composable
private fun StatisticsBar(statistics: AnalysisStatistics) {
    Surface(
        shadowElevation = 8.dp,
        tonalElevation = 4.dp,
        color = MaterialTheme.colorScheme.surface
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            StatItem(value = "${statistics.totalInstructions}", label = "Instructions")
            StatItem(value = "${statistics.totalFunctions}", label = "Functions")
            StatItem(value = "${statistics.totalStrings}", label = "Strings")
            StatItem(value = "${statistics.analysisTimeMs}ms", label = "Time")
        }
    }
}

@Composable
private fun StatItem(value: String, label: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun EmptyInstructionsView(onNavigate: () -> Unit) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text("No instructions loaded", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            TextButton(onClick = onNavigate) {
                Text("Load instructions at current address")
            }
        }
    }
}

@Composable
private fun ErrorView(message: String) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Default.ErrorOutline, null, modifier = Modifier.size(48.dp), tint = MaterialTheme.colorScheme.error)
            Spacer(modifier = Modifier.height(16.dp))
            Text(message, color = MaterialTheme.colorScheme.error)
        }
    }
}
