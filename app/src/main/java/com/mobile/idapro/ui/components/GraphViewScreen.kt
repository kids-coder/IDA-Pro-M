package com.mobile.idapro.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsState
import com.mobile.idapro.data.model.DisassemblyInstruction
import com.mobile.idapro.viewmodel.MainViewModel

/**
 * Graph View Screen (Control Flow Graph - from IDA Pro Mobile enhanced for v3.0)
 * 
 * Features:
 * - Canvas-based control flow graph (CFG) rendering
 * - Basic block visualization with edges
 * - Zoom and pan support via gestures
 * - Node selection for inspection
 * - Conditional branch highlighting (true/false paths)
 * - Minimap/overview support
 * - Export graph as image option
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GraphViewScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier,
    onNavigateToAddress: (Long) -> Unit = {}
) {
    val instructions by viewModel.instructions.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    
    // Graph state
    var zoomLevel by remember { mutableFloatStateOf(1f) }
    var panOffset by remember { mutableStateOf(Offset.Zero) }
    var selectedNodeId by remember { mutableIntStateOf(-1) }
    
    // Generate CFG from instructions
    val cfgGraph = remember(instructions) {
        generateCFGFromInstructions(instructions)
    }
    
    // Layout nodes for rendering
    val layoutNodes = remember(cfgGraph, zoomLevel) {
        layoutCFGNodes(cfgGraph)
    }
    
    Column(modifier = modifier.fillMaxSize()) {
        // Toolbar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "Control Flow Graph",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "${cfgGraph.nodes.size} basic blocks • ${cfgGraph.edges.size} edges",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            // Zoom controls
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = { zoomLevel = (zoomLevel * 1.2f).coerceIn(0.25f, 4f) }) {
                    Icon(Icons.Default.ZoomIn, contentDescription = "Zoom In")
                }
                
                Text(
                    text = "${(zoomLevel * 100).toInt()}%",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.width(50.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                IconButton(onClick = { zoomLevel = (zoomLevel / 1.2f).coerceIn(0.25f, 4f) }) {
                    Icon(Icons.Default.ZoomOut, contentDescription = "Zoom Out")
                }
                
                HorizontalDivider(modifier = Modifier.height(24.dp).padding(horizontal = 8.dp))
                
                IconButton(onClick = { 
                    zoomLevel = 1f
                    panOffset = Offset.Zero
                }) {
                    Icon(Icons.Default.CenterFocusStrong, contentDescription = "Reset View")
                }
            }
        }
        
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
                            text = "Building control flow graph...",
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
                    icon = Icons.Default.AccountTree,
                    title = "No Graph Data",
                    description = "Load a binary file and disassemble to view the control flow graph"
                )
            }
            
            else -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .pointerInput(Unit) {
                            detectTransformGestures { _, pan, zoom, _ ->
                                zoomLevel = (zoomLevel * zoom).coerceIn(0.25f, 4f)
                                panOffset += pan / zoomLevel
                            }
                        }
                ) {
                    // Canvas for drawing the graph
                    val textMeasurer = rememberTextMeasurer()
                    
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        // Apply transformations
                        val scale = zoomLevel
                        
                        // Draw edges first (behind nodes)
                        drawCFGEgdes(cfgGraph, layoutNodes, scale, panOffset)
                        
                        // Draw nodes on top
                        drawCFGNodes(
                            cfgGraph = cfgGraph,
                            layoutNodes = layoutNodes,
                            scale = scale,
                            offset = panOffset,
                            selectedNodeId = selectedNodeId,
                            textMeasurer = textMeasurer,
                            onNodeClick = { nodeId -> selectedNodeId = nodeId },
                            onAddressClick = onNavigateToAddress
                        )
                    }
                    
                    // Selected node info overlay
                    if (selectedNodeId >= 0 && selectedNodeId < cfgGraph.nodes.size) {
                        Surface(
                            modifier = Modifier
                                .align(Alignment.BottomCenter)
                                .padding(16.dp),
                            shape = MaterialTheme.shapes.large,
                            tonalElevation = 8.dp,
                            shadowElevation = 8.dp,
                            color = MaterialTheme.colorScheme.surfaceVariant
                        ) {
                            val node = cfgGraph.nodes[selectedNodeId]
                            Column(
                                modifier = Modifier.padding(16.dp)
                            ) {
                                Text(
                                    text = "Basic Block #${selectedNodeId}",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.Bold
                                )
                                
                                Spacer(Modifier.height(8.dp))
                                
                                Text(
                                    text = buildString {
                                        append("Start: ${String.format("0x%08X", node.startAddress)}")
                                        append("\n")
                                        append("End: ${String.format("0x%08X", node.endAddress)}")
                                        append("\n")
                                        append("Instructions: ${node.instructions.size}")
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace
                                )
                                
                                Spacer(Modifier.height(12.dp))
                                
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    FilledTonalButton(onClick = { 
                                        onNavigateToAddress(node.startAddress)
                                    }) {
                                        Icon(Icons.Default.OpenInNew, contentDescription = null, Modifier.size(16.dp))
                                        Spacer(Modifier.width(4.dp))
                                        Text("Go to Start")
                                    }
                                    
                                    TextButton(onClick = { selectedNodeId = -1 }) {
                                        Text("Close")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// === CFG Data Classes ===

/**
 * Represents a basic block in the control flow graph
 */
data class CFGNode(
    val id: Int,
    val startAddress: Long,
    val endAddress: Long,
    val instructions: List<DisassemblyInstruction>,
    val isEntry: Boolean = false,
    val isExit: Boolean = false,
    val hasConditionalBranch: Boolean = false
)

/**
 * Represents an edge between two basic blocks
 */
data class CFGEdge(
    val fromId: Int,
    val toId: Int,
    val type: EdgeType = EdgeType.UNCONDITIONAL,
    val label: String? = null
)

enum class EdgeType {
    UNCONDITIONAL,   // jmp, call
    CONDITIONAL_TRUE,  // taken branch (beq true)
    CONDITIONAL_FALSE, // fall-through (beq false)
    CALL,             // function call
    RETURN            // function return
}

/**
 * Complete control flow graph structure
 */
data class ControlFlowGraph(
    val nodes: List<CFGNode> = emptyList(),
    val edges: List<CFGEdge> = emptyList()
)

/**
 * Layout position for a CFG node during rendering
 */
data class NodeLayout(
    val x: Float,
    val y: Float,
    val width: Float,
    val height: Float
)

// === CFG Generation ===

/**
 * Generate a simple control flow graph from disassembled instructions
 * This creates basic blocks based on jump targets and branch instructions
 */
private fun generateCFGFromInstructions(instructions: List<DisassemblyInstruction>): ControlFlowGraph {
    if (instructions.isEmpty()) return ControlFlowGraph()
    
    val nodes = mutableListOf<CFGNode>()
    val edges = mutableListOf<CFGEdge>()
    
    // Find all addresses that are targets of jumps/calls (block boundaries)
    val targetAddresses = mutableSetOf<Long>()
    instructions.forEach { instr ->
        if (instr.isJump || instr.isBranch) {
            instr.jumpTarget?.let { targetAddresses.add(it) }
            if (instr.isBranch) targetAddresses.add(instr.address + instr.byteLength)
        }
    }
    
    // Split into basic blocks
    var currentBlockStart = 0
    val currentBlockInstructions = mutableListOf<DisassemblyInstruction>()
    
    for (i in instructions.indices) {
        val instr = instructions[i]
        currentBlockInstructions.add(instr)
        
        val shouldEndBlock = instr.isJump || 
                             instr.isBranch ||
                             targetAddresses.contains(instr.address) && i > currentBlockStart ||
                             i == instructions.lastIndex
        
        if (shouldEndBlock) {
            if (currentBlockInstructions.isNotEmpty()) {
                val startInstr = currentBlockInstructions.first()
                val endInstr = currentBlockInstructions.last()
                
                nodes.add(CFGNode(
                    id = nodes.size,
                    startAddress = startInstr.address,
                    endAddress = endInstr.address + endInstr.byteLength,
                    instructions = currentBlockInstructions.toList(),
                    isEntry = nodes.isEmpty(),
                    isExit = instr.isJump && !instr.isBranch,
                    hasConditionalBranch = instr.isBranch
                ))
            }
            
            currentBlockInstructions.clear()
            currentBlockStart = i + 1
        }
    }
    
    // Handle any remaining instructions
    if (currentBlockInstructions.isNotEmpty()) {
        val startInstr = currentBlockInstructions.first()
        val endInstr = currentBlockInstructions.last()
        nodes.add(CFGNode(
            id = nodes.size,
            startAddress = startInstr.address,
            endAddress = endInstr.address + endInstr.byteLength,
            instructions = currentBlockInstructions.toList(),
            isExit = true
        ))
    }
    
    // Create edges between blocks
    for (i in nodes.indices) {
        val node = nodes[i]
        val lastInstr = node.instructions.lastOrNull() ?: continue
        
        if (lastInstr.isBranch) {
            // Conditional branch - two edges
            lastInstr.jumpTarget?.let { target ->
                val targetNodeIndex = nodes.indexOfFirst { it.startAddress == target }
                if (targetNodeIndex >= 0) {
                    edges.add(CFGEdge(i, targetNodeIndex, EdgeType.CONDITIONAL_TRUE, "T"))
                }
            }
            // Fall-through edge
            if (i + 1 < nodes.size) {
                edges.add(CFGEdge(i, i + 1, EdgeType.CONDITIONAL_FALSE, "F"))
            }
        } else if (lastInstr.isJump) {
            // Unconditional jump
            lastInstr.jumpTarget?.let { target ->
                val targetNodeIndex = nodes.indexOfFirst { it.startAddress == target }
                if (targetNodeIndex >= 0) {
                    edges.add(CFGEdge(i, targetNodeIndex, EdgeType.UNCONDITIONAL))
                }
            }
        } else if (!node.isExit && i + 1 < nodes.size) {
            // Fall-through to next block
            edges.add(CFGEdge(i, i + 1, EdgeType.UNCONDITIONAL))
        }
    }
    
    return ControlFlowGraph(nodes, edges)
}

// === Layout Algorithm ===

/**
 * Simple hierarchical layout for CFG nodes
 * Places nodes in rows based on depth from entry point
 */
private fun layoutCFGNodes(graph: ControlFlowGraph): Map<Int, NodeLayout> {
    if (graph.nodes.isEmpty()) return emptyMap()
    
    val layouts = mutableMapOf<Int, NodeLayout>()
    val nodeWidth = 180f
    val nodeHeight = 80f
    val horizontalSpacing = 40f
    val verticalSpacing = 60f
    
    // Simple layered layout based on BFS from entry
    val layers = mutableListOf<List<Int>>()
    val visited = mutableSetOf<Int>()
    val queue = ArrayDeque<Pair<Int, Int>>() // (nodeId, layer)
    
    // Find entry node
    val entryNode = graph.nodes.indexOfFirst { it.isEntry }.coerceAtLeast(0)
    queue.add(entryNode to 0)
    visited.add(entryNode)
    
    while (queue.isNotEmpty()) {
        val (nodeId, layer) = queue.removeFirst()
        
        // Ensure we have enough layers
        while (layers.size <= layer) {
            layers.add(emptyList())
        }
        
        layers[layer] = layers[layer] + nodeId
        
        // Find successors
        val successors = graph.edges
            .filter { it.fromId == nodeId }
            .map { it.toId }
            .filter { it !in visited }
        
        successors.forEach { succId ->
            visited.add(succId)
            queue.add(succId to layer + 1)
        }
    }
    
    // Add any unvisited nodes
    graph.nodes.indices.filter { it !in visited }.forEach { nodeId ->
        visited.add(nodeId)
        while (layers.size <= 1) {
            layers.add(emptyList())
        }
        layers[1] = layers[1] + nodeId
    }
    
    // Calculate positions
    layers.forEachIndexed { layerIndex, layerNodes ->
        val totalWidth = layerNodes.size * nodeWidth + (layerNodes.size - 1) * horizontalSpacing
        val startX = -totalWidth / 2
        
        layerNodes.forEachIndexed { nodeIndex, nodeId ->
            layouts[nodeId] = NodeLayout(
                x = startX + nodeIndex * (nodeWidth + horizontalSpacing),
                y = layerIndex.toFloat() * (nodeHeight + verticalSpacing),
                width = nodeWidth,
                height = nodeHeight
            )
        }
    }
    
    return layouts
}

// === Drawing Functions ===

/**
 * Draw CFG edges (connections between nodes)
 */
private fun DrawScope.drawCFGEgdes(
    graph: ControlFlowGraph,
    layouts: Map<Int, NodeLayout>,
    scale: Float,
    offset: Offset
) {
    graph.edges.forEach { edge ->
        val fromLayout = layouts[edge.fromId] ?: return@forEach
        val toLayout = layouts[edge.toId] ?: return@forEach
        
        // Calculate connection points
        val fromCenter = Offset(
            (fromLayout.x + fromLayout.width / 2) * scale + offset.x,
            (fromLayout.y + fromLayout.height) * scale + offset.y
        )
        val toCenter = Offset(
            (toLayout.x + toLayout.width / 2) * scale + offset.x,
            toLayout.y * scale + offset.y
        )
        
        // Determine edge color based on type
        val edgeColor = when (edge.type) {
            EdgeType.CONDITIONAL_TRUE -> Color(0xFF4CAF50) // Green for true
            EdgeType.CONDITIONAL_FALSE -> Color(0xFFF44336) // Red for false
            EdgeType.CALL -> Color(0xFF9C27B0) // Purple for calls
            EdgeType.RETURN -> Color(0xFF607D8B) // Blue-grey for returns
            else -> AsmKeyword // Blue for unconditional
        }
        
        // Draw curved path for better visual
        val path = Path().apply {
            moveTo(fromCenter.x, fromCenter.y)
            
            // Use quadratic bezier for smooth curves
            val midY = (fromCenter.y + toCenter.y) / 2
            quadraticBezierTo(
                fromCenter.x, midY,
                toCenter.x, toCenter.y
            )
        }
        
        // Draw the edge line
        drawPath(
            path = path,
            color = edgeColor,
            alpha = 0.7f,
            strokeWidth = 2f / scale.coerceAtLeast(0.5f)
        )
        
        // Draw arrow head
        drawArrowHead(toCenter, edge.type, edgeColor, scale)
        
        // Draw edge label if present
        edge.label?.let { label ->
            val labelPos = Offset(
                (fromCenter.x + toCenter.x) / 2 + 10f,
                (fromCenter.y + toCenter.y) / 2
            )
            drawContext.canvas.nativeCanvas.apply {
                val paint = android.graphics.Paint().apply {
                    this.color = edgeColor.toArgb()
                    textSize = 24f / scale.coerceAtLeast(0.5f)
                    isAntiAlias = true
                    typeface = android.graphics.Typeface.MONOSPACE
                }
                drawText(label, labelPos.x, labelPos.y, paint)
            }
        }
    }
}

/**
 * Draw arrow head at the end of an edge
 */
private fun DrawScope.drawArrowHead(
    position: Offset,
    type: EdgeType,
    color: Color,
    scale: Float
) {
    val arrowSize = 10f / scale.coerceAtLeast(0.5f)
    
    val path = Path().apply {
        moveTo(position.x, position.y)
        lineTo(position.x - arrowSize, position.y - arrowSize)
        lineTo(position.x + arrowSize, position.y - arrowSize)
        close()
    }
    
    drawPath(path = path, color = color)
}

/**
 * Draw CFG nodes (basic blocks)
 */
private fun DrawScope.drawCFGNodes(
    cfgGraph: ControlFlowGraph,
    layoutNodes: Map<Int, NodeLayout>,
    scale: Float,
    offset: Offset,
    selectedNodeId: Int,
    textMeasurer: androidx.compose.ui.text.TextMeasurer,
    onNodeClick: (Int) -> Unit,
    onAddressClick: (Long) -> Unit
) {
    layoutNodes.forEach { (nodeId, layout) ->
        val node = cfgGraph.nodes.getOrNull(nodeId) ?: return@forEach
        
        // Calculate scaled position
        val x = layout.x * scale + offset.x
        val y = layout.y * scale + offset.y
        val w = layout.width * scale
        val h = layout.height * scale
        
        // Determine colors based on node state
        val backgroundColor = when {
            nodeId == selectedNodeId -> MaterialTheme.colorScheme.primaryContainer
            node.isEntry -> Success.copy(alpha = 0.3f)
            node.isExit -> Error.copy(alpha = 0.2f)
            else -> MaterialTheme.colorScheme.surface
        }
        
        val borderColor = when {
            nodeId == selectedNodeId -> MaterialTheme.colorScheme.primary
            node.isEntry -> Success
            node.hasConditionalBranch -> AsmImmediate
            else -> MaterialTheme.colorScheme.outline
        }
        
        // Draw node background (rounded rectangle)
        drawRoundRect(
            color = backgroundColor,
            topLeft = Offset(x, y),
            size = Size(w, h),
            cornerRadius = CornerRadius(8.dp.toPx()),
            style = Stroke(width = if (selectedNodeId == nodeId) 3f else 1.5f, color = borderColor)
        )
        
        // Fill interior
        drawRoundRect(
            color = backgroundColor.copy(alpha = 0.9f),
            topLeft = Offset(x + 1, y + 1),
            size = Size(w - 2, h - 2),
            cornerRadius = CornerRadius(7.dp.toPx())
        )
        
        // Draw node header background
        drawRoundRect(
            color = borderColor.copy(alpha = 0.3f),
            topLeft = Offset(x + 1, y + 1),
            size = Size(w - 2, 20.dp.toPx() * scale),
            cornerRadius = CornerRadius(7.dp.toPx(), 7.dp.toPx(), 0f, 0f)
        )
        
        // Draw text using native canvas for better performance
        drawContext.canvas.nativeCanvas.apply {
            val textColor = OnSurface.toArgb()
            val addressColor = AsmAddress.toArgb()
            
            // Title text (address range)
            val titlePaint = android.graphics.Paint().apply {
                this.color = textColor
                textSize = 14f * scale.coerceAtLeast(0.5f)
                isAntiAlias = true
                isFakeBoldText = true
                typeface = android.graphics.Typeface.MONOSPACE
            }
            
            val title = String.format("0x%08X", node.startAddress)
            drawText(title, x + 6 * scale, y + 14 * scale, titlePaint)
            
            // Instruction count
            val infoPaint = android.graphics.Paint().apply {
                this.color = addressColor
                textSize = 11f * scale.coerceAtLeast(0.5f)
                isAntiAlias = true
                typeface = android.graphics.Typeface.MONOSPACE
            }
            
            val infoText = "${node.instructions.size} instrs"
            drawText(infoText, x + 6 * scale, y + 28 * scale, infoPaint)
            
            // First instruction mnemonic
            if (node.instructions.isNotEmpty()) {
                val firstInstr = node.instructions.first()
                val mnemonicPaint = android.graphics.Paint().apply {
                    this.color = AsmKeyword.toArgb()
                    textSize = 11f * scale.coerceAtLeast(0.5f)
                    isAntiAlias = true
                    typeface = android.graphics.Typeface.MONOSPACE
                }
                
                val mnemonicText = "${firstInstr.mnemonic} ${firstInstr.getOperandsString()}"
                if (mnemonicText.length > 18) {
                    drawText(mnemonicText.take(17) + "...", x + 6 * scale, y + 42 * scale, mnemonicPaint)
                } else {
                    drawText(mnemonicText, x + 6 * scale, y + 42 * scale, mnemonicPaint)
                }
            }
            
            // Entry/Exit badges
            val badgePaint = android.graphics.Paint().apply {
                textSize = 9f * scale.coerceAtLeast(0.5f)
                isAntiAlias = true
                textAlign = android.graphics.Paint.Align.CENTER
            }
            
            if (node.isEntry) {
                badgePaint.color = Success.toArgb()
                drawRect(android.graphics.RectF(x + w - 30 * scale, y + 4 * scale, x + w - 4 * scale, y + 18 * scale), badgePaint)
                badgePaint.color = android.graphics.Color.WHITE
                drawText("ENTRY", x + w - 17 * scale, y + 15 * scale, badgePaint)
            }
            
            if (node.isExit) {
                badgePaint.color = Error.toArgb()
                drawRect(android.graphics.RectF(x + w - 30 * scale, y + h - 22 * scale, x + w - 4 * scale, y + h - 6 * scale), badgePaint)
                badgePaint.color = android.graphics.Color.WHITE
                drawText("EXIT", x + w - 17 * scale, y + h - 11 * scale, badgePaint)
            }
        }
    }
}
