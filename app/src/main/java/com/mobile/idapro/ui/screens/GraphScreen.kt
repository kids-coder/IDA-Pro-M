package com.mobile.idapro.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel

/**
 * IDA Pro M - Control Flow Graph Screen
 * 
 * Visualizes function control flow graphs with basic blocks,
 * edges (conditional/unconditional), and navigation.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GraphScreen(
    fileId: Long,
    functionId: Int = -1,
    onBack: () -> Unit
) {
    val viewModel: GraphViewModel = hiltViewModel()
    
    // Graph state
    val graphData by viewModel.graphData.collectAsState()
    val selectedNode by viewModel.selectedNode.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    
    LaunchedEffect(fileId, functionId) {
        if (functionId >= 0) {
            viewModel.loadFunctionGraph(fileId, functionId)
        }
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Control Flow Graph") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { /* Zoom in */ }) {
                        Icon(Icons.Default.ZoomIn, contentDescription = "Zoom in")
                    }
                    IconButton(onClick = { /* Zoom out */ }) {
                        Icon(Icons.Default.ZoomOut, contentDescription = "Zoom out")
                    }
                    IconButton(onClick = { /* Fit to screen */ }) {
                        Icon(Icons.Default.CenterFocusStrong, contentDescription = "Fit")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            if (graphData != null) {
                GraphInfoBar(graphData = graphData!!)
            }
        }
    ) { paddingValues ->
        if (isLoading) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator()
                Text("Loading graph...", modifier = Modifier.padding(16.dp))
            }
        } else if (graphData == null) {
            EmptyGraphView(onSelectFunction = { /* Navigate to function selection */ })
        } else {
            CFGCanvas(
                graphData = graphData!!,
                selectedNode = selectedNode,
                onNodeSelected = { node -> viewModel.selectNode(node) },
                modifier = Modifier.padding(paddingValues)
            )
        }
    }
}

@Composable
private fun CFGCanvas(
    graphData: ControlFlowGraphData,
    selectedNode: GraphNode?,
    onNodeSelected: (GraphNode) -> Unit,
    modifier: Modifier = Modifier
) {
    var scale by remember { mutableFloatStateOf(1f) }
    var offset by remember { mutableStateOf(Offset.Zero) }
    
    Canvas(modifier = modifier.fillMaxSize()) {
        val canvasWidth = size.width
        val canvasHeight = size.height
        
        // Calculate layout with padding
        val padding = 40.dp.toPx()
        
        // Draw edges first (so nodes appear on top)
        drawEdges(graphData.edges, graphData.nodes, scale, offset, padding)
        
        // Draw nodes
        drawNodes(graphData.nodes, scale, offset, padding, canvasWidth, selectedNode, onNodeSelected)
    }
}

private fun androidx.compose.ui.graphics.drawscope.DrawScope.drawEdges(
    edges: List<GraphEdge>,
    nodes: List<GraphNode>,
    scale: Float,
    offset: Offset,
    padding: Float
) {
    for (edge in edges) {
        val sourceNode = nodes.find { it.id == edge.sourceNodeId } ?: continue
        val targetNode = nodes.find { it.id == edge.targetNodeId } ?: continue
        
        val startX = padding + (sourceNode.x * scale) + offset.x
        val startY = padding + (sourceNode.y * scale) + offset.y
        val endX = padding + (targetNode.x * scale) + offset.x
        val endY = padding + (targetNode.y * scale) + offset.y
        
        // Choose color based on edge type
        val edgeColor = when (edge.type) {
            EdgeType.TRUE -> GraphEdgeTrue
            EdgeType.FALSE -> GraphEdgeFalse
            EdgeType.UNCONDITIONAL -> GraphEdgeDefault
            EdgeType.LOOP_BACK -> StatusWarning
        }
        
        // Draw arrow line
        drawLine(
            start = Offset(startX, startY),
            end = Offset(endX, endY),
            color = edgeColor,
            strokeWidth = 2.dp.toPx()
        )
        
        // Draw arrowhead (simplified)
        val angle = kotlin.math.atan2((endY - startY).toDouble(), (endX - startX).toDouble())
        val arrowLength = 10.dp.toPx()
        val arrowAngle = 0.5 // radians
        
        val x1 = endX - arrowLength * kotlin.math.cos(angle - arrowAngle).toFloat()
        val y1 = endY - arrowLength * kotlin.math.sin(angle - arrowAngle).toFloat()
        val x2 = endX - arrowLength * kotlin.math.cos(angle + arrowAngle).toFloat()
        val y2 = endY - arrowLength * kotlin.math.sin(angle + arrowAngle).toFloat()
        
        drawPath(
            path = Path().apply {
                moveTo(endX, endY)
                lineTo(x1, y1)
                lineTo(x2, y2)
                close()
            },
            color = edgeColor
        )
    }
}

private fun androidx.compose.ui.graphics.drawscope.DrawScope.drawNodes(
    nodes: List<GraphNode>,
    scale: Float,
    offset: Offset,
    padding: Float,
    canvasWidth: Float,
    selectedNode: GraphNode?,
    onNodeSelected: (GraphNode) -> Unit
) {
    for (node in nodes) {
        val nodeX = padding + (node.x * scale) + offset.x
        val nodeY = padding + (node.y * scale) + offset.y
        val nodeWidth = 120.dp.toPx() * scale.coerceAtLeast(0.5f)
        val nodeHeight = when {
            node.isEntry || node.isExit -> 50.dp.toPx()
            node.isConditional -> 60.dp.toPx()
            else -> 45.dp.toPx()
        } * scale.coerceAtLeast(0.5f)
        
        // Node background color based on type
        val nodeColor = when {
            node.isEntry -> GraphEntryNode
            node.isExit -> GraphExitNode
            node.isConditional -> GraphConditionalNode
            node == selectedNode -> MaterialTheme.colorScheme.primaryContainer
            else -> GraphNodeFill
        }
        
        // Draw rounded rectangle for node
        drawRoundRect(
            topLeft = Offset(nodeX - nodeWidth / 2, nodeY - nodeHeight / 2),
            size = Size(nodeWidth, nodeHeight),
            cornerRadius = CornerRadius(8.dp.toPx()),
            color = nodeColor,
            style = Stroke(width = if (node == selectedNode) 3.dp.toPx() else 1.5.dp.toPx(), 
                       color = if (node == selectedNode) MaterialTheme.colorScheme.primary else GraphNodeStroke)
        )
        
        // Node label text would be drawn here using native canvas
        // For simplicity, we skip actual text rendering in this Canvas example
    }
}

@Composable
private fun GraphInfoBar(graphData: ControlFlowGraphData) {
    Surface(
        shadowElevation = 8.dp,
        tonalElevation = 4.dp,
        color = MaterialTheme.colorScheme.surface
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceEvenly,
            verticalAlignment = Alignment.CenterVertically
        ) {
            InfoItem(value = "${graphData.nodeCount}", label = "Nodes")
            InfoItem(value = "${graphData.edgeCount}", label = "Edges")
            InfoItem(value = "${graphData.cyclomaticComplexity}", label = "Complexity")
            InfoItem(value = graphData.functionName.ifEmpty { "sub_${graphData.entryAddress.toString(16)}" }, label = "Function", maxChars = 12)
        }
    }
}

@Composable
private fun InfoItem(value: String, label: String, maxChars: Int = 6) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            value.take(maxChars),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary
        )
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// ============================================================================
// Data classes for graph visualization
// ============================================================================

data class ControlFlowGraphData(
    val entryAddress: Long = 0L,
    val functionName: String = "",
    val nodes: List<GraphNode> = emptyList(),
    val edges: List<GraphEdge> = emptyList(),
    val nodeCount: Int = 0,
    val edgeCount: Int = 0,
    val cyclomaticComplexity: Int = 0
)

data class GraphNode(
    val id: Int,
    val address: Long,
    val x: Float = 0f,
    val y: Float = 0f,
    val label: String = "",
    val isEntry: Boolean = false,
    val isExit: Boolean = false,
    val isConditional: Boolean = false,
    val instructionCount: Int = 0
)

data class GraphEdge(
    val id: Int,
    val sourceNodeId: Int,
    val targetNodeId: Int,
    val type: EdgeType = EdgeType.UNCONDITIONAL
)

enum class EdgeType {
    UNCONDITIONAL,
    TRUE,
    FALSE,
    LOOP_BACK
}

// ============================================================================
// Graph ViewModel
// ============================================================================

@HiltViewModel
class GraphViewModel @Inject constructor() : ViewModel() {
    
    private val _graphData = MutableStateFlow<ControlFlowGraphData?>(null)
    val graphData: StateFlow<ControlFlowGraphData?> = _graphData.asStateFlow()
    
    private val _selectedNode = MutableStateFlow<GraphNode?>(null)
    val selectedNode: StateFlow<GraphNode?> = _selectedNode.asStateLoop()
    
    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateLoop()
    
    fun loadFunctionGraph(fileId: Long, functionId: Int) {
        // Would load from database or native engine
        // For now, generate sample data
        _isLoading.value = true
        
        val sampleNodes = listOf(
            GraphNode(id = 1, address = 0x1000, x = 200f, y = 100f, label = "entry", isEntry = true),
            GraphNode(id = 2, address = 0x1010, x = 200f, y = 220f, label = "cmp"),
            GraphNode(id = 3, address = 0x1020, x = 100f, y = 340f, label = "true_block", isConditional = true),
            GraphNode(id = 4, address = 0x1030, x = 300f, y = 340f, label = "false_block", isConditional = true),
            GraphNode(id = 5, address = 0x1040, x = 200f, y = 460f, label = "merge", isExit = true)
        )
        
        val sampleEdges = listOf(
            GraphEdge(id = 1, sourceNodeId = 1, targetNodeId = 2),
            GraphEdge(id = 2, sourceNodeId = 2, targetNodeId = 3, type = EdgeType.TRUE),
            GraphEdge(id = 3, sourceNodeId = 2, targetNodeId = 4, type = EdgeType.FALSE),
            GraphEdge(id = 4, sourceNodeId = 3, targetNodeId = 5),
            GraphEdge(id = 5, sourceNodeId = 4, targetNodeId = 5)
        )
        
        _graphData.value = ControlFlowGraphData(
            entryAddress = 0x1000,
            functionName = "main",
            nodes = sampleNodes,
            edges = sampleEdges,
            nodeCount = sampleNodes.size,
            edgeCount = sampleEdges.size,
            cyclomaticComplexity = 3
        )
        
        _isLoading.value = false
    }
    
    fun selectNode(node: GraphNode?) {
        _selectedNode.value = node
    }
}

@Composable
private fun EmptyGraphView(onSelectFunction: () -> Unit) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Default.AccountTree, null, modifier = Modifier.size(64.dp), tint = MaterialTheme.colorScheme.outline)
            Spacer(modifier = Modifier.height(16.dp))
            Text("No graph to display", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            Button(onClick = onSelectFunction) {
                Text("Select Function")
            }
        }
    }
}
