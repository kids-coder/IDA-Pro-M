package com.mobile.idapro

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.*
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.mobile.idapro.ui.components.*
import com.mobile.idapro.ui.theme.IdaProMobileTheme
import com.mobile.idapro.viewmodel.MainViewModel
import com.mobile.idapro.viewmodel.MainViewModelFactory

/**
 * Main Activity for IDA Pro M
 * 
 * Features merged from both KTIMAZ-REV and IDA Pro Mobile:
 * - File management with Room database persistence
 * - ELF/ARM disassembly with native C++23 code
 * - Graph visualization view with zoom/pan
 * - Bookmarks and annotations (persistent)
 * - Symbol table viewer
 * - Hex viewer with ASCII representation
 * - Section-based analysis
 * - Search/filter functionality
 * 
 * Build Configuration:
 * - AGP 9.3, Kotlin 2.4, JDK 26
 * - Compose BOM 2025.09.01
 * - CMake 4.4.2 with C++23
 */
class MainActivity : ComponentActivity() {

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { isGranted: Boolean ->
        if (isGranted) {
            Toast.makeText(this, "Storage permission granted!", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(
                this,
                "Storage permission denied. Some features may be limited.",
                Toast.LENGTH_LONG
            ).show()
            // Open app settings if denied
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
            val uri = Uri.fromParts("package", packageName, null)
            intent.data = uri
            startActivity(intent)
        }
    }
    
    // File picker launcher for binary files
    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let { 
            viewModel?.loadBinaryFile(this@MainActivity, it)
        }
    }

    private var viewModel: MainViewModel? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        
        requestStoragePermission()

        setContent {
            IdaProMobileTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    MainAppScreen(onFilePickerClick = { filePickerLauncher.launch("*/*") })
                }
            }
        }
    }

    private fun requestStoragePermission() {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.R) {
            requestPermissionLauncher.launch(android.Manifest.permission.READ_EXTERNAL_STORAGE)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainAppScreen(onFilePickerClick: () -> Unit) {
    val context = LocalContext.current
    val application = context.applicationContext as IdaProApplication
    
    val viewModel: MainViewModel = viewModel(
        factory = MainViewModelFactory(application.database)
    )

    // Store reference for activity access
    MainAppScreenInternal(viewModel = viewModel, onFilePickerClick = onFilePickerClick)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainAppScreenInternal(
    viewModel: MainViewModel,
    onFilePickerClick: () -> Unit
) {
    val selectedFile by viewModel.selectedBinaryFile.collectAsStateWithLifecycle()
    val isLoading by viewModel.isLoading.collectAsStateWithLifecycle()
    val errorMessage by viewModel.errorMessage.collectAsStateWithLifecycle()
    
    // Merged state from KTIMAZ-REV
    val currentTab by viewModel.currentTab.collectAsStateWithLifecycle()
    val searchQuery by viewModel.searchQuery.collectAsStateWithLifecycle()
    val bookmarks by viewModel.bookmarks.collectAsStateWithLifecycle()

    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { 
                    Text("IDA Pro M") 
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                ),
                actions = {
                    IconButton(onClick = onFilePickerClick) {
                        Icon(Icons.Filled.FileOpen, contentDescription = "Open File")
                    }
                    IconButton(onClick = { /* Settings */ }) {
                        Icon(Icons.Filled.Settings, contentDescription = "Settings")
                    }
                    DropdownMenu(
                        expanded = viewModel.showMenu.collectAsStateWithLifecycle().value,
                        onDismissRequest = { viewModel.toggleMenu(false) }
                    ) {
                        DropdownMenuItem(
                            text = { Text("About IDA Pro M v3.0") },
                            onClick = { 
                                viewModel.toggleMenu(false)
                                scope.launch {
                                    snackbarHostState.showSnackbar("IDA Pro M v3.0 | AGP 9.3 | CMake 4.4.2 | C++23")
                                }
                            },
                            leadingIcon = { Icon(Icons.Filled.Info, contentDescription = null) }
                        )
                        DropdownMenuItem(
                            text = { Text("Export Analysis") },
                            onClick = { 
                                viewModel.toggleMenu(false)
                                scope.launch {
                                    snackbarHostState.showSnackbar("Export feature coming soon")
                                }
                            },
                            leadingIcon = { Icon(Icons.Filled.Share, contentDescription = null) }
                        )
                        DropdownMenuItem(
                            text = { Text("Native Status: ${if (IdaProApplication.isFullFunctionalAvailable()) "Loaded" else "Fallback"}") },
                            onClick = { viewModel.toggleMenu(false) },
                            leadingIcon = { 
                                Icon(
                                    if (IdaProApplication.isFullFunctionalAvailable()) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                                    contentDescription = null
                                )
                            }
                        )
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                AppTab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = currentTab == tab,
                        onClick = { viewModel.selectTab(tab) },
                        icon = {
                            when (tab) {
                                AppTab.Files -> Icon(Icons.Default.FolderOpen, contentDescription = null)
                                AppTab.Disassembly -> Icon(Icons.Default.Code, contentDescription = null)
                                AppTab.HexView -> Icon(Icons.Default.ViewModule, contentDescription = null)
                                AppTab.Functions -> Icon(Icons.Default.Functions, contentDescription = null)
                                AppTab.Symbols -> Icon(Icons.AutoMirrored.Filled.List, contentDescription = null)
                                AppTab.Bookmarks -> Icon(Icons.Default.Bookmark, contentDescription = null)
                                AppTab.GraphView -> Icon(Icons.Default.AccountTree, contentDescription = null)
                            }
                        },
                        label = { Text(tab.title) }
                    )
                }
            },
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
        ) {
            // Error message display
            errorMessage?.let { error ->
                Card(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Filled.Error,
                            contentDescription = "Error",
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = error,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            }

            // Loading indicator
            if (isLoading) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }

            // Main content based on tab selection
            when (currentTab) {
                AppTab.Files -> {
                    FileUploadScreen(
                        viewModel = viewModel,
                        modifier = Modifier.fillMaxSize()
                    )
                }
                AppTab.Disassembly -> {
                    DisassemblyScreen(
                        viewModel = viewModel,
                        searchQuery = searchQuery,
                        onSearchQueryChange = { viewModel.updateSearchQuery(it) },
                        modifier = Modifier.fillMaxSize()
                    )
                }
                AppTab.HexView -> {
                    HexViewScreen(viewModel = viewModel, modifier = Modifier.fillMaxSize())
                }
                AppTab.Functions -> {
                    FunctionListScreen(viewModel = viewModel, modifier = Modifier.fillMaxSize())
                }
                AppTab.Symbols -> {
                    SymbolsScreen(viewModel = viewModel, modifier = Modifier.fillMaxSize())
                }
                AppTab.Bookmarks -> {
                    BookmarksScreen(
                        viewModel = viewModel,
                        bookmarks = bookmarks,
                        modifier = Modifier.fillMaxSize()
                    )
                }
                AppTab.GraphView -> {
                    GraphViewScreen(viewModel = viewModel, modifier = Modifier.fillMaxSize())
                }
            }
        }
    }
}
