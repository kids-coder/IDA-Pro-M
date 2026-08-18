package com.mobile.idapro.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.view.WindowCompat
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.mobile.idapro.ui.screens.HomeScreen
import com.mobile.idapro.ui.screens.DisassemblyScreen
import com.mobile.idapro.ui.screens.HexEditorScreen
import com.mobile.idapro.ui.screens.StringsScreen
import com.mobile.idapro.ui.screens.GraphScreen
import com.mobile.idapro.ui.screens.SearchScreen
import com.mobile.idapro.ui.screens.SettingsScreen
import com.mobile.idapro.ui.theme.IDAProMTheme
import dagger.hilt.android.AndroidEntryPoint

/**
 * IDA Pro M - Main Activity
 * 
 * Entry point for the application. Sets up:
 * - Edge-to-edge display mode
 * - Jetpack Compose UI
 * - Navigation controller
 * - Theme management
 */
@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Enable edge-to-edge display
        enableEdgeToEdge()
        
        // Set up system bar behavior
        WindowCompat.setDecorFitsSystemWindows(window, false)
        
        setContent {
            IDAProMTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    IdaProNavHost()
                }
            }
        }
    }
}

/**
 * Main navigation host for IDA Pro M.
 * Handles navigation between all major screens.
 */
@Composable
fun IdaProNavHost() {
    val navController = rememberNavController()
    
    NavHost(
        navController = navController,
        startDestination = "home"
    ) {
        // Home screen - file browser and recent files
        composable("home") {
            HomeScreen(
                onNavigateToDisassembly = { fileId ->
                    navController.navigate("disassembly/$fileId")
                },
                onNavigateToHexEditor = { fileId ->
                    navController.navigate("hexeditor/$fileId")
                },
                onNavigateToStrings = { fileId ->
                    navController.navigate("strings/$fileId")
                },
                onNavigateToGraph = { fileId ->
                    navController.navigate("graph/$fileId")
                }
            )
        }
        
        // Disassembly view screen
        composable(
            route = "disassembly/{fileId}",
            arguments = listOf(navArgument("fileId") { type = NavType.LongType })
        ) { backStackEntry ->
            val fileId = backStackEntry.arguments?.getLong("fileId") ?: 0L
            DisassemblyScreen(
                fileId = fileId,
                onBack = { navController.popBackStack() },
                onNavigateToHexEditor = { address ->
                    navController.navigate("hexeditor/$fileId?address=$address")
                },
                onNavigateToStrings = {
                    navController.navigate("strings/$fileId")
                },
                onNavigateToGraph = { functionId ->
                    navController.navigate("graph/$fileId?functionId=$functionId")
                }
            )
        }
        
        // Hex editor screen
        composable(
            route = "hexeditor/{fileId}?address={address}",
            arguments = listOf(
                navArgument("fileId") { type = NavType.LongType },
                navArgument("address") { type = NavType.LongType; defaultValue = 0L }
            )
        ) { backStackEntry ->
            val fileId = backStackEntry.arguments?.getLong("fileId") ?: 0L
            val address = backStackEntry.arguments?.getLong("address") ?: 0L
            HexEditorScreen(
                fileId = fileId,
                initialAddress = address,
                onBack = { navController.popBackStack() },
                onNavigateToDisassembly = { addr ->
                    navController.navigate("disassembly/$fileId?address=$addr")
                }
            )
        }
        
        // Strings view screen
        composable(
            route = "strings/{fileId}",
            arguments = listOf(navArgument("fileId") { type = NavType.LongType })
        ) { backStackEntry ->
            val fileId = backStackEntry.arguments?.getLong("fileId") ?: 0L
            StringsScreen(
                fileId = fileId,
                onBack = { navController.popBackStack() },
                onNavigateToAddress = { address ->
                    navController.navigate("disassembly/$fileId?address=$address")
                }
            )
        }
        
        // Control flow graph screen
        composable(
            route = "graph/{fileId}?functionId={functionId}",
            arguments = listOf(
                navArgument("fileId") { type = NavType.LongType },
                navArgument("functionId") { type = NavType.IntType; defaultValue = -1 }
            )
        ) { backStackEntry ->
            val fileId = backStackEntry.arguments?.getLong("fileId") ?: 0L
            val functionId = backStackEntry.arguments?.getInt("functionId") ?: -1
            GraphScreen(
                fileId = fileId,
                functionId = functionId,
                onBack = { navController.popBackStack() }
            )
        }
        
        // Search screen (can be accessed from anywhere)
        composable(
            route = "search/{fileId}",
            arguments = listOf(navArgument("fileId") { type = NavType.LongType })
        ) { backStackEntry ->
            val fileId = backStackEntry.arguments?.getLong("fileId") ?: 0L
            SearchScreen(
                fileId = fileId,
                onBack = { navController.popBackStack() },
                onNavigateToAddress = { address ->
                    navController.navigate("disassembly/$fileId?address=$address")
                }
            )
        }
        
        // Settings screen
        composable("settings") {
            SettingsScreen(
                onBack = { navController.popBackStack() }
            )
        }
    }
}
