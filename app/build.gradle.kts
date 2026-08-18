plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
    id("com.google.dagger.hilt.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "com.mobile.idapro"
    compileSdk = project.extra["compileSdk"] as Int

    defaultConfig {
        applicationId = "com.mobile.idapro"
        minSdk = project.extra["minSdk"] as Int
        targetSdk = project.extra["targetSdk"] as Int
        versionCode = project.extra["versionCode"] as Int
        versionName = project.extra["versionName"] as String

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        
        vectorDrawables {
            useSupportLibrary = true
        }

        // CMake configuration for native disassembly engine
        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++20"
                cppFlags += "-fexceptions"
                cppFlags += "-frtti"
                cppFlags += "-O2"
                cppFlags += "-Wall"
                cppFlags += "-Wextra"
                arguments += "-DANDROID_STL=c++_shared"
                arguments += "-DCMAKE_BUILD_TYPE=Release"
            }
        }

        ndk {
            abiFilters += "arm64-v8a"
            abiFilters += "armeabi-v7a"
            abiFilters += "x86"
            abiFilters += "x86_64"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            
            // Signing config for release builds
            signingConfig = signingConfigs.getByName("debug")
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-DEBUG"
            isDebuggable = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf(
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
            "-opt-in=kotlinx.coroutines.ExperimentalCoroutinesApi",
            "-opt-in=kotlinx.serialization.ExperimentalSerializationApi",
            "-Xjsr305=strict"
        )
    }

    buildFeatures {
        compose = true
        buildConfig = true
        viewBinding = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "/META-INF/*.kotlin_module"
            pickFirsts += "**/lib*.so"
        }
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    lint {
        abortOnError = false
        warningsAsErrors = false
        disable += "MissingTranslation"
        disable += "ExtraTranslation"
    }
}

dependencies {
    // Jetpack Compose BOM 2024.12.01
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    
    // Compose UI Libraries
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.animation:animation")
    implementation("androidx.compose.foundation:foundation")
    
    // Navigation Compose
    implementation("androidx.navigation:navigation-compose:${project.extra["navigationComposeVersion"]}")
    
    // Lifecycle & ViewModel
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:${project.extra["lifecycleVersion"]}")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:${project.extra["lifecycleVersion"]}")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:${project.extra["lifecycleVersion"]}")
    
    // Hilt Dependency Injection
    implementation("com.google.dagger:hilt-android:${project.extra["hiltVersion"]}")
    ksp("com.google.dagger:hilt-compiler:${project.extra["hiltVersion"]}")
    implementation("androidx.hilt:hilt-navigation-compose:1.2.0")
    
    // Room Database
    val roomVersion = project.extra["roomVersion"] as String
    implementation("androidx.room:room-ktx:$roomVersion")
    implementation("androidx.room:room-runtime:$roomVersion")
    ksp("androidx.room:room-compiler:$roomVersion")
    
    // DataStore Preferences
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    
    // Serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    
    // Image Loading (Coil for Compose)
    implementation("io.coil-kt:coil-compose:${project.extra["coilVersion"]}")
    
    // Material Design Extended
    implementation("androidx.compose.material:material:1.7.5")
    
    // Window Manager (for foldables/tablets)
    implementation("androidx.window:window:1.3.0")
    
    // Accompanist System UI Controller
    implementation("com.google.accompanist:accompanist-systemuicontroller:0.36.0")
    
    // File handling utilities
    implementation("commons-io:commons-io:2.17.0")
    
    // Apache Commons Codec (for hex encoding/decoding)
    implementation("commons-codec:commons-codec:1.17.1")
    
    // Kotlin Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    
    // Logging
    implementation("com.jakewharton.timber:timber:5.0.1")
    
    // Security (encrypted preferences)
    implementation("androidx.security:security-crypto:1.0.0")
    
    // Testing Dependencies
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
    testImplementation("org.robolectric:robolectric:4.13")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    testImplementation("app.cash.turbine:turbine:1.1.0")
    
    // Android Instrumentation Tests
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.12.01"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("com.google.dagger:hilt-android-testing:${project.extra["hiltVersion"]}")
    kspAndroidTest("com.google.dagger:hilt-compiler:${project.extra["hiltVersion"]}")
    
    // Debug implementations
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
