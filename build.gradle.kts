// IDA Pro M - Mobile Reverse Engineering & Disassembler
// Root build configuration
// AGP 8.7.3 | Kotlin 2.0.21 | JDK 17 | Compose BOM 2024.12.01

plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("com.android.library") version "8.7.3" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
    id("com.google.devtools.ksp") version "2.0.21-1.0.28" apply false
    id("com.google.dagger.hilt.android") version "2.52" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.0.21" apply false
}

// NOTE: Repositories are now defined in settings.gradle.kts
// Do NOT add them here - it will cause build failure!

tasks.register("clean", Delete::class) {
    delete(rootProject.buildDir)
}

// Extra properties for consistent versioning across modules
extra.apply {
    set("minSdk", 24)
    set("targetSdk", 35)
    set("compileSdk", 35)
    set("versionCode", 300)
    set("versionName", "3.0.0")
    set("agpVersion", "8.7.3")
    set("kotlinVersion", "2.0.21")
    set("composeBomVersion", "2024.12.01")
    set("hiltVersion", "2.52")
    set("roomVersion", "2.6.1")
    set("navigationComposeVersion", "2.8.5")
    set("lifecycleVersion", "2.8.7")
    set("coilVersion", "2.7.0")
}
