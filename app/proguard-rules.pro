# IDA Pro M - ProGuard Configuration
# Version 3.0.0

# Keep all Compose-related classes
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# Keep Hilt/Dagger classes
-keep class dagger.hilt.** { *; }
-keep class javax.inject.** { *; }
-keep class * extends dagger.hilt.android.internal.managers.ViewComponentManager$FragmentContextWrapper { *; }

# Keep Room entities and DAOs
-keep @androidx.room.Entity class *
-keep class * implements androidx.room.Dao { *; }
-dontwarn androidx.room.paging.**

# Keep Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# Keep serialization
-keepattributes Signature
-keepattributes *Annotation*
-keepclassmembers,allowshrinking,allowobfuscation class * {
    @com.google.gson.annotations.SerializedName <fields>;
}
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

# Keep native method names
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep our application classes
-keep class com.mobile.idapro.** { *; }
-keep class com.mobile.idapro.data.model.** { *; }
-keep class com.mobile.idapro.native.** { *; }

# Disassembly engine classes
-keep class com.mobile.idapro.disassembly.** { *; }
-keep class com.mobile.idapro.engine.** { *; }

# Remove logging in release builds
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}

# Optimization settings
-optimizationpasses 5
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose

# Preverification
-dontpreverify

# Keep source file/line info for crash reports
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

# Keep annotations for reflection
-keepattributes *Annotation*
-keepattributes EnclosingMethod
-keepattributes InnerClasses
-keepattributes Signature

# Keep exceptions for better stack traces
-keepattributes Exceptions

# Obfuscation options
-useuniqueclassmembernames
-adaptclassstrings
-adaptresourcefilecontents **.properties,META-INF/MANIFEST.MF

# Don't warn about missing classes
-dontwarn java.awt.**
-dontwarn javax.swing.**
-dontwarn org.apache.log4j.**
-dontwarn org.slf4j.**

# Keep Google Play Services
-keep class com.google.android.gms.** { *; }
-dontwarn com.google.android.gms.**

# Keep Coil image loading
-keep class coil.** { *; }

# Keep DataStore
-keep class androidx.datastore.** { *; }

# Keep navigation compose
-keep class androidx.navigation.** { *; }
