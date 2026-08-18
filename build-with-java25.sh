#!/bin/bash
# Workaround for Java 25 compatibility with Kotlin 2.0.21+
# This script bridges the version compatibility gap

set -e

# Get the actual Java version
JAVA_VERSION=$(java -version 2>&1 | grep -oP 'version "\K[^"]+' || true)

if [[ $JAVA_VERSION == 25* ]]; then
    echo "Detected Java 25 - applying compatibility workaround..."
    
    # Create a wrapper that patches the version detection
    # Use export to set Java home to a compatible version if available
    
    # Alternative: use preview features and suppress warnings
    export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS} --enable-preview"
fi

# Run gradle with the build command
./gradlew "$@"
