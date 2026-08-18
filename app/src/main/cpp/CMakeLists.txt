# IDA Pro M - Native Disassembly Engine
# CMake 4.4.2 Configuration
# Supports: ARM, ARM64, x86, x86_64

cmake_minimum_required(VERSION 4.4.2)
project("idapro_native" VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Optimization flags for release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -fvisibility=hidden -fvisibility-inlines-hidden")
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Source files for disassembly engine
file(GLOB_RECURSE DISASM_SOURCES 
    "src/*.cpp"
    "src/*.c"
)

# Main native library
add_library(idapro_engine SHARED
    ${DISASM_SOURCES}
    src/disassembler.cpp
    src/arm_disassembler.cpp
    src/x86_disassembler.cpp
    src/hex_utils.cpp
    src/pattern_scanner.cpp
    src/string_extractor.cpp
    src/xref_analyzer.cpp
    src/function_analyzer.cpp
    src/call_graph_builder.cpp
    src/elf_parser.cpp
    src/pe_parser.cpp
    src/macho_parser.cpp
    src/dex_parser.cpp
    src/binary_loader.cpp
    src/memory_region.cpp
    src/instruction.cpp
    src/operand.cpp
    src/register_info.cpp
    src/architecture.cpp
)

# Link libraries
target_link_libraries(idapro_engine
    android
    log
    z
)

# Compiler-specific options
if(MSVC)
    target_compile_options(idapro_engine PRIVATE /W4 /WX)
else()
    target_compile_options(idapro_engine PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Werror=return-type
        -fPIC
    )
endif()

# Export headers
install(TARGETS idapro_engine
    LIBRARY DESTINATION lib
)

# Install header files
install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)
