# IDA Pro M - Mobile Reverse Engineering Suite

<p align="center">
  <img src="docs/logo.png" alt="IDA Pro M Logo" width="200" />
</p>

## 📱 Overview

**IDA Pro M** is a comprehensive mobile reverse engineering and disassembler application for Android, inspired by the legendary desktop **IDA Pro**. It brings professional-grade binary analysis capabilities to your mobile device.

### ✨ Key Features

- 🔍 **Multi-Architecture Disassembly**
  - ARM 32-bit (ARMv7/ARMv8)
  - ARM 64-bit (AArch64)
  - Thumb/Thumb-2
  - x86 32-bit
  - x86-64 (AMD64)
  - MIPS (partial support)

- 📄 **Binary Format Support**
  - ELF (Linux/Android executables)
  - PE (Windows executables)
  - Mach-O (macOS/iOS)
  - DEX (Android Dalvik)
  - Raw binaries

- 🎨 **Interactive Disassembly View**
  - Syntax-highlighted instructions
  - Address navigation (Go to address)
  - Cross-reference display
  - Function labels and comments

- 🔢 **Hex Editor**
  - Editable hex view with ASCII column
  - Pattern search and replace
  - Selection and modification tracking
  - Multiple encoding support

- 📝 **String Extraction**
  - ASCII strings
  - UTF-8 / UTF-16 (wide) strings
  - Automatic type classification (URLs, paths, GUIDs, etc.)
  - Filterable string list

- 🕸️ **Control Flow Graphs**
  - Visual function CFG rendering
  - Basic block identification
  - Edge classification (true/false/unconditional)
  - Cyclomatic complexity metrics

- 🔗 **Cross-Reference Analysis**
  - Code references (jumps/calls)
  - Data references
  - Import/export resolution
  - String reference tracking

- 🔍 **Pattern & Signature Detection**
  - YARA-like pattern matching
  - Compiler detection signatures
  - Anti-debugging pattern detection
  - Packer/cryptor identification

- ⚙️ **Analysis Options**
  - Auto-analysis on file open
  - Deep scan mode
  - Configurable string extraction
  - Custom signature databases

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│                  Presentation Layer          │
│              (Jetpack Compose)            │
├─────────────────────────────────────────────┤
│                   ViewModel Layer           │
│         (State Management)                │
├─────────────────────────────────────────────┤
│                    Data Layer                 │
│    (Room Database + Repositories)        │
├─────────────────────────────────────────────┤
│                  Native Engine               │
│     (C++ via JNI - NDK/CMake)             │
│   • ARM32/ARM64 Disassembler             │
│   • x86/x86-64 Disassembler             │
│   • Hex Utilities                       │
│   • String Extractor                    │
│   • Pattern Scanner                     │
│   • Xref Analyzer                      │
│   • Function Analyzer                  │
│   • Call Graph Builder                 │
│   • Binary Parser (ELF/PE/Mach-O/DEX)      │
└─────────────────────────────────────────────┘
```

## 🛠️ Technical Specifications

| Component | Version |
|------------|---------|
| Android Gradle Plugin | 9.3.0 |
| Kotlin | 2.4 |
| JDK | 26 |
| Jetpack Compose BOM | 2025.09.01 |
| CMake | 4.4.2 |
| Min SDK | 24 |
| Target SDK | 37 |
| Package Name | `com.mobile.idapro` |
| Architecture | arm64-v8a / armeabi-v7a |

## 📦 Installation

### From Source Code

```bash
# Clone the repository
git clone https://github.com/youruser/IDA-Pro-M.git
cd IDA-Pro-M

# Build debug APK
./gradlew assembleDebug

# Build release APK/AAB
./gradlew assembleRelease
./gradlew bundleRelease

# Run unit tests
./gradlew testDebugUnitTest

# Run instrumented tests (requires emulator)
./gradlew connectedDebugAndroidTest
```

### Requirements

- **Android Studio**: Hedgehog or newer
- **NDK r26+**: For native C++ compilation
- **CMake 4.4.2+**: For build system
- **JDK 26**: Java Development Kit

## 🚀 Quick Start

1. **Open the app** → Grant storage permissions
2. **Import a binary file** → Tap "+" or use file picker
3. **Wait for analysis** → Automatic or manual trigger
4. **Explore results**:
   - **Disassembly tab**: View decoded instructions
   - **Hex Editor tab**: Inspect raw bytes
   - **Strings tab**: Extracted strings
   - **Graph tab**: Control flow visualization
   - **Search tab**: Find patterns/instructions

## 📁 Project Structure

```
IDA-Pro-M/
├── app/
│   ├── src/main/
│   │   ├── java/com/mobile/idapro/
│   │   │   ├── IdaProApplication.kt
│   │   │   ├── ui/
│   │   │   │   ├── MainActivity.kt
│   │   │   │   ├── screens/
│   │   │   │   │   ├── HomeScreen.kt
│   │   │   │   │   ├── DisassemblyScreen.kt
│   │   │   │   │   ├── HexEditorScreen.kt
│   │   │   │   │   ├── StringsScreen.kt
│   │   │   │   │   ├── GraphScreen.kt
│   │   │   │   │   ├── SearchScreen.kt
│   │   │   │   │   └── SettingsScreen.kt
│   │   │   │   ├── theme/
│   │   │   │   └── Theme.kt
│   │   │   ├── data/
│   │   │   │   ├── model/
│   │   │   │   └── Models.kt
│   │   │   ├── local/
│   │   │   │   └── Database.kt
│   │   │   ├── repository/
│   │   │   │   └── Repositories.kt
│   │   │   └── native/
│   │   │       └── DisassemblerNative.kt
│   │   ├── cpp/
│   │   │   ├── include/idapro_engine.h
│   │   │   └── src/
│   │   │       ├── disassembler.cpp
│   │   │       ├── arm_disassembler.cpp
│   │   │       ├── arm64_disassembler.cpp
│   │   │       ├── x86_disassembler.cpp
│   │   │       ├── hex_utils.cpp
│   │   │       ├── pattern_scanner.cpp
│   │   │       ├── string_extractor.cpp
│   │   │       ├── xref_analyzer.cpp
│   │   │       ├── function_analyzer.cpp
│   │   │       ├── call_graph_builder.cpp
│   │   │       ├── binary_parser.cpp
│   │   │       ├── binary_loader.cpp
│   │   │       └── instruction.cpp
│   │   └── res/
│   │       └── values/, drawable/, xml/, etc.
│   └── test/
│       └── java/com/mobile/idapro/
│           └── ModelTests.kt
├── .github/workflows/
│   └── ci-cd.yml
├── docs/
│   └── logo.png
├── gradle.properties
├── build.gradle.kts (root)
├── settings.gradle.kts
└── README.md
```

## 🧪 Supported Instructions

### ARM/ARM64
- Data processing: MOV, MVN, ADD, SUB, MUL, DIV, AND, ORR, EOR, BIC, shifts
- Branch/jump: B, BL, BX, BLX, CBZ, CBNZ, TBZ, TBNZ
- Load/store: LDR, STR, LDM, STM, PUSH, POP, LDRB, STRB, LDRH, STRH
- System: SVC, DMB, DSB, ISB, WFI, WFE
- SIMD/NEON: VADD, VSUB, VMUL, VMOV, VLD, VST

### x86/x86-64
- General purpose: MOV, LEA, XCHG, NOP, INT, RET, CALL, JMP
- Arithmetic: ADD, SUB, MUL, DIV, INC, DEC, NEG
- Logical: AND, OR, XOR, NOT, SHL, SHR, SAR, ROL, ROR
- Stack: PUSH, POP, ENTER, LEAVE
- FPU: FADD, FSUB, FMUL, FDIV, FMOV, FCOM
- SSE/AVX: MOVAPS, MOVUPS, PADDDQ, PXOR

## 📊 Version History

### v3.0.0 (Current)
- Complete rewrite with modern architecture
- Native C++ disassembly engine
- Full Compose UI implementation
- GitHub Actions CI/CD pipeline
- Enhanced analysis capabilities

### Future Roadmap
- [ ] Live patching/editing in hex editor
- [ ] Decompiler integration
- [ ] Scripting/automation API
- [ ] Cloud sync for projects
- [ ] Plugin system for custom analyzers
- [ ] Collaboration features (shared annotations)

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is licensed under the **GPL v3 License** - see [LICENSE](LICENSE) file for details.

## 🙏️ Acknowledgments

- Inspired by **Hex-Rays** and **IDA Pro** by Hex-Rays SA
- Built with **Jetpack Compose**, **Room**, **Hilt**, and **Kotlin Coroutines**
- Native engine architecture influenced by **Capstone** and **Zydis**

---

<div align="center">
  <strong>IDA Pro M</strong> • Mobile Reverse Engineering Suite<br>
  <em>"Bringing professional-grade RE tools to Android"</em>
</div>
