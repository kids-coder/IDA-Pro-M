# Changelog

All notable changes to IDA Pro M will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [3.0.0] - 2025-01-19

### Added
- Complete native C++ disassembly engine with JNI bridge
- ARM32/ARM64 instruction decoder (full ISA coverage)
- x86/x86-64 instruction decoder (variable-length support)
- Thumb/Thumb-2 mode support
- Hex editor with editing capabilities
- String extraction (ASCII, UTF-8, UTF-16)
- Control flow graph visualization with Canvas API
- Cross-reference analysis system
- Pattern/signature detection framework
- Binary parser for ELF, PE, Mach-O, DEX formats
- Function identification and analysis
- Call graph construction
- GitHub Actions CI/CD pipeline
- Comprehensive unit test suite
- Jetpack Compose UI implementation
- Hilt dependency injection
- Room database for local storage
- DataStore preferences
- Material You 3 theming (Light/Dark/AMOLED)
- Edge-to-edge display support

### Changed
- Complete rewrite from previous version
- Modernized architecture with clean separation of concerns
- Improved performance with native code execution
- Enhanced UI with modern Material Design 3

### Fixed
- Memory management issues in native engine
- Thread safety improvements
- Screen rotation handling
- Large file handling optimizations

---

## [2.0.0] - 2024-12-01

### Added
- Initial basic disassembly functionality
- Simple hex viewer
- Basic string extraction
- File import/export features

### Known Issues
- Limited architecture support
- No native engine (pure Kotlin)
- Performance issues with large files
