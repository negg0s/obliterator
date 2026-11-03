# Contributing to Obliterator

Thank you for your interest in improving Obliterator.

## 1. Environment Requirements

- Windows 10 or Windows 11 (x64 or ARM64).
- Visual Studio 2022 or 2026 with C++20 support (MSVC toolset).
- CMake 3.20 or newer.

## 2. Building and Testing

### Build Commands

From an elevated Developer Command Prompt or PowerShell:

```cmd
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Or using CMake Presets:

```cmd
cmake --preset release
cmake --build --preset release
```

### Running Test Suite

```cmd
ctest --test-dir build -C Release --output-on-failure
```

Or run the test binary directly:

```cmd
build\Release\obliterator_tests.exe
```

## 3. Code Style and Architecture Rules

- **Zero External Dependencies**: Use native Win32 APIs and static standard C++20 library only. Do not add external third-party libraries.
- **Resource Management**: Wrap Windows handles in RAII types (`UniqueHandle`, `UniqueHKey`, `UniqueScHandle`).
- **Error Handling**: Use `Result<T>` and `Win32Error` instead of raw unhandled error codes or unhandled exceptions across module boundaries.
- **Path Handling**: Always preserve extended path support (`\\?\` prefix) and handle non-ASCII / Unicode paths without data loss.
- **Safety Checks**: Every disk modification must pass safety checks in `SafetyValidator`. Do not bypass protection checks for root drives or Windows system directories.
- **Formatting**: Adhere to the root `.clang-format` rules.

## 4. Commits and Pull Requests

- Keep commit messages in imperative English (e.g., `Add feature X`, `Fix handle leak in Y`).
- Ensure all tests pass with zero warnings under `/W4 /WX`.
- Pull Requests should describe the motivation, the implementation details, and verification steps.
