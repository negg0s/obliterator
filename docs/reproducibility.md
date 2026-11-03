# Reproducible Builds Guide

This document describes the configuration and verification of deterministic builds in Obliterator.

## 1. Deterministic Build Flags

Obliterator enables reproducible outputs through MSVC compiler and linker settings:

- **Linker `/Brepro` Flag**: Tells the MSVC linker to emit deterministic timestamps and checksums in PE headers instead of current system time.
- **Static Runtime (`/MT`)**: Eliminates dependencies on dynamic C runtime variants and standardizes symbol resolutions.
- **Strict Conformance (`/permissive-`, `/utf-8`)**: Ensures identical character encoding parsing across different locale environments.
- **Control Flow Guard & ASLR (`/guard:cf`, `/DYNAMICBASE`, `/HIGHENTROPYVA`)**: Deterministic code instrumentation for security controls.

## 2. CI Verification

In the continuous integration pipeline (`.github/workflows/ci.yml`), a verification step ensures that consecutive builds of the same commit generate bit-for-bit identical binary hashes:

1. Build `obliterator.exe` in a clean directory (`build1`).
2. Build `obliterator.exe` in a separate clean directory (`build2`).
3. Compute SHA-256 for both outputs and assert that hashes match.

## 3. Toolchain Pinning

To reproduce an identical binary outside of the CI runner:
- Use Visual Studio 2026 (MSVC toolset version 19.51.x or higher).
- Windows SDK version 10.0.26100.0 or higher.
- Standard CMake 3.20 or higher with Ninja or MSBuild generator.

In GitHub Actions, the runner image is pinned to `windows-latest` with explicit developer command prompt initialization via `ilammy/msvc-dev-cmd@v1`.

## 4. Known Limitations

- **Cross-Compiler Variations**: Binaries compiled on different major or minor compiler versions (e.g. MSVC 19.40 vs 19.51) will not have identical checksums due to optimizer improvements and code generation updates.
- **Debug Information (PDB)**: If `/DEBUG` or PDB generation is enabled without `/PDBALTPATH`, absolute PDB file paths may be embedded into the debug directory section of the PE header. Release builds omit external PDB path dependencies.
- **Macro Expansions**: The preprocessor macros `__DATE__` and `__TIME__` are not used in Obliterator source code to prevent non-deterministic variations between compilation passes.
