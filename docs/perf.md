# Performance Benchmark Report

## Test Environment

- CPU: Intel(R) Core(TM) i5-10400F @ 2.90GHz (6 physical cores, 12 logical threads)
- RAM: 16 GB DDR4
- OS: Windows 10/11 x64
- Storage: MC512 SSD (System C:), NTFS Fixed Volume (D:)
- Test Dataset: 5,000 files across ~200 directories (depth 8), 600 MB total (4,994 small files, 6 large 90+ MB files)
- Measurement method: QueryPerformanceCounter high-resolution timer, median of 10 runs

## Results Summary: Before vs After

### 1. Obliteration by Stages (5,000 files, 600 MB)

| Stage | Baseline (Before) | Optimized (After) | Speedup | Target Goal | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Process Search | 1574.23 ms | 42.31 ms | 37.2x | < 100.00 ms | PASS |
| File Enumeration | 16.63 ms | 16.95 ms | 1.0x | < 50.00 ms | PASS |
| File Deletion | 177.71 ms | 132.63 ms | 1.34x | < 500.00 ms | PASS |
| Registry Scan | 16.39 ms | 16.90 ms | 1.0x | < 50.00 ms | PASS |
| **Total Duration** | **1792.86 ms** | **213.08 ms** | **8.41x** | **< 1000.00 ms** | **PASS** |

### 2. Installed Applications Scan (Warm Cache)

| Operation | Baseline (Before) | Optimized (After) | Target Goal | Status |
| :--- | :--- | :--- | :--- | :--- |
| Enumerate Installed Apps | 23.48 ms | 23.14 ms | < 300.00 ms | PASS |

Runs: 23.27, 23.14, 23.31, 23.47, 23.49, 24.03, 23.99, 24.25, 23.84, 23.41 ms.

## Thread Scaling Analysis

Work distribution was refactored from per-file dispatch to per-folder batches. Distributing whole folders eliminates lock contention on the NTFS directory index B-tree.

Measurements on 5,000 files across 200 directories:

| Worker Threads | Median Deletion Time | Relative Throughput |
| :--- | :--- | :--- |
| 1 thread | 536.34 ms | 1.00x (baseline) |
| 2 threads | 307.97 ms | 1.74x |
| 4 threads | 169.73 ms | 3.16x |
| 6 threads | 161.86 ms | 3.31x |
| 8 threads | 132.85 ms | 4.04x (optimal) |
| 12 threads | 146.57 ms | 3.66x |
| 16 threads | 136.42 ms | 3.93x |

8 worker threads delivered the lowest latency (132.85 ms). Higher thread counts (12 and 16) incurred slight overhead from context switching and scheduling.

## Top 3 Bottlenecks Identified and Resolved

1. **Process Module Snapshot Loop (1574 ms -> 42 ms)**:
   - Root cause: Process search was taking Toolhelp module snapshots (TH32CS_SNAPMODULE) for hundreds of active system and user processes sequentially, calling path normalization on every loaded module.
   - Fix:
     - Statically cached normalized Windows and System32 directory paths, eliminating repeated API and normalization queries per process.
     - Added quick directory check for binary modules (.dll, .exe) in the target root. When a target contains no binaries, module snapshot enumeration across external processes is bypassed completely.
     - Removed redundant std::filesystem path canonicalization inside module comparison loops.

2. **File Deletion and Metadata Contention (178 ms -> 133 ms)**:
   - Root cause: Deletion previously operated on individual files concurrently within the same directories, causing directory metadata serialization in NTFS. Each file also incurred explicit attribute queries and modifications before calling DeleteFileW.
   - Fix:
     - Implemented fast POSIX unlink semantics via SetFileInformationByHandle(FileDispositionInfoEx) with FILE_DISPOSITION_FLAG_POSIX_SEMANTICS and FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE. The filename is unbound immediately from the namespace without a separate attribute clearing pass.
     - Work was grouped into folder batches so distinct threads operate on separate directories.
     - Fallback paths (FileDispositionInfo, FILE_FLAG_DELETE_ON_CLOSE, and lazy ACL reset) ensure compatibility.

3. **Directory Traversal Buffer and Size Computation in Silent Mode**:
   - Root cause: Traverse used FindFirstFileExW with single-item fetches and separated size collection.
   - Fix:
     - Switched enumeration to GetFileInformationByHandleEx(FileIdBothDirectoryInfo) with a 64 KB buffer, batching multiple directory entries per syscall and reading sizes directly from EndOfFile.
     - In --yes mode without --json, unnecessary size calculations are bypassed to avoid superfluous accumulation and allocation.
