# Performance Benchmark Report

## Test Environment

- CPU: Intel(R) Core(TM) i5-10400F @ 2.90GHz (6 physical cores, 12 logical processors)
- RAM: 16 GB DDR4
- OS: Windows 10/11 x64
- Storage: MC512 SSD (System C:), SATA Fixed Drive (D:)
- Test Dataset: 5,000 files across ~200 directories (depth 8), 600 MB total (4,994 small files, 6 large 90+ MB files)
- Measurement method: QueryPerformanceCounter high-resolution timer, median of 10 runs

## Baseline Measurements (Before Optimization)

### 1. Installed Applications Scan (Warm Cache)

| Operation | Target Goal | Baseline (Median, 10 runs) | Status |
| :--- | :--- | :--- | :--- |
| Enumerate Installed Apps | < 300.00 ms | 23.48 ms | PASS |

Individual runs: 23.27, 23.14, 23.31, 23.47, 23.49, 24.03, 23.99, 24.25, 23.84, 23.41 ms.

### 2. Obliteration by Stages (5,000 files, 600 MB)

| Stage | Baseline Duration (Median, 10 runs) | Notes |
| :--- | :--- | :--- |
| Process Search | 1574.23 ms | Scans all processes and loaded modules |
| File Enumeration | 16.63 ms | FindFirstFileExW traversal with WIN32_FIND_DATAW |
| File Deletion | 177.71 ms | 8 worker threads, DeleteFileW with lazy ACL fallback |
| Registry Scan | 16.39 ms | Autorun, shell extensions, product keys |
| **Total Duration** | **1792.86 ms** | Goal is < 1000.00 ms (< 1 s) |

Individual total run times: 1789.4, 1782.9, 1796.3, 1804.9, 1988.4, 1772.2, 1796.6, 1817.6, 1783.3, 1783.9 ms.

## Planned Optimizations

1. File enumeration: Switch from FindFirstFileExW to GetFileInformationByHandleEx(FileIdBothDirectoryInfo) with a 64 KB buffer, reading sizes directly from directory records.
2. File deletion: POSIX delete semantics via SetFileInformationByHandle(FileDispositionInfoEx) with FILE_DISPOSITION_POSIX_SEMANTICS to instantly unbind names.
3. Thread pool tuning: Partition work per folder to eliminate directory metadata contention across threads; measure optimal thread count.
4. Selective computations: Skip calculating sizes in --yes mode unless full report requested.
5. Process search optimization: Replace slow module enumeration with fast image path checks and filter by process attributes before attempting module inspection.
