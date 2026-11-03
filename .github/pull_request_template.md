## Summary of Changes
Describe the motivation, technical approach, and bug or feature addressed.

## Category
- [ ] Bug fix
- [ ] Performance improvement
- [ ] Platform / Architecture support
- [ ] Documentation update
- [ ] Test coverage or fuzzer addition

## Verification
Detail the testing steps performed:
- [ ] Unit tests pass: `ctest --output-on-failure`
- [ ] Static analysis passes clean
- [ ] Verified on Windows 10/11 x64
- [ ] Verified on Windows 11 ARM64 (if applicable)

## Checks
- [ ] No external runtime DLL dependencies introduced (static CRT `/MT`)
- [ ] Windows API return values and handles checked properly
- [ ] All filesystem paths handle extended length paths (`\\?\`)
- [ ] No regression in scan or deletion latency
