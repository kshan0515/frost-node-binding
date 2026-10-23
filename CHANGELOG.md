# Changelog

All notable changes to this project will be documented in this file.

## [0.2.1] - 2026-10-23

### Changed
- Updated CI Node.js version to `22`.

## [0.2.0] - 2026-10-12

### Added
- **Ephemeral Nonce ($k_i$) Memory Zeroization & Use-After-Free Protection**:
  - Implemented `ZeroizableNonces` wrapper (`Zeroize`, `Drop`, `ZeroizeOnDrop`) to guarantee automatic zeroization of sensitive nonce scalars upon drop or session completion.
  - Added explicit N-API methods `destroy()` and `isDestroyed()` (`is_destroyed()`) on `FrostExecutor`.
  - Guard against use-after-free with defensive check throwing `napi::Error::from_reason("Executor has already been destroyed")`.
- **N-API Asynchronous Worker (`stepAsync` / `step_async`)**:
  - Offloaded cryptographic steps to libuv worker threadpool via `napi::Task` trait (`StepTask`) without blocking the V8 event loop.
  - TypeScript signature: `stepAsync(inputs: Array<Buffer>): Promise<Array<Buffer>>` (backward compatible with synchronous `step`).
- **V8 Heap Isolation via `napi::External` Handles**:
  - Added `exportKeyshareHandle()` and `importKeyshareHandle(handle)` on `FrostExecutor`.
  - Added `exportKeyPackageHandle()` and `importKeyPackageHandle(handle, pubkeyPackageBin)` on `FrostExecutor`.
  - Added `dkgPart1Handle`, `dkgPart2Handle`, `dkgPart3Handle` on `FrostDkgState` and `signPart1Handle`, `signPart2Handle` on `FrostSigningState`.
  - Prevents sensitive private key packages from being copied into garbage-collected V8 heap memory.
- **Strict Participant Verification & Bad Share Detection**:
  - Round 1 and Round 2 validation for unauthorized participant identifiers and duplicate inputs.
  - Fraudulent / corrupted signature share detection via `frost_core::verify_signature_share`.
- Added unit tests in Rust and comprehensive Jest integration tests.

## [0.1.0] - 2026-08-26

- Initial release of FROST Ed25519 MPC Node.js native binding.
