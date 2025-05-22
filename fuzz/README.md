# Encryptor Fuzzer

A step-by-step guide to fuzz testing the `encryptor` crate from scratch using both **libFuzzer** (via `cargo-fuzz`) and **AFL++**.

---

## Getting Started

### Prerequisites

1. **Install Rust via `rustup`** (ensure `rustup`’s toolchains take precedence over Homebrew):
   ```bash
   brew uninstall rust
   curl https://sh.rustup.rs -sSf | sh
   echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
   source ~/.zshrc
   ```

2. **Add the Nightly toolchain** (required for sanitizer flags):
   ```bash
   rustup toolchain install nightly
   ```

3. **Install `cargo-fuzz`** (for libFuzzer harness):
   ```bash
   cargo +nightly install cargo-fuzz
   ```

4. **Install AFL++** (the fuzzer executable):
   ```bash
   brew install afl++
   ```

5. **Install `cargo-afl`** (Rust wrapper for AFL++):
   ```bash
   cargo +stable install cargo-afl --locked
   ```

---

## Project Layout

```text
encryptor/                     # Your library crate
└── fuzz/
    ├── Cargo.toml             # Fuzz project manifest
    └── fuzz_targets/
        ├── encryptor_fuzz.rs  # libFuzzer CDYLIB harness
        └── afl_harness.rs     # AFL++ binary harness
```

---

## Running the Fuzzer

### 1. libFuzzer (via `cargo-fuzz`)

```bash
cd encryptor/fuzz
rustup override set nightly   # ensure nightly in this folder
cargo fuzz run encryptor_fuzz
```

Fuzzer artifacts (crashes, units, logs) appear in `fuzz/artifacts/encryptor_fuzz/`.

### 2. AFL++

#### a. Prepare a seed corpus

```bash
cd encryptor/fuzz
mkdir -p in out
echo "hello" > in/seed1  # a minimal seed input
```

#### b. Build the AFL binary

```bash
cargo afl build --features afl --bin encryptor_afl
```

#### c. Run the fuzzer

```bash
afl-fuzz -i in -o out -- ./target/debug/encryptor_afl
```

- `-i in`: input directory with seed testcases
- `-o out`: output directory for findings (crashes, hangs)

---

## Deep Dive: How Fuzzing Works

### Coverage-Guided Mutation

- **Instrumentation**: Instrumented code logs executed branches (ASan or AFL persistent mode).
- **Mutators**: Random bit-flips, arithmetic tweaks, and splicing of existing seeds generate new inputs.
- **Feedback Loop**: Inputs that increase coverage are retained for further mutation.

### Persistent Mode & Performance

- **libFuzzer**: In-process fuzzer that invokes your entry function repeatedly for high throughput.
- **AFL++**: Persistent and deferred-fork modes avoid full process respawns, boosting speed.

### What It Tests

1. **API Correctness**
   - `derive_key()` must never panic on malformed input.
   - Encryption/decryption APIs must round-trip data exactly.

2. **Memory Safety**
   - ASan/UBSan detect out-of-bounds, use-after-free, integer overflows, etc.

3. **Edge Cases & Unhandled Errors**
   - Unexpected byte sequences expose logic flaws and unchecked error paths.

### Why Run Both

| Feature           | libFuzzer (`cargo-fuzz`)        | AFL++ (`cargo-afl` + `afl-fuzz`)     |
|-------------------|---------------------------------|--------------------------------------|
| Sanitizer Support | Built-in ASan/UBSan             | Separate ASan build required         |
| Mutation Engine   | Custom mutators + splicing      | Mature AFL++ mutators & splicing     |
| Parallelism       | Multi-threaded                  | Master/secondary mode across cores   |
| Invocation        | `cargo fuzz run …`              | `afl-fuzz -i … -o … -- ./bin`        |

> **Tip:** Fuzzing is an ongoing process. Quick bugs surface in minutes; deep edge-case issues can take hours or days. Continuously expand your seed corpus with representative examples and triage crashes promptly to maximize coverage.
