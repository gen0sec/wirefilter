# Wirefilter

[![Build status](https://img.shields.io/travis/com/cloudflare/wirefilter/master.svg)](https://travis-ci.com/cloudflare/wirefilter)
[![Crates.io](https://img.shields.io/crates/v/wirefilter-engine.svg)](https://crates.io/crates/wirefilter-engine)
[![License](https://img.shields.io/github/license/cloudflare/wirefilter.svg)](LICENSE)

This is an execution engine for [Wireshark®](https://www.wireshark.org/)-like filters.

It contains public APIs for parsing filter syntax, compiling them into
an executable IR and, finally, executing filters against provided values.

## Example

```rust
use wirefilter::{ExecutionContext, Scheme};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a map of possible filter fields.
    let scheme = Scheme! {
        http.method: Bytes,
        http.ua: Bytes,
        port: Int,
    }
    .build();

    // Parse a Wireshark-like expression into an AST.
    let ast = scheme.parse(
        r#"
            http.method != "POST" &&
            not http.ua matches "(googlebot|facebook)" &&
            port in {80 443}
        "#,
    )?;

    println!("Parsed filter representation: {:?}", ast);

    // Compile the AST into an executable filter.
    let filter = ast.compile();

    // Set runtime field values to test the filter against.
    let mut ctx = ExecutionContext::new(&scheme);

    ctx.set_field_value(scheme.get_field("http.method").unwrap(), "GET")?;

    ctx.set_field_value(
        scheme.get_field("http.ua").unwrap(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
    )?;

    ctx.set_field_value(scheme.get_field("port").unwrap(), 443)?;

    // Execute the filter with given runtime values.
    println!("Filter matches: {:?}", filter.execute(&ctx)?); // true

    // Amend one of the runtime values and execute the filter again.
    ctx.set_field_value(scheme.get_field("port").unwrap(), 8080)?;

    println!("Filter matches: {:?}", filter.execute(&ctx)?); // false

    Ok(())
}
```

## Fuzzing

There are fuzz tests in the fuzz directory.

Install afl:

```
cargo install afl --force
```

Build `bytes` fuzz test:

```
cd fuzz/bytes
cargo afl build
```

Run fuzz test (from inside `fuzz/bytes` directory):

```
cargo afl fuzz -i in -o out ../../target/debug/fuzz-bytes
```

If you see an error like:

```
Looks like the target binary is not instrumented!
```

Try deleting the compiled binary and re-building with `cargo afl build`.

## Licensing

Licensed under the MIT license. See the [LICENSE](LICENSE) file for details.

## Release Process

The `wirefilter-engine` crate (workspace member) is published to the
private `gen0sec` Cargo registry (`https://crates-internal.g0s.dev`).
The other workspace members (`wirefilter-ffi`, `wirefilter-wasm`, fuzz
targets) are marked `publish = false` and are not released. Releases
are driven by `vX.Y.Z` git tags — `.github/workflows/release.yaml`
handles build, publish, and GitHub Release creation.

### One-time setup

- **Repo secret**: `GEN0SEC_CARGO_TOKEN` — bearer token for the registry.
- **`release` GitHub environment** (Settings → Environments → New) for
  optional manual approval gating before publish.
- **Local cargo config** (`~/.cargo/config.toml`):

  ```toml
  [registries.gen0sec]
  index = "sparse+https://crates-internal.g0s.dev/api/v1/crates/"
  credential-provider = ["cargo:token"]
  token = "<your_token>"
  ```

### Cutting a release

The workspace version lives in `[workspace.package]` in the root
`Cargo.toml`. Use `cargo-release` from the workspace root:

```bash
cargo install cargo-release
cargo release patch --execute   # or minor / major / 1.2.3
```

It bumps the workspace version + `Cargo.lock`, commits, creates
`vX.Y.Z`, and pushes. CI publishes on the tag push.
`[package.metadata.release] publish = false` in `engine/Cargo.toml`
keeps the local command from publishing — that is left to CI.

### CI jobs on `v*` tag

1. **`verify-version`** — fails if tag does not match the workspace
   version.
2. **`package-crate`** — `cargo package -p wirefilter-engine --registry gen0sec --locked`,
   uploads `wirefilter-engine-X.Y.Z.crate`.
3. **`publish`** — `release` environment-gated
   `cargo publish -p wirefilter-engine` with retry/timeout hardening.
4. **`gh-release`** — downloads `.crate`, generates SHA256 sidecars,
   creates a GitHub Release.

### Required Cargo.toml metadata

The gen0sec registry enforces these `[package]` fields on
`wirefilter-engine`:

`name`, `description`, `repository`, `license`, `authors`, `categories`,
`keywords`, `links`, `readme`.
