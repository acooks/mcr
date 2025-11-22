// SPDX-License-Identifier: Apache-2.0 OR MIT
fn main() {
    // This build script tells rustc to recognize the `tarpaulin` cfg flag.
    // `cargo tarpaulin` sets this flag during its test runs, but the compiler
    // needs to be made aware of it to avoid "unexpected cfg" errors during
    // normal checks and builds.
    println!("cargo:rustc-check-cfg=cfg(tarpaulin)");
}
