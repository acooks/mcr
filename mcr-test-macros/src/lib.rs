//! Test macros for MCR integration tests
//!
//! This crate provides procedural macros for test prerequisites like requiring root privileges.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Require root privileges for this test
///
/// This attribute macro injects a root privilege check at the start of the test function.
/// If the test is not running as root, it will panic with a clear skip message.
///
/// # Example
///
/// ```ignore
/// use mcr_test_macros::requires_root;
///
/// #[tokio::test]
/// #[ignore]
/// #[requires_root]
/// async fn test_network_namespace() -> Result<()> {
///     // Test code here - will only run as root
///     Ok(())
/// }
/// ```
///
/// # Implementation
///
/// The macro transforms:
/// ```ignore
/// #[requires_root]
/// async fn test_something() -> Result<()> {
///     // test body
/// }
/// ```
///
/// Into:
/// ```ignore
/// async fn test_something() -> Result<()> {
///     if !nix::unistd::geteuid().is_root() {
///         panic!("SKIPPED: Test requires root privileges - run with: sudo -E cargo test ...");
///     }
///     // test body
/// }
/// ```
#[proc_macro_attribute]
pub fn requires_root(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);

    let attrs = &input.attrs;
    let vis = &input.vis;
    let sig = &input.sig;
    let block = &input.block;

    let output = quote! {
        #(#attrs)*
        #vis #sig {
            // Check for root privileges
            if !nix::unistd::geteuid().is_root() {
                panic!("SKIPPED: Test requires root privileges - run with: sudo -E cargo test --test integration test_basic -- --ignored --test-threads=1");
            }

            // Original function body
            #block
        }
    };

    output.into()
}
