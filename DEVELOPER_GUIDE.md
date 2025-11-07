# Developer Guide

This guide provides the essential steps to set up a development environment for the Multicast Relay project. Our goal is to enable you to contribute effectively, not to prescribe a specific set of tools or a rigid workflow.

The process is broken into two main parts: a one-time setup of the necessary toolchains, and the day-to-day commands you will use to build and test the code.

## 1. One-Time Environment Setup

This section covers the prerequisites you need to have installed on your Linux host.

### Essential Build Tools

First, you need a C compiler and standard development libraries. These are required to compile Rust itself and many common Rust libraries.

*   **For Fedora / RHEL / CentOS:**
    ```bash
    sudo dnf group install "Development Tools"
    ```

*   **For openSUSE:**
    ```bash
    sudo zypper install -t pattern devel_basis
    ```

*   **For Ubuntu / Debian:**
    ```bash
    sudo apt update
    sudo apt install build-essential
    ```

*   **For Gentoo:**
    ```bash
    sudo emerge --ask --oneshot dev-util/pkgconf dev-util/ccache
    ```

*   **For Arch Linux:**
    ```bash
    sudo pacman -S base-devel
    ```

### The Rust Toolchain

The only other prerequisite is the Rust toolchain, which **must be managed by `rustup`**.

#### Why `rustup`? (And not your distribution's package)

While you can install Rust via your distribution's package manager, we require `rustup` for this project. The reason is **consistency**.

Distribution packages for Rust can be months or even years out of date, which can cause compilation errors with modern Rust code. `rustup` is the official tool that allows our project to pin the **exact version** of the Rust compiler we use. This is done via the `rust-toolchain.toml` file in our repository.

When you use `rustup`, it will automatically detect this file and ensure you are using the same toolchain as every other developer and our CI server. This completely eliminates "it works on my machine" errors related to the compiler version.

1.  **Install `rustup`:**
    The following command will download and run the official `rustup` installer. It's the same for all distributions.
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
    When prompted, choose the default installation option.

2.  **Configure your shell:**
    After the installation is complete, you must configure your current shell to add Cargo's binary directory to your `PATH`.
    ```bash
    source "${HOME}/.cargo/env"
    ```
    This step is only needed once per session, as it will be configured in your shell's startup file automatically.

    **Verification:** To ensure your `PATH` is set up correctly, open a **new** terminal and run `which cargo`. The output should be similar to `/home/your-username/.cargo/bin/cargo`. If the command returns "not found", you may need to log out and log back in, or manually add the line `source "$HOME/.cargo/env"` to your shell's startup file (e.g., `~/.bashrc`, `~/.zshrc`).

### Project-Specific Developer Tools

This project uses the `just` command runner to simplify common development tasks. You need to install it once globally.

From your terminal, run:
```bash
cargo install just
```

This command installs `just` into your Cargo binary directory (`~/.cargo/bin`), which should already be in your `PATH` if you followed the `rustup` setup correctly.

Your environment is now fully bootstrapped.

## 2. Core Development Workflow

This project uses a `justfile` as the single source of truth for common development tasks. It provides a convenient way to run the same checks that our Continuous Integration (CI) pipeline uses.

### Verifying Your Changes

Before committing, the primary command you will use is:
```bash
just check
```
This single command runs the complete suite of quality gates:
1.  **`fmt`**: Checks for correct code formatting.
2.  **`clippy`**: Lints the code for common mistakes and style issues.
3.  **`build`**: Compiles the entire project.
4.  **`test`**: Runs all unit and integration tests.
5.  **`audit`**: Checks for known security vulnerabilities in the dependencies.
6.  **`outdated`**: Checks for outdated dependencies.

### Running Individual Tasks

You are not required to run the entire suite every time. You can run any of the individual steps as needed. For example, to just run the tests:
```bash
just test
```
To see all available commands, you can view the `justfile` in the root of the repository.
