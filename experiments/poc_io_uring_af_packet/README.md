# PoC: `io_uring` with `AF_PACKET`

This experiment is a minimal, self-contained proof-of-concept to demonstrate and verify the use of the `tokio-uring` runtime for reading raw packets from an `AF_PACKET` socket.

## Purpose

The primary goal is to establish a correct, working pattern for the core data plane ingress path as defined in the project's architecture. It proves that a raw file descriptor, created using `libc` calls to set up an `AF_PACKET` socket, can be successfully integrated into the `tokio-uring` ecosystem for high-performance, asynchronous I/O.

This PoC was created to de-risk the implementation after significant challenges with higher-level abstractions (`nix` crate) failed.

## How to Run

The included `run_test.sh` script automates the entire test, including setting up an isolated network environment.

It requires `sudo` privileges to create network namespaces and configure interfaces.

```sh
sudo ./run_test.sh
```
