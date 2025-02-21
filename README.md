# instant-acme: async, pure-Rust ACME client

[![Documentation](https://docs.rs/instant-acme/badge.svg)](https://docs.rs/instant-acme/)
[![Crates.io](https://img.shields.io/crates/v/instant-acme.svg)](https://crates.io/crates/instant-acme)
[![Build status](https://github.com/djc/instant-acme/workflows/CI/badge.svg)](https://github.com/djc/instant-acme/actions?query=workflow%3ACI)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

instant-acme is an async, pure-Rust ACME (RFC 8555) client.

instant-acme is used in production at [Instant Domain Search](https://instantdomainsearch.com/) to help
us provision TLS certificates within seconds for our customers. instant-acme relies
on Tokio and rustls to implement the [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html)
specification.

## Features

* Store/recover your account credentials by serializing/deserializing
* Fully async implementation with tracing support
* Support for processing multiple orders concurrently
* Support for external account binding
* Support for certificate revocation
* Uses hyper with rustls and Tokio for HTTP requests
* Uses *ring* or aws-lc-rs for ECDSA signing
* Minimum supported Rust version (MSRV): 1.70

## Cargo features

* `hyper-rustls` (default): use a hyper client with rustls
* `ring` (default): use the *ring* crate as the crypto backend
* `aws-lc-rs`: use the aws-lc-rs crate as the crypto backend
* `fips`: enable the aws-lc-rs crate's FIPS-compliant mode

If both `ring` and `aws-lc-rs` are enabled, which backend is used depends on the `fips` feature.
If `fips` is enabled, `aws-lc-rs` is used; otherwise, `ring` is used.

## Limitations

* Only supports P-256 ECDSA account keys for now

## Getting started

See the [examples](examples) directory for an example of how to use instant-acme.
