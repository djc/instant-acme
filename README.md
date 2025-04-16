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
* Support for the [ACME renewal information (ARI)] extension
* Support for the [profiles] extension
* Support for account key rollover
* Support for account contacts update
* Uses hyper with rustls and Tokio for HTTP requests
* Uses *ring* or aws-lc-rs for ECDSA signing
* Minimum supported Rust version (MSRV): 1.70

[ACME renewal information (ARI)]: https://www.ietf.org/archive/id/draft-ietf-acme-ari-08.html
[profiles]: https://datatracker.ietf.org/doc/draft-aaron-acme-profiles/

## Cargo features

* `hyper-rustls` (default): use a hyper client with rustls
* `aws-lc-rs` (default): use the aws-lc-rs crate as the crypto backend
* `ring`: use the *ring* crate as the crypto backend
* `fips`: enable the aws-lc-rs crate's FIPS-compliant mode
* `x509-parser`: enable extracting `CertificateIdentifier` values for ARI from
  certificates
* `time`: enable fetching `RenewalInfo` for a `CertificateIdentifier`

If both `ring` and `aws-lc-rs` are enabled, `aws-lc-rs` will be used.

## Limitations

* Only supports P-256 ECDSA account keys for now

## Getting started

See the [examples](examples) directory for an example of how to use instant-acme.
