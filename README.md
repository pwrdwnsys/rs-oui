# oui
Rust library to lookup MAC/EUI48 OUI vendor name information from the [Wireshark manufacturer database](https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf).

[![crates.io](http://meritbadge.herokuapp.com/oui)](https://crates.io/crates/oui)
[![docs.rs](https://docs.rs/oui/badge.svg)](https://docs.rs/oui)
[![Build Status](https://travis-ci.org/pwrdwnsys/rs-oui.svg?branch=master)](https://travis-ci.org/pwrdwnsys/rs-oui)

This library allows you to provide a MAC/EUI48 address and returns information on the vendor registered to the [Organizationally Unique Identifier (OUI)](https://en.wikipedia.org/wiki/Organizationally_unique_identifier) component of the supplied address. For each entry in the Wireshark database, this will be at a minimum the vendor's Wireshark short name, but most entries include the full organization/company name and some also include a descriptive comment.

Where IEEE Registration Authority blocks have been sub-divided, the specific manufacturer is returned. Note that a vendor/organization may have been allocated multiple blocks by the IEEE - these are each treated independently, should a vendor sub-division be later re-allocated or renamed following acquisition.

Example wget command to download the manufacturer database:
`wget -O manuf.txt 'https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf'`

oui is available on [crates.io](https://crates.io/crates/oui) and can be included in your Cargo.toml as follows:

```toml
[dependencies]
oui = "0.5.1"
```

## Documentation

Documentation can be found at the official documentation repository: https://docs.rs/oui

## Examples

Check the `/examples` directory for usage.

Simple MAC address lookups:
```shell
RUST_LOG=oui=debug cargo run --example lookup
```

Export and subsequent re-import of the parsed Wireshark database:
```shell
RUST_LOG=oui=debug cargo run --example dumpdb
```

## Feedback and Enhancements

I welcome feedback and enhancements to this library. Please create a Github Issue or a Pull Request subject to the license and contribution sections below.

## License
oui is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in oui by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
