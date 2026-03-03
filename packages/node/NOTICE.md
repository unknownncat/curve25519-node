# NOTICE

This repository is distributed under the MIT license and includes third-party software components.

Primary package: `@unknownncat/curve25519-node`  
Repository: <https://github.com/unknownncat/curve25519-node>

## Security and Disclosure

- Security policy: [SECURITY.md](./SECURITY.md)
- Vulnerability reporting should follow the private disclosure flow described in that file.

## Direct ecosystem references

- `curve25519-js` — MIT or CC0 (as declared upstream)  
  <https://github.com/harveyconnor/curve25519-js>
- `TweetNaCl.js` — Public Domain (as declared upstream)  
  <https://tweetnacl.js.org/>
- OpenSSL (used through Node.js `node:crypto`) — Apache-2.0  
  <https://www.openssl.org/>

## Rust dependency notices

The project contains Rust crates for WASM and native N-API:

- `rust/crates/curve-wasm`
- `rust/crates/axlsign-wasm`
- `rust/crates/curve-napi`

License inventory was collected with:

```bash
cargo license -t
```

### Crates present in both Rust projects

| Crate                      | License                             |
| -------------------------- | ----------------------------------- |
| block-buffer               | Apache-2.0 OR MIT                   |
| bumpalo                    | Apache-2.0 OR MIT                   |
| cfg-if                     | Apache-2.0 OR MIT                   |
| cpufeatures                | Apache-2.0 OR MIT                   |
| crypto-common              | Apache-2.0 OR MIT                   |
| curve25519-dalek           | BSD-3-Clause                        |
| curve25519-dalek-derive    | Apache-2.0 OR MIT                   |
| digest                     | Apache-2.0 OR MIT                   |
| ed25519                    | Apache-2.0 OR MIT                   |
| ed25519-dalek              | BSD-3-Clause                        |
| fiat-crypto                | Apache-2.0 OR BSD-1-Clause OR MIT   |
| generic-array              | MIT                                 |
| libc                       | Apache-2.0 OR MIT                   |
| once_cell                  | Apache-2.0 OR MIT                   |
| proc-macro2                | Apache-2.0 OR MIT                   |
| quote                      | Apache-2.0 OR MIT                   |
| rand_core                  | Apache-2.0 OR MIT                   |
| rustc_version              | Apache-2.0 OR MIT                   |
| rustversion                | Apache-2.0 OR MIT                   |
| semver                     | Apache-2.0 OR MIT                   |
| sha2                       | Apache-2.0 OR MIT                   |
| signature                  | Apache-2.0 OR MIT                   |
| subtle                     | BSD-3-Clause                        |
| syn                        | Apache-2.0 OR MIT                   |
| typenum                    | Apache-2.0 OR MIT                   |
| unicode-ident              | (Apache-2.0 OR MIT) AND Unicode-3.0 |
| version_check              | Apache-2.0 OR MIT                   |
| wasm-bindgen               | Apache-2.0 OR MIT                   |
| wasm-bindgen-macro         | Apache-2.0 OR MIT                   |
| wasm-bindgen-macro-support | Apache-2.0 OR MIT                   |
| wasm-bindgen-shared        | Apache-2.0 OR MIT                   |
| x25519-dalek               | BSD-3-Clause                        |

### Crates present only in `rust/crates/axlsign-wasm`

| Crate   | License           |
| ------- | ----------------- |
| zeroize | Apache-2.0 OR MIT |

### Local Rust crates

| Crate                   | License |
| ----------------------- | ------- |
| curve25519-node-wasm    | MIT     |
| curve25519-node-axlsign | MIT     |
| curve25519-node-napi    | MIT     |

## Notes

- Upstream licenses remain with their respective authors and projects.
- This NOTICE summarizes dependencies and does not replace upstream license texts.
- For full build/runtime details, see `README.md`, `README.en.md`, and `../../rust/README.md`.
