# Third-party components

| Component | Where | Licence | Notes |
|---|---|---|---|
| [c2pa-rs](https://github.com/contentauth/c2pa-rs) (`c2pa` crate) and its Rust dependencies | compiled into `c2paview-helper.exe` | MIT OR Apache-2.0 | The C2PA reference implementation, built with `rust_native_crypto` (no OpenSSL) and no HTTP client. Run `cargo tree -p c2paview-helper` for the full dependency list, or `cargo install cargo-license && cargo license` for per-crate licences. |
| Content Credentials icon (`assets/cr-icon.svg`, `assets/cr.ico`) | embedded in `c2paview.dll` | Trademark of the C2PA; source file MIT (Adobe, via `contentauth/c2pa-js-legacy`) | Used unaltered, as the C2PA UX guidance requires. See [assets/ICON-SOURCE.md](assets/ICON-SOURCE.md). |
| C2PA Conformance Program trust lists (`trust/c2pa-*.pem`) | `trust/` | CC-BY-4.0 (c2pa-org/conformance-public) | Snapshot; refresh with `Update-TrustLists.ps1`. |
| Interim Content Credentials trust list (`trust/interim-*`, `trust/store.cfg`) | `trust/` | Published by the Content Authenticity Initiative at contentcredentials.org | Snapshot; refresh with `Update-TrustLists.ps1`. |
| `samples/signed.jpg` (`CA.jpg`) | `samples/` | MIT OR Apache-2.0 (c2pa-rs test fixtures) | Signed with the C2PA test certificate, so it demonstrates the "signer can't be verified" state. |

Everything else in this repository is MIT, see [LICENSE](LICENSE).
