# Deployments

Each row is one install of `m6po5-ayaaa-aaaag-azikq-cai`. The module hash is the SHA-256 of the
Wasm, as `./build.sh` prints it for that commit and as the canister reports it
(`icp canister status`, or `module_hash` from the ICP dashboard API).

| Date (UTC) | Commit | Module hash | Mode |
|---|---|---|---|
| 2026-11-11 | `6b9319a` | `e12f1699074392f81208e01386563e377fb6b2c5cabc73ce88a7338add59b477` | upgrade, state kept |
| 2026-11-11 | `24d14dd` | `dd7c399f895635451d17581a24c3964064446135c68af49c2a679b316f0dd196` | upgrade, state kept |

Installs before 2026-11-11 were development builds made on Windows. They are not reproducible from
this repository and are not listed.
