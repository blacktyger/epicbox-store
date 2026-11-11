# epicbox-store

The mailboxes of an Epicbox relay, kept in an Internet Computer canister.

Wallets keep speaking Epicbox. A front-end translates their websocket frames into calls on this
canister; other canisters call it directly; any HTTPS client can use its `/v1/` API. The canister
checks every signature itself, so no front-end can forge a message, read a mailbox without the
owner's signature over a fresh challenge, or acknowledge a message on the owner's behalf.

| | |
|---|---|
| Canister | `m6po5-ayaaa-aaaag-azikq-cai` (subnet `lspz2-…`) |
| Front-end | `wss://icpepicbox.btlabs.uk` (Epicbox 3.0.0) |
| HTTPS | `https://m6po5-ayaaa-aaaag-azikq-cai.raw.icp0.io/v1/info` |

## What it does

- **Posts** are Epicbox `PostSlate`s, unchanged. A post is accepted when `signature` verifies over
  `str` for the key in `from`. It goes to the mailbox of the key in `str.destination.public_key`.
- **Routing:** a post whose `str.destination` domain is one this store answers for
  (`set_local_domains`) is kept. Any other is queued for a front-end to forward to that relay.
- **Reading** needs the mailbox key's signature over a challenge
  (`ebh-<unix seconds>-<random hex>`, at most 20 minutes old), or ownership. A canister claims an
  address once, by a signature over `epicbox-icp claim <its principal>`, and then reads and
  acknowledges as its owner.
- **Acknowledging** is signed over the message id, as Epicbox `Made` is.
- **Retention and limits:**
  - messages wait at most 7 days;
  - at most 200 pending per mailbox, and 20 per sender per mailbox;
  - a post that arrives twice is kept once;
  - posts over HTTPS are limited per sender key.
- **State** survives upgrades.

### Interfaces

- **Candid** (`epicbox-store.did`):
  - for owners: `post`, `claim`, `pull_owned`, `made_owned`;
  - for wallets with signatures: `pull`, `pull_many`, `made`;
  - for front-ends: `pull_outbound`, `outbound_done`;
  - for operators (and controllers): `add_poster`, `add_local_domain`;
  - for controllers only: `remove_poster`, `set_local_domains`, `set_operators`;
  - `stats`.

  `post` is open to approved front-ends and canisters (`posters`).
- **HTTPS**, `epicbox-https/0.1`, on the raw gateway domain:

  | Request | Purpose |
  |---|---|
  | `GET /v1/info` | what the store accepts |
  | `POST /v1/post` | a `PostSlate` |
  | `POST /v1/pull` | `{mailboxes: [{address, challenge, signature}], limit}` |
  | `POST /v1/made` | `{address, acks: [{id, signature}]}` |
  | `GET /stats` | counters |

  Reads are not certified; every message carries its sender's signature, which the client checks.

## Build it yourself

The build is reproducible on Linux. The same source gives the same bytes in any directory and on any
machine. The toolchain is pinned in `rust-toolchain.toml` (Rust 1.99.0, `wasm32-unknown-unknown`),
the dependencies in `Cargo.lock`, and `build.sh` rewrites local paths to fixed names.

```sh
# rustup installs the pinned toolchain and target on first use
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
git clone https://github.com/blacktyger/epicbox-store && cd epicbox-store
git checkout <commit>
./build.sh
```

`build.sh` prints the SHA-256 of `target/wasm32-unknown-unknown/release/epicbox_store.wasm`.

## Check what is running

A canister's module hash is the SHA-256 of the Wasm installed in it:

```sh
curl -s https://ic-api.internetcomputer.org/api/v3/canisters/m6po5-ayaaa-aaaag-azikq-cai \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["module_hash"], d["controllers"])'
```

If it equals the hash `build.sh` printed for a commit, that commit is what runs. Each deployment
lists its commit and hash in `DEPLOYMENTS.md`.

## Tests

```sh
cargo test
```

The tests include a message signed and encrypted by epic-wallet's own code, and the Epicbox address
vectors from LEPIC (`testdata/epicbox/`), so signature and address checks are proven against what
wallets produce.

## Control

While the store is young it has one controller, BT Labs. The plan is a multi-approval controller,
under which no upgrade happens without both parties' approval, and frozen code (no controller) once
it has stopped changing. The controllers are always visible with the command above.

Routine, additive settings (adding a poster or a local domain) are open to `operators`, so they do
not need the approvals. Removing a poster, replacing the domain list and changing the operators
stay with the controllers.

## Licence

Apache-2.0, see `LICENSE`. The test vectors in `testdata/epicbox/` come from
[LEPIC](https://github.com/BTLabsUK/lepic) (Apache-2.0).
