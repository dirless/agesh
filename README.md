# agesh

**AGE-encrypted remote shell and file copy.**

Secure remote access using [age](https://age-encryption.org/) (X25519 + ChaCha20-Poly1305) instead of SSH's transport. Public keys in `~/.age/authorized_keys` authenticate users — no CA, no certificates.

Three binaries: `agesh-server` (server), `agesh` (shell client), `age-cp` (file copy over rsync).

## Build

```sh
just build                                    # agesh-server + agesh (release)
crystal build src/cli/copy.cr -o bin/age-cp   # age-cp
```

Requires Crystal >= 1.20.0 and the `age-crystal` shard (see `shard.yml`).

## Setup

```sh
agesh keygen                                  # client: creates ~/.age/identity{,.pub}
echo "age1..." >> ~/.age/authorized_keys       # server: authorize a client key
```

`authorized_keys` is one `age1...` key per line; `#` comments allowed.

## Usage

### Server

```sh
agesh-server [-b 0.0.0.0] [-p 2202]
```

### Shell client

```sh
agesh user@host [-p 2202] [-i ~/.age/identity]
```

Authenticates with your identity over the encrypted channel and opens a remote shell in raw terminal mode.

### File copy

```sh
age-cp [-l user] [-p 2202] [-i ~/.age/identity] [--progress] [--debug] SRC user@host:DEST
```

Wraps `rsync` (required on both ends), tunneling it over an authenticated agesh session. Unrecognized flags pass through to rsync; `--progress` shows a transfer bar. `~/` in `DEST` resolves relative to the remote home.

## Protocol

Each connection runs five phases: **version exchange** → **X25519 key exchange** (HKDF transport key) → **challenge-response auth** (server wraps a random challenge to the client's age key; client unwraps to prove key ownership) → **session setup** (PTY + shell, or piped command for `age-cp`) → **encrypted data channel** (per-record ChaCha20-Poly1305, separate counter per direction).

## Security

- **No shelling out** — the server `fork`s and uses raw `LibC.execve`; no `system()`/backticks/`Process.run`.
- **Fork-safe child** — all Crystal allocations happen pre-fork; the child uses only `LibC` to set up the PTY, drop privileges, and exec.
- **Constant-time** challenge verification; **per-direction counters** prevent replay.
- **Minimal surface** — no OpenSSL, no certificates, no SSH daemon.

## Tests

```sh
crystal spec   # or: just spec
```

## License

MIT
