# agesh

**AGE-encrypted terminal access client and server.**

A secure remote shell that uses [age](https://age-encryption.org/) (X25519 + ChaCha20-Poly1305) for end-to-end encryption instead of SSH's transport layer. Public keys in `~/.age/authorized_keys` authenticate users — no CA, no certificate management.

## How it works

The protocol has five phases:

1. **Version exchange** — client and server agree on protocol version
2. **X25519 key exchange** — ephemeral keypair negotiation, HKDF transport key derivation
3. **Challenge-response authentication** — server wraps a random challenge with the client's AGE public key; client unwraps it to prove private key ownership
4. **Session setup** — client sends terminal type, window size, environment variables; server allocates a PTY and spawns a shell
5. **Data channel** — bidirectional encrypted proxy (ChaCha20-Poly1305 per-record encryption) between client stdin/stdout and the remote PTY

## Requirements

- **Crystal** >= 1.20.0
- **age-crystal** library (local dependency, see `shard.yml`)

## Build

```sh
# Server binary
crystal build src/cli/server.cr -o bin/agesh-server

# Client binary
crystal build src/cli/client.cr -o bin/agesh
```

## Setup

### Generate an identity (on the client)

```sh
agesh keygen
```

This creates `~/.age/identity` (secret key) and `~/.age/identity.pub` (public key).
Add the public key to each server you want to connect to.

### Authorize a client key (on the server)

Append the client's `age1...` public key to the user's `~/.age/authorized_keys`:

```sh
echo "age1..." >> ~/.age/authorized_keys
```

One key per line. Lines starting with `#` and inline comments are supported.

## Usage

### Server

```sh
agesh-server
agesh-server -b 127.0.0.1 -p 2202
```

| Option | Default | Description |
|--------|---------|-------------|
| `-b, --bind ADDR` | `0.0.0.0` | Bind address |
| `-p, --port PORT` | `2202` | Listen port |
| `-h, --help` | | Show help |

### Client

```sh
agesh user@host
agesh user@host -p 2222
agesh user@host -i ~/.age/work-identity
```

| Option | Default | Description |
|--------|---------|-------------|
| `-p, --port PORT` | `2202` | Server port |
| `-i, --identity FILE` | `~/.age/identity` | AGE secret key to authenticate with |
| `-h, --help` | | Show help |

The client reads the user's `~/.age/identity`, derives the corresponding public key, authenticates over the encrypted channel, and opens a remote shell in raw terminal mode.

## Security

- **No shelling out.** The codebase never invokes a shell — no `system()`, no backticks, no `Process.run`. The server uses raw `LibC.execve` to replace the process image after fork.
- **Fork-safe child setup.** All Crystal heap allocations happen in the parent before `fork()`. The child uses only raw `LibC` calls to set up the PTY, drop privileges (setgid/initgroups/setuid), chdir, and exec.
- **Constant-time comparison.** Challenge verification uses XOR + OR to prevent timing side-channels.
- **Per-direction transport counters.** Records are tagged with a counter (max 2³² per direction, ~256 TiB at 64 KiB per record) to prevent replay.
- **Minimal attack surface.** No dependency on OpenSSL, no certificate infrastructure, no SSH daemon modifications.

## Tests

```sh
crystal spec
```

23 examples covering:
- Session key derivation (HKDF)
- Auth challenge wrapping/unwrapping (AGE file encryption flow)
- Protocol message serialization
- Length-prefixed framing
- Transport encryption/decryption
- Handshake protocol logic
- Challenge-response authentication

## License

MIT