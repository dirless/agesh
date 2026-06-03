# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
# Build both binaries (release, optimized for the local CPU)
just build

# Run tests (randomized order, parallel)
just spec

# Lint: format check + ameba static analysis
just lint

# Statically linked binaries (requires .local/lib/libzstd.a — see justfile)
just build-static

# Run a single spec file
crystal spec spec/protocol/handshake_spec.cr

# Debug build (faster compile, includes debug info)
crystal build src/cli/server.cr -o bin/agesh-server
crystal build src/cli/client.cr -o bin/agesh
```

## Architecture

agesh is an AGE-encrypted remote shell. Everything lives under the `AgeSh` module. `src/agesh.cr` is the shared require file that both CLI entry points (`src/cli/server.cr`, `src/cli/client.cr`) pull in.

### Five-phase protocol

Each connection goes through these phases in `Server::Connection#run` and `ClientCLI.run`:

1. **Version exchange** — `Handshake.server/client` exchanges protocol version then ephemeral X25519 public keys
2. **Key derivation** — `Crypto::SessionKey.derive` calls HKDF-SHA256 with `salt = client_pub || server_pub` to produce a symmetric transport key
3. **Transport session** — `Transport::Session` splits the transport key into two directional ChaCha20-Poly1305 keys via HKDF (SEND_INFO / RECV_INFO). Each direction has its own 32-bit counter for the nonce.
4. **Challenge-response auth** — `Authentication.server/client`: server wraps a 32-byte random challenge with the client's AGE public key via `Crypto::AuthWrap` (same X25519+HKDF+ChaCha20-Poly1305 as AGE file encryption). Client unwraps, verifies with constant-time comparison, returns it as proof.
5. **Session setup + data channel** — `Session.server_setup/client_setup` exchanges terminal parameters; server forks via `UserSession.spawn_with_master` (raw LibC only post-fork), then two fibers proxy bidirectional data between the PTY master fd and the encrypted socket.

### Key design constraints

**Post-fork child must use only raw LibC calls.** Crystal's GC is not fork-safe. `UserSession.spawn_with_master` builds all Crystal heap objects (strings, arrays) in the parent before `LibC.fork`, then the child only calls LibC functions (`setsid`, `ioctl`, `dup2`, `setgid`, `initgroups`, `setuid`, `chdir`, `execve`, `_exit`). Never add Crystal runtime calls in the child branch.

**No shelling out.** The codebase never uses `system()`, backticks, or `Process.run`. The server uses `LibC.execve` directly.

### Module responsibilities

| Module | Responsibility |
|--------|----------------|
| `Protocol::Framer` | Length-prefixed wire framing — `[4-byte BE length][payload]`. Raises on errors during handshake; returns bool on the data channel for clean EOF. |
| `Protocol::Messages` | Pure codec — serialize/deserialize all protocol messages. No I/O. |
| `Protocol::Handshake` | Version exchange + X25519 ephemeral key exchange. |
| `Protocol::Authentication` | Challenge-response auth over the encrypted transport. |
| `Protocol::Session` | Terminal parameter exchange (term type, rows, cols, env). |
| `Protocol::Transport` | `Session` holds two `Direction` objects. Each `Direction` encrypts/decrypts with ChaCha20-Poly1305 using a monotonic counter nonce. |
| `Crypto::SessionKey` | HKDF derivation of the transport key from the X25519 shared secret. |
| `Crypto::AuthWrap` | AGE-style wrapping/unwrapping of the auth challenge. |
| `Server::Connection` | Per-connection handler — orchestrates phases 1–5. Runs each connection in a fiber. |
| `Server::AuthorizedKeys` | Parses `~/.age/authorized_keys` (one `age1...` key per line, `#` comments). |
| `Server::UserSession` | Forks, drops privileges, execs the user's shell. |
| `Client::Terminal` | Raw mode, winsize queries, SIGWINCH → resize messages. |

### Testing

`spec/spec_helper.cr` defines `DuplexIO` (reads from one `IO::Memory`, writes to another) to simulate bidirectional sockets in unit tests. Protocol tests wire up client and server sides against each other through paired `DuplexIO` instances.
