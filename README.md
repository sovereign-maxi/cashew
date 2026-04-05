# Cashew

Elixir NIF bindings for secp256k1 cryptographic primitives used by the
[Cashu](https://cashu.space) ecash protocol.

Built with [Rustler](https://github.com/rustler-elixir/rustler) on top of
[`secp256k1`](https://crates.io/crates/secp256k1) (libsecp256k1 bindings).

## What it does

| Capability | Spec |
|---|---|
| Blind Diffie-Hellman Key Exchange (BDHKE) | [NUT-00](https://github.com/cashubtc/nuts/blob/main/00.md) |
| Hash-to-curve (try-and-increment) | [NUT-00](https://github.com/cashubtc/nuts/blob/main/00.md) |
| DLEQ proofs on blind signatures | [NUT-12](https://github.com/cashubtc/nuts/blob/main/12.md) |
| BIP-340 Schnorr signing / verification | [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) |

All functions operate on raw binaries — no structs, no protocol-level framing.
Higher-level Cashu token types live in the consuming application.

## Prerequisites

- Elixir >= 1.17
- Rust toolchain (stable) — the NIF compiles automatically via Rustler

## Installation

Add as a path dependency in your `mix.exs`:

```elixir
{:cashew, path: "../packages/cashew"}
```

## Usage

### Key generation

```elixir
{:ok, {privkey, pubkey}} = Cashew.generate_keypair()
{:ok, pubkey}            = Cashew.pubkey_from_privkey(privkey)
```

### BDHKE blind signature round-trip (NUT-00)

```elixir
# Client: blind a secret
{:ok, {b_prime, r}} = Cashew.step1_alice(secret)

# Mint: sign the blinded message
{:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)

# Client: unblind the signature
{:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)

# Mint: verify an unblinded token
:ok = Cashew.verify(privkey, secret, c)
```

### DLEQ proofs (NUT-12)

```elixir
# Mint: prove honest signing
{:ok, {e, s}} = Cashew.generate_dleq_proof(privkey, b_prime)

# Client: verify the proof
:ok = Cashew.verify_dleq_proof(pubkey, b_prime, c_prime, e, s)
```

### Hash-to-curve

```elixir
{:ok, point} = Cashew.hash_to_curve(secret)
# => 33-byte compressed secp256k1 point
```

### BIP-340 Schnorr signatures

```elixir
msg_hash = :crypto.hash(:sha256, message)

{:ok, {signature, xonly_pubkey}} = Cashew.schnorr_sign(privkey, msg_hash)
:ok = Cashew.schnorr_verify(xonly_pubkey, msg_hash, signature)
```

## API reference

| Function | Description |
|---|---|
| `generate_keypair/0` | Random 32-byte privkey + 33-byte compressed pubkey |
| `pubkey_from_privkey/1` | Derive compressed pubkey from privkey |
| `hash_to_curve/1` | NUT-00 hash-to-curve (domain-separated SHA-256, try-and-increment) |
| `step1_alice/1,2` | Blind a secret: `B' = Y + r*G` (random or provided `r`) |
| `step2_bob/2` | Sign blinded message: `C' = k * B'` |
| `step3_alice/3` | Unblind signature: `C = C' - r*K` |
| `verify/3` | Verify unblinded token: `C == k * hash_to_curve(secret)` |
| `generate_dleq_proof/2` | NUT-12 DLEQ proof `{e, s}` for a blind signature |
| `verify_dleq_proof/5` | Verify a DLEQ proof against pubkey, B', C' |
| `schnorr_sign/2` | BIP-340 Schnorr sign (64-byte sig + 32-byte x-only pubkey) |
| `schnorr_verify/3` | BIP-340 Schnorr verify |
| `ensure_loaded!/0` | Assert the NIF is available (raises on failure) |

All functions return `{:ok, result}` on success or `{:error, reason}` on
failure, except `verify/3` and `schnorr_verify/3` which return `:ok` or
`{:error, :invalid_signature}`, and `ensure_loaded!/0` which raises.

## Development

### Pre-commit Hook

```bash
# Enable pre-commit hooks (format, credo, tests, dialyzer)
git config core.hooksPath hooks
```

### Tests

```bash
source $HOME/.cargo/env   # ensure Rust toolchain is on PATH
mix deps.get
mix test                  # 100 tests including property-based (StreamData)
```

## License

MIT
