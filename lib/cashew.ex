defmodule Cashew do
  @moduledoc """
  NIF bindings for secp256k1 cryptographic operations.

  Provides the raw cryptographic primitives used by the
  Blind Diffie-Hellman Key Exchange (BDHKE) protocol as specified
  by Cashu NUT-00. All functions accept and return raw binaries.

  Implements:
  - BDHKE blind signatures (NUT-00)
  - DLEQ proofs (NUT-12)
  - Hash-to-curve (NUT-00)
  - BIP-340 Schnorr signing
  """

  use Rustler,
    otp_app: :cashew,
    crate: "cashew"

  @doc """
  Generate a random secp256k1 keypair.

  Returns `{:ok, {privkey, pubkey}}` where `privkey` is a 32-byte binary
  and `pubkey` is a 33-byte compressed public key.
  """
  @spec generate_keypair() :: {:ok, {binary(), binary()}}
  def generate_keypair, do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Derive a compressed public key from a 32-byte private key.

  Returns `{:ok, pubkey}` where `pubkey` is a 33-byte compressed public key,
  or `{:error, reason}` if the private key is invalid.
  """
  @spec pubkey_from_privkey(binary()) :: {:ok, binary()} | {:error, atom()}
  def pubkey_from_privkey(privkey)
      when is_binary(privkey) and byte_size(privkey) == 32,
      do: :erlang.nif_error(:nif_not_loaded)

  def pubkey_from_privkey(_), do: {:error, :invalid_private_key_size}

  @doc """
  Hash arbitrary binary data to a secp256k1 curve point.

  Implements the Cashu NUT-00 hash_to_curve specification using
  domain-separated SHA256 and try-and-increment.

  Returns `{:ok, point}` where `point` is a 33-byte compressed public key.
  """
  @spec hash_to_curve(binary()) :: {:ok, binary()} | {:error, atom()}
  def hash_to_curve(message) when is_binary(message),
    do: :erlang.nif_error(:nif_not_loaded)

  def hash_to_curve(_), do: {:error, :invalid_input}

  @doc """
  Step 1 of BDHKE (Alice/client side): create blinded message.

  Computes B' = Y + r*G where Y = hash_to_curve(secret).
  The second argument can be a 32-byte blinding factor binary
  or nil to generate a random one.

  Returns `{:ok, {b_prime, r}}` where `b_prime` is the 33-byte blinded
  message and `r` is the 32-byte blinding factor used.
  """
  @spec step1_alice(binary(), binary() | nil) ::
          {:ok, {binary(), binary()}} | {:error, atom()}
  def step1_alice(secret, blinding_factor \\ nil)

  def step1_alice(secret, blinding_factor)
      when is_binary(secret) and (is_binary(blinding_factor) or is_nil(blinding_factor)),
      do: :erlang.nif_error(:nif_not_loaded)

  def step1_alice(_, _), do: {:error, :invalid_input}

  @doc """
  Step 2 of BDHKE (Bob/mint side): sign the blinded message.

  Computes C' = k * B' where k is the mint's private key.

  Returns `{:ok, c_prime}` where `c_prime` is a 33-byte compressed point.
  """
  @spec step2_bob(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def step2_bob(privkey, blinded_point)
      when is_binary(privkey) and byte_size(privkey) == 32 and
             is_binary(blinded_point) and byte_size(blinded_point) == 33,
      do: :erlang.nif_error(:nif_not_loaded)

  def step2_bob(_, _), do: {:error, :invalid_input}

  @doc """
  Step 3 of BDHKE (Alice/client side): unblind the signature.

  Computes C = C' - r*K where C' is the blind signature,
  r is the blinding factor, and K is the mint's public key.

  Returns `{:ok, c}` where `c` is a 33-byte compressed point.
  """
  @spec step3_alice(binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def step3_alice(c_prime, blinding_factor, mint_pubkey)
      when is_binary(c_prime) and byte_size(c_prime) == 33 and
             is_binary(blinding_factor) and byte_size(blinding_factor) == 32 and
             is_binary(mint_pubkey) and byte_size(mint_pubkey) == 33,
      do: :erlang.nif_error(:nif_not_loaded)

  def step3_alice(_, _, _), do: {:error, :invalid_input}

  @doc """
  Verify an unblinded signature.

  Checks that C == k * hash_to_curve(secret).

  Returns `:ok` if valid, `{:error, :invalid_signature}` otherwise.
  """
  @spec verify(binary(), binary(), binary()) :: :ok | {:error, atom()}
  def verify(privkey, secret, signature)
      when is_binary(privkey) and byte_size(privkey) == 32 and
             is_binary(secret) and
             is_binary(signature) and byte_size(signature) == 33,
      do: :erlang.nif_error(:nif_not_loaded)

  def verify(_, _, _), do: {:error, :invalid_input}

  @doc """
  BIP-340 Schnorr sign: produce a 64-byte signature and 32-byte x-only pubkey.

  Takes a 32-byte private key and a 32-byte message hash (e.g. SHA256 of event).
  Returns `{:ok, {signature_64, xonly_pubkey_32}}` or `{:error, reason}`.
  """
  @spec schnorr_sign(binary(), binary()) :: {:ok, {binary(), binary()}} | {:error, atom()}
  def schnorr_sign(privkey, msg_hash)
      when is_binary(privkey) and byte_size(privkey) == 32 and
             is_binary(msg_hash) and byte_size(msg_hash) == 32,
      do: :erlang.nif_error(:nif_not_loaded)

  def schnorr_sign(_, _), do: {:error, :invalid_input}

  @doc """
  BIP-340 Schnorr verify: verify a 64-byte signature against a 32-byte x-only
  public key and 32-byte message hash.

  Returns `:ok` if valid, `{:error, :invalid_signature}` otherwise.
  """
  @spec schnorr_verify(binary(), binary(), binary()) :: :ok | {:error, atom()}
  def schnorr_verify(xonly_pubkey, msg_hash, signature)
      when is_binary(xonly_pubkey) and byte_size(xonly_pubkey) == 32 and
             is_binary(msg_hash) and byte_size(msg_hash) == 32 and
             is_binary(signature) and byte_size(signature) == 64,
      do: :erlang.nif_error(:nif_not_loaded)

  def schnorr_verify(_, _, _), do: {:error, :invalid_input}

  @doc """
  Generate a NUT-12 DLEQ proof for a blind signature.

  Proves that C' = k * B' (the mint used its private key honestly)
  without revealing k. The proof {e, s} can be verified against the
  mint's public key K = k*G.

  Takes a 32-byte private key and 33-byte blinded message point B'.
  Returns `{:ok, {e, s}}` where e and s are 32-byte scalars.
  """
  @spec generate_dleq_proof(binary(), binary()) ::
          {:ok, {binary(), binary()}} | {:error, atom()}
  def generate_dleq_proof(privkey, b_prime)
      when is_binary(privkey) and byte_size(privkey) == 32 and
             is_binary(b_prime) and byte_size(b_prime) == 33,
      do: :erlang.nif_error(:nif_not_loaded)

  def generate_dleq_proof(_, _), do: {:error, :invalid_input}

  @doc """
  Verify a NUT-12 DLEQ proof on a blind signature.

  Verifies that {e, s} proves C' = k * B' where K is the mint's public key.

  Takes:
  - 33-byte compressed public key K
  - 33-byte blinded message B'
  - 33-byte blind signature C'
  - 32-byte challenge e
  - 32-byte response s

  Returns `:ok` or `{:error, :invalid_dleq_proof}`.
  """
  @spec verify_dleq_proof(binary(), binary(), binary(), binary(), binary()) ::
          :ok | {:error, atom()}
  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  def verify_dleq_proof(pubkey, b_prime, c_prime, e, s)
      when is_binary(pubkey) and byte_size(pubkey) == 33 and
             is_binary(b_prime) and byte_size(b_prime) == 33 and
             is_binary(c_prime) and byte_size(c_prime) == 33 and
             is_binary(e) and byte_size(e) == 32 and
             is_binary(s) and byte_size(s) == 32,
      do: :erlang.nif_error(:nif_not_loaded)

  def verify_dleq_proof(_, _, _, _, _), do: {:error, :invalid_input}

  @doc """
  Verifies that the NIF was loaded successfully at runtime.
  Raises if the NIF is not available.
  """
  @spec ensure_loaded!() :: :ok
  def ensure_loaded! do
    {:ok, _} = generate_keypair()
    :ok
  rescue
    e -> reraise "Cashew NIF not loaded: #{inspect(e)}", __STACKTRACE__
  end
end
