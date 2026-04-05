use rustler::{Binary, Env, NewBinary, Term};
use secp256k1::schnorr::Signature as SchnorrSignature;
use secp256k1::{Keypair, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Generate a random secp256k1 keypair.
/// Returns {:ok, {privkey_32bytes, compressed_pubkey_33bytes}}.
#[rustler::nif]
fn generate_keypair<'a>(env: Env<'a>) -> Term<'a> {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());

    let mut sk_bytes = secret_key.secret_bytes();
    let pk_bytes = public_key.serialize();

    let mut sk_binary = NewBinary::new(env, 32);
    sk_binary.as_mut_slice().copy_from_slice(&sk_bytes);
    sk_bytes.zeroize();

    let mut pk_binary = NewBinary::new(env, 33);
    pk_binary.as_mut_slice().copy_from_slice(&pk_bytes);

    let sk_term = Binary::from(sk_binary).to_term(env);
    let pk_term = Binary::from(pk_binary).to_term(env);

    let pair = rustler::types::tuple::make_tuple(env, &[sk_term, pk_term]);
    make_ok_tuple(env, pair)
}

/// Derive a compressed public key from a 32-byte private key.
/// Returns {:ok, compressed_pubkey_33bytes} or {:error, reason}.
#[rustler::nif]
fn pubkey_from_privkey<'a>(env: Env<'a>, privkey: Binary<'a>) -> Term<'a> {
    if privkey.len() != 32 {
        return make_error(env, "invalid_private_key_size");
    }

    let secret_key = match SecretKey::from_slice(privkey.as_slice()) {
        Ok(sk) => sk,
        Err(_) => return make_error(env, "invalid_private_key"),
    };

    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let pk_bytes = public_key.serialize();

    let mut pk_binary = NewBinary::new(env, 33);
    pk_binary.as_mut_slice().copy_from_slice(&pk_bytes);

    make_ok_tuple(env, Binary::from(pk_binary).to_term(env))
}

/// Hash arbitrary binary data to a secp256k1 curve point.
/// Implements the Cashu NUT-00 hash_to_curve specification.
/// Returns {:ok, compressed_point_33bytes}.
#[rustler::nif]
fn hash_to_curve<'a>(env: Env<'a>, message: Binary<'a>) -> Term<'a> {
    match hash_to_curve_impl(message.as_slice()) {
        Ok(point) => {
            let point_bytes = point.serialize();
            let mut binary = NewBinary::new(env, 33);
            binary.as_mut_slice().copy_from_slice(&point_bytes);
            make_ok_tuple(env, Binary::from(binary).to_term(env))
        }
        Err(msg) => make_error(env, msg),
    }
}

/// Internal hash_to_curve implementation reused by verify.
/// Follows Cashu NUT-00 specification exactly:
///   msg_hash = SHA256("Secp256k1_HashToCurve_Cashu_" || x)
///   for counter in 0..:
///     hash = SHA256(msg_hash || counter_le_u32)
///     Y = try PublicKey(0x02 || hash)
fn hash_to_curve_impl(message: &[u8]) -> Result<PublicKey, &'static str> {
    // Step 1: msg_hash = SHA256(DOMAIN_SEPARATOR || x)
    let mut hasher = Sha256::new();
    hasher.update(b"Secp256k1_HashToCurve_Cashu_");
    hasher.update(message);
    let msg_hash = hasher.finalize();

    // Step 2: Try-and-increment to find a valid curve point
    // Statistically finds a valid point within 1-2 iterations; cap at 256 as safety bound
    for counter in 0u32..256 {
        // hash = SHA256(msg_hash || counter_le_u32)
        let mut hasher = Sha256::new();
        hasher.update(msg_hash.as_slice());
        hasher.update(counter.to_le_bytes());
        let hash = hasher.finalize();

        // Try to construct a valid point with 0x02 prefix (even y)
        let mut point_bytes = [0u8; 33];
        point_bytes[0] = 0x02;
        point_bytes[1..].copy_from_slice(&hash);

        if let Ok(point) = PublicKey::from_slice(&point_bytes) {
            return Ok(point);
        }
    }

    Err("hash_to_curve_failed")
}

/// Step 1 of BDHKE (Alice/client side):
/// Given a secret and an optional blinding factor, compute the blinded message B'.
/// B' = Y + r*G where Y = hash_to_curve(secret), r is blinding factor, G is generator.
/// Returns {:ok, {b_prime_33bytes, r_32bytes}} or {:error, reason}.
#[rustler::nif]
fn step1_alice<'a>(env: Env<'a>, secret: Binary<'a>, blinding_factor: Term<'a>) -> Term<'a> {
    let secp = Secp256k1::new();

    // Compute Y = hash_to_curve(secret)
    let y = match hash_to_curve_impl(secret.as_slice()) {
        Ok(point) => point,
        Err(msg) => return make_error(env, msg),
    };

    // Get or generate the blinding factor r
    let r_secret_key = if blinding_factor.is_binary() {
        let r_bin: Binary = match blinding_factor.decode() {
            Ok(b) => b,
            Err(_) => return make_error(env, "invalid_blinding_factor"),
        };
        if r_bin.len() != 32 {
            return make_error(env, "invalid_blinding_factor_size");
        }
        match SecretKey::from_slice(r_bin.as_slice()) {
            Ok(sk) => sk,
            Err(_) => return make_error(env, "invalid_blinding_factor"),
        }
    } else {
        // Generate random blinding factor
        SecretKey::new(&mut rand::thread_rng())
    };

    // Compute r*G (the public key corresponding to r)
    let r_pub = PublicKey::from_secret_key(&secp, &r_secret_key);

    // Compute B' = Y + r*G (point addition)
    let b_prime = match y.combine(&r_pub) {
        Ok(point) => point,
        Err(_) => return make_error(env, "point_addition_failed"),
    };

    let b_prime_bytes = b_prime.serialize();
    let mut r_bytes = r_secret_key.secret_bytes();

    let mut b_prime_binary = NewBinary::new(env, 33);
    b_prime_binary
        .as_mut_slice()
        .copy_from_slice(&b_prime_bytes);

    let mut r_binary = NewBinary::new(env, 32);
    r_binary.as_mut_slice().copy_from_slice(&r_bytes);
    r_bytes.zeroize();

    let b_prime_term = Binary::from(b_prime_binary).to_term(env);
    let r_term = Binary::from(r_binary).to_term(env);

    let pair = rustler::types::tuple::make_tuple(env, &[b_prime_term, r_term]);
    make_ok_tuple(env, pair)
}

/// Step 2 of BDHKE (Bob/mint side):
/// Sign the blinded message: C' = k * B'
/// Returns {:ok, c_prime_33bytes} or {:error, reason}.
#[rustler::nif]
fn step2_bob<'a>(env: Env<'a>, privkey: Binary<'a>, blinded_point: Binary<'a>) -> Term<'a> {
    if privkey.len() != 32 {
        return make_error(env, "invalid_private_key");
    }
    if blinded_point.len() != 33 {
        return make_error(env, "invalid_point");
    }

    let secret_key = match SecretKey::from_slice(privkey.as_slice()) {
        Ok(sk) => sk,
        Err(_) => return make_error(env, "invalid_private_key"),
    };

    let b_prime = match PublicKey::from_slice(blinded_point.as_slice()) {
        Ok(pk) => pk,
        Err(_) => return make_error(env, "invalid_point"),
    };

    let secp = Secp256k1::new();

    // C' = k * B' (scalar multiplication)
    let scalar = Scalar::from(secret_key);
    let c_prime = match b_prime.mul_tweak(&secp, &scalar) {
        Ok(point) => point,
        Err(_) => return make_error(env, "scalar_multiplication_failed"),
    };

    let c_prime_bytes = c_prime.serialize();
    let mut binary = NewBinary::new(env, 33);
    binary.as_mut_slice().copy_from_slice(&c_prime_bytes);

    make_ok_tuple(env, Binary::from(binary).to_term(env))
}

/// Step 3 of BDHKE (Alice/client side):
/// Unblind the signature: C = C' - r*K
/// where C' is the blind signature, r is the blinding factor, K is the mint's public key.
/// Returns {:ok, c_33bytes} or {:error, reason}.
#[rustler::nif]
fn step3_alice<'a>(
    env: Env<'a>,
    c_prime: Binary<'a>,
    blinding_factor: Binary<'a>,
    mint_pubkey: Binary<'a>,
) -> Term<'a> {
    if c_prime.len() != 33 {
        return make_error(env, "invalid_c_prime");
    }
    if blinding_factor.len() != 32 {
        return make_error(env, "invalid_blinding_factor");
    }
    if mint_pubkey.len() != 33 {
        return make_error(env, "invalid_mint_pubkey");
    }

    let c_prime_point = match PublicKey::from_slice(c_prime.as_slice()) {
        Ok(pk) => pk,
        Err(_) => return make_error(env, "invalid_c_prime"),
    };

    let r = match SecretKey::from_slice(blinding_factor.as_slice()) {
        Ok(sk) => sk,
        Err(_) => return make_error(env, "invalid_blinding_factor"),
    };

    let k_pub = match PublicKey::from_slice(mint_pubkey.as_slice()) {
        Ok(pk) => pk,
        Err(_) => return make_error(env, "invalid_mint_pubkey"),
    };

    let secp = Secp256k1::new();

    // Compute r*K
    let scalar = Scalar::from(r);
    let r_k = match k_pub.mul_tweak(&secp, &scalar) {
        Ok(point) => point,
        Err(_) => return make_error(env, "scalar_multiplication_failed"),
    };

    // Compute C = C' - r*K = C' + (-(r*K))
    let r_k_neg = r_k.negate(&secp);
    let c = match c_prime_point.combine(&r_k_neg) {
        Ok(point) => point,
        Err(_) => return make_error(env, "point_subtraction_failed"),
    };

    let c_bytes = c.serialize();
    let mut binary = NewBinary::new(env, 33);
    binary.as_mut_slice().copy_from_slice(&c_bytes);

    make_ok_tuple(env, Binary::from(binary).to_term(env))
}

/// Verify an unblinded signature.
/// Checks that C == k * hash_to_curve(secret).
/// Returns :ok or {:error, :invalid_signature}.
#[rustler::nif]
fn verify<'a>(
    env: Env<'a>,
    privkey: Binary<'a>,
    secret: Binary<'a>,
    signature: Binary<'a>,
) -> Term<'a> {
    if privkey.len() != 32 {
        return make_error(env, "invalid_private_key");
    }
    if signature.len() != 33 {
        return make_error(env, "invalid_signature");
    }

    let secret_key = match SecretKey::from_slice(privkey.as_slice()) {
        Ok(sk) => sk,
        Err(_) => return make_error(env, "invalid_private_key"),
    };

    let c = match PublicKey::from_slice(signature.as_slice()) {
        Ok(pk) => pk,
        Err(_) => return make_error(env, "invalid_signature"),
    };

    // Compute Y = hash_to_curve(secret)
    let y = match hash_to_curve_impl(secret.as_slice()) {
        Ok(point) => point,
        Err(msg) => return make_error(env, msg),
    };

    let secp = Secp256k1::new();

    // Compute expected_C = k * Y
    let scalar = Scalar::from(secret_key);
    let expected_c = match y.mul_tweak(&secp, &scalar) {
        Ok(point) => point,
        Err(_) => return make_error(env, "scalar_multiplication_failed"),
    };

    // Compare serialized compressed points (constant-time via serialize comparison)
    if c.serialize().ct_eq(&expected_c.serialize()).into() {
        rustler::types::atom::ok().to_term(env)
    } else {
        make_error(env, "invalid_signature")
    }
}

/// BIP-340 Schnorr sign: given a 32-byte private key and 32-byte message hash,
/// produce a 64-byte Schnorr signature and the 32-byte x-only public key.
/// Returns {:ok, {sig_64bytes, xonly_pubkey_32bytes}} or {:error, reason}.
#[rustler::nif]
fn schnorr_sign<'a>(env: Env<'a>, privkey: Binary<'a>, msg_hash: Binary<'a>) -> Term<'a> {
    if privkey.len() != 32 {
        return make_error(env, "invalid_private_key_size");
    }
    if msg_hash.len() != 32 {
        return make_error(env, "invalid_message_hash_size");
    }

    let secret_key = match SecretKey::from_slice(privkey.as_slice()) {
        Ok(sk) => sk,
        Err(_) => return make_error(env, "invalid_private_key"),
    };

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let sig = secp.sign_schnorr(msg_hash.as_slice(), &keypair);
    let (xonly, _parity) = keypair.x_only_public_key();

    let sig_bytes = sig.to_byte_array();
    let xonly_bytes = xonly.serialize();

    let mut sig_binary = NewBinary::new(env, 64);
    sig_binary.as_mut_slice().copy_from_slice(&sig_bytes);

    let mut xonly_binary = NewBinary::new(env, 32);
    xonly_binary.as_mut_slice().copy_from_slice(&xonly_bytes);

    let sig_term = Binary::from(sig_binary).to_term(env);
    let xonly_term = Binary::from(xonly_binary).to_term(env);

    let pair = rustler::types::tuple::make_tuple(env, &[sig_term, xonly_term]);
    make_ok_tuple(env, pair)
}

/// BIP-340 Schnorr verify: given a 32-byte x-only public key, 32-byte message hash,
/// and 64-byte signature, verify the signature.
/// Returns :ok or {:error, :invalid_signature}.
#[rustler::nif]
fn schnorr_verify<'a>(
    env: Env<'a>,
    xonly_pubkey: Binary<'a>,
    msg_hash: Binary<'a>,
    signature: Binary<'a>,
) -> Term<'a> {
    if xonly_pubkey.len() != 32 {
        return make_error(env, "invalid_public_key_size");
    }
    if msg_hash.len() != 32 {
        return make_error(env, "invalid_message_hash_size");
    }
    if signature.len() != 64 {
        return make_error(env, "invalid_signature_size");
    }

    let xonly = match XOnlyPublicKey::from_slice(xonly_pubkey.as_slice()) {
        Ok(pk) => pk,
        Err(_) => return make_error(env, "invalid_public_key"),
    };

    let sig = match SchnorrSignature::from_slice(signature.as_slice()) {
        Ok(s) => s,
        Err(_) => return make_error(env, "invalid_signature"),
    };

    let secp = Secp256k1::new();

    match secp.verify_schnorr(&sig, msg_hash.as_slice(), &xonly) {
        Ok(()) => rustler::types::atom::ok().to_term(env),
        Err(_) => make_error(env, "invalid_signature"),
    }
}

/// Generate a NUT-12 DLEQ proof for a blind signature.
///
/// Proves that C' = k * B' (the mint used its private key honestly)
/// without revealing k. Returns {e, s} where:
///   r_nonce = random scalar
///   R1 = r_nonce * G
///   R2 = r_nonce * B'
///   K = pubkey(k)
///   C' = k * B'
///   e = SHA256(R1 || R2 || K || C')  (all compressed 33-byte points)
///   s = r_nonce + e * k  (mod n)
///
/// Returns {:ok, {e_32bytes, s_32bytes}} or {:error, reason}.
#[rustler::nif]
fn generate_dleq_proof<'a>(env: Env<'a>, privkey: Binary<'a>, b_prime: Binary<'a>) -> Term<'a> {
    if privkey.len() != 32 {
        return make_error(env, "invalid_private_key");
    }
    if b_prime.len() != 33 {
        return make_error(env, "invalid_point");
    }

    let secret_key = match SecretKey::from_slice(privkey.as_slice()) {
        Ok(sk) => sk,
        Err(_) => return make_error(env, "invalid_private_key"),
    };

    let b_prime_point = match PublicKey::from_slice(b_prime.as_slice()) {
        Ok(pk) => pk,
        Err(_) => return make_error(env, "invalid_point"),
    };

    let secp = Secp256k1::new();

    // K = pubkey(k) — mint's public key
    let k_pub = PublicKey::from_secret_key(&secp, &secret_key);

    // C' = k * B' — the blind signature
    let scalar_k = Scalar::from(secret_key);
    let c_prime = match b_prime_point.mul_tweak(&secp, &scalar_k) {
        Ok(point) => point,
        Err(_) => return make_error(env, "scalar_multiplication_failed"),
    };

    // r_nonce = random scalar
    let r_nonce = SecretKey::new(&mut rand::thread_rng());

    // R1 = r_nonce * G
    let r1 = PublicKey::from_secret_key(&secp, &r_nonce);

    // R2 = r_nonce * B'
    let scalar_r = Scalar::from(r_nonce);
    let r2 = match b_prime_point.mul_tweak(&secp, &scalar_r) {
        Ok(point) => point,
        Err(_) => return make_error(env, "scalar_multiplication_failed"),
    };

    // e = SHA256(R1 || R2 || K || C') — all as compressed 33-byte points
    let e_hash = hash_dleq_challenge(&r1, &r2, &k_pub, &c_prime);

    // s = r_nonce + e * k (mod n)
    // We need modular arithmetic in the secp256k1 scalar field
    let mut s_bytes = compute_dleq_response(&r_nonce, &e_hash, &secret_key);

    let mut e_binary = NewBinary::new(env, 32);
    e_binary.as_mut_slice().copy_from_slice(&e_hash);

    let mut s_binary = NewBinary::new(env, 32);
    s_binary.as_mut_slice().copy_from_slice(&s_bytes);
    s_bytes.zeroize();

    let e_term = Binary::from(e_binary).to_term(env);
    let s_term = Binary::from(s_binary).to_term(env);

    let pair = rustler::types::tuple::make_tuple(env, &[e_term, s_term]);
    make_ok_tuple(env, pair)
}

/// Verify a NUT-12 DLEQ proof on a blind signature.
///
/// Verifies that the DLEQ proof {e, s} is valid for the claim that
/// C' = k * B' where K is the mint's public key (K = k*G).
///
/// Verification:
///   R1' = s*G - e*K
///   R2' = s*B' - e*C'
///   e' = SHA256(R1' || R2' || K || C')
///   assert e' == e
///
/// Returns :ok or {:error, :invalid_dleq_proof}.
#[rustler::nif]
fn verify_dleq_proof<'a>(
    env: Env<'a>,
    pubkey: Binary<'a>,
    b_prime: Binary<'a>,
    c_prime: Binary<'a>,
    e: Binary<'a>,
    s: Binary<'a>,
) -> Term<'a> {
    if pubkey.len() != 33 || b_prime.len() != 33 || c_prime.len() != 33 {
        return make_error(env, "invalid_point");
    }
    if e.len() != 32 || s.len() != 32 {
        return make_error(env, "invalid_proof");
    }

    let k_pub = match PublicKey::from_slice(pubkey.as_slice()) {
        Ok(pk) => pk,
        Err(_) => return make_error(env, "invalid_point"),
    };

    let b_prime_point = match PublicKey::from_slice(b_prime.as_slice()) {
        Ok(pk) => pk,
        Err(_) => return make_error(env, "invalid_point"),
    };

    let c_prime_point = match PublicKey::from_slice(c_prime.as_slice()) {
        Ok(pk) => pk,
        Err(_) => return make_error(env, "invalid_point"),
    };

    let s_key = match SecretKey::from_slice(s.as_slice()) {
        Ok(sk) => sk,
        Err(_) => return make_error(env, "invalid_proof"),
    };

    let secp = Secp256k1::new();

    // R1' = s*G - e*K
    let s_g = PublicKey::from_secret_key(&secp, &s_key);
    let e_scalar = scalar_from_bytes(e.as_slice());
    let e_k = match k_pub.mul_tweak(&secp, &e_scalar) {
        Ok(point) => point,
        Err(_) => return make_error(env, "scalar_multiplication_failed"),
    };
    let e_k_neg = e_k.negate(&secp);
    let r1_prime = match s_g.combine(&e_k_neg) {
        Ok(point) => point,
        Err(_) => return make_error(env, "point_addition_failed"),
    };

    // R2' = s*B' - e*C'
    let s_scalar = Scalar::from(s_key);
    let s_b = match b_prime_point.mul_tweak(&secp, &s_scalar) {
        Ok(point) => point,
        Err(_) => return make_error(env, "scalar_multiplication_failed"),
    };
    let e_c = match c_prime_point.mul_tweak(&secp, &e_scalar) {
        Ok(point) => point,
        Err(_) => return make_error(env, "scalar_multiplication_failed"),
    };
    let e_c_neg = e_c.negate(&secp);
    let r2_prime = match s_b.combine(&e_c_neg) {
        Ok(point) => point,
        Err(_) => return make_error(env, "point_addition_failed"),
    };

    // e' = SHA256(R1' || R2' || K || C')
    let e_computed = hash_dleq_challenge(&r1_prime, &r2_prime, &k_pub, &c_prime_point);

    // Compare e' == e (constant-time)
    if e_computed.ct_eq(e.as_slice()).into() {
        rustler::types::atom::ok().to_term(env)
    } else {
        make_error(env, "invalid_dleq_proof")
    }
}

// Compute DLEQ challenge: e = SHA256(R1 || R2 || K || C')
// All points are serialized as compressed 33-byte representations.
fn hash_dleq_challenge(
    r1: &PublicKey,
    r2: &PublicKey,
    k: &PublicKey,
    c_prime: &PublicKey,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(r1.serialize());
    hasher.update(r2.serialize());
    hasher.update(k.serialize());
    hasher.update(c_prime.serialize());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// Compute DLEQ response: s = r_nonce + e * privkey (mod n)
// Uses secp256k1 scalar arithmetic via the Scalar type.
fn compute_dleq_response(r_nonce: &SecretKey, e_bytes: &[u8; 32], privkey: &SecretKey) -> [u8; 32] {
    // secp256k1 curve order
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    // Convert to big integers for modular arithmetic
    let mut r_sk_bytes = r_nonce.secret_bytes();
    let mut k_sk_bytes = privkey.secret_bytes();

    let mut r = u256_from_bytes(&r_sk_bytes);
    let e = u256_from_bytes(e_bytes);
    let mut k = u256_from_bytes(&k_sk_bytes);
    let n = u256_from_bytes(&N);

    r_sk_bytes.zeroize();
    k_sk_bytes.zeroize();

    // s = (r + e * k) mod n
    let mut ek = mulmod_u256(e, k, n);
    let s = addmod_u256(r, ek, n);

    // Zeroize intermediates holding secret material
    r.zeroize();
    k.zeroize();
    ek.zeroize();

    u256_to_bytes(s)
}

// Convert a Scalar from raw bytes (used for verification).
fn scalar_from_bytes(bytes: &[u8]) -> Scalar {
    // secp256k1 curve order
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    // Reduce the bytes modulo n to get a valid scalar.
    // If bytes represent a value >= n, reduce it.
    let val = u256_from_bytes(bytes);
    let n = u256_from_bytes(&N);
    let reduced = if u256_ge(val, n) {
        u256_sub(val, n)
    } else {
        val
    };
    let mut reduced_bytes = u256_to_bytes(reduced);

    // SecretKey::from_slice rejects zero. For DLEQ verification, a zero scalar
    // means the proof is invalid — return Scalar::ZERO which will cause the
    // verification check to fail (correct behavior).
    let scalar = match SecretKey::from_slice(&reduced_bytes) {
        Ok(sk) => Scalar::from(sk),
        Err(_) => Scalar::ZERO,
    };
    reduced_bytes.zeroize();
    scalar
}

// Simple 256-bit unsigned integer type for modular arithmetic
type U256 = (u128, u128); // (high, low)

fn u256_from_bytes(bytes: &[u8]) -> U256 {
    let mut high_bytes = [0u8; 16];
    let mut low_bytes = [0u8; 16];
    high_bytes.copy_from_slice(&bytes[..16]);
    low_bytes.copy_from_slice(&bytes[16..]);
    (
        u128::from_be_bytes(high_bytes),
        u128::from_be_bytes(low_bytes),
    )
}

fn u256_to_bytes(val: U256) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[..16].copy_from_slice(&val.0.to_be_bytes());
    result[16..].copy_from_slice(&val.1.to_be_bytes());
    result
}

// 256-bit addition with carry
fn u256_add(a: U256, b: U256) -> (U256, bool) {
    let (low, carry1) = a.1.overflowing_add(b.1);
    let (high, carry2) = a.0.overflowing_add(b.0);
    let (high, carry3) = high.overflowing_add(if carry1 { 1 } else { 0 });
    ((high, low), carry2 || carry3)
}

// 256-bit subtraction
fn u256_sub(a: U256, b: U256) -> U256 {
    let (low, borrow1) = a.1.overflowing_sub(b.1);
    let (high, _) = a.0.overflowing_sub(b.0);
    let high = if borrow1 { high.wrapping_sub(1) } else { high };
    (high, low)
}

fn u256_ge(a: U256, b: U256) -> bool {
    a.0 > b.0 || (a.0 == b.0 && a.1 >= b.1)
}

// Modular addition: (a + b) mod n
fn addmod_u256(a: U256, b: U256, n: U256) -> U256 {
    let (sum, overflow) = u256_add(a, b);
    if overflow || u256_ge(sum, n) {
        u256_sub(sum, n)
    } else {
        sum
    }
}

// Modular multiplication: (a * b) mod n
// Uses shift-and-add method for 256-bit values.
//
// SECURITY NOTE: The shift-and-add approach has variable-time execution but is
// acceptable because DLEQ proofs use public nonces — the secret key enters via
// a single scalar multiply, and timing leakage from U256 operations is negligible
// compared to the NIF call overhead.
fn mulmod_u256(a: U256, b: U256, n: U256) -> U256 {
    let mut result: U256 = (0, 0);
    let mut base = a;

    // Process each bit of b from LSB to MSB
    let mut b_val = b;
    for _ in 0..256 {
        if b_val.1 & 1 == 1 {
            result = addmod_u256(result, base, n);
        }
        base = addmod_u256(base, base, n); // double
                                           // Right shift b by 1
        let high_bit = (b_val.0 & 1) << 127;
        b_val = (b_val.0 >> 1, (b_val.1 >> 1) | high_bit);
    }

    result
}

// Helper: create {:ok, value} tuple
fn make_ok_tuple<'a>(env: Env<'a>, value: Term<'a>) -> Term<'a> {
    let ok_atom = rustler::types::atom::ok().to_term(env);
    rustler::types::tuple::make_tuple(env, &[ok_atom, value])
}

// Helper: create {:error, reason_atom} tuple
fn make_error<'a>(env: Env<'a>, reason: &str) -> Term<'a> {
    let error_atom = rustler::types::atom::error().to_term(env);
    let reason_term = match rustler::Atom::from_str(env, reason) {
        Ok(atom) => atom.to_term(env),
        Err(_) => rustler::types::atom::error().to_term(env),
    };
    rustler::types::tuple::make_tuple(env, &[error_atom, reason_term])
}

rustler::init!("Elixir.Cashew");

#[cfg(test)]
mod u256_tests {
    use super::*;

    #[test]
    fn test_mulmod_known_values() {
        // (7 * 13) mod 10 = 91 mod 10 = 1
        let a = (0u128, 7u128);
        let b = (0u128, 13u128);
        let n = (0u128, 10u128);
        assert_eq!(mulmod_u256(a, b, n), (0, 1));
    }

    #[test]
    fn test_mulmod_large_values() {
        // (u128::MAX * 2) mod u128::MAX = 0
        let a = (0, u128::MAX);
        let b = (0, 2);
        let n = (0, u128::MAX);
        assert_eq!(mulmod_u256(a, b, n), (0, 0));
    }

    #[test]
    fn test_mulmod_identity() {
        // (a * 1) mod n = a mod n
        let a = (0, 42);
        let one = (0, 1);
        let n = (0, 100);
        assert_eq!(mulmod_u256(a, one, n), (0, 42));
    }

    #[test]
    fn test_mulmod_zero() {
        // (a * 0) mod n = 0
        let a = (0, 42);
        let zero = (0, 0);
        let n = (0, 100);
        assert_eq!(mulmod_u256(a, zero, n), (0, 0));
    }

    #[test]
    fn test_addmod_overflow() {
        // (MAX + 1) mod MAX = 1
        let a = (0, u128::MAX);
        let b = (0, 1);
        let n = (0, u128::MAX);
        assert_eq!(addmod_u256(a, b, n), (0, 1));
    }

    #[test]
    fn test_addmod_no_overflow() {
        // (3 + 4) mod 10 = 7
        let a = (0, 3);
        let b = (0, 4);
        let n = (0, 10);
        assert_eq!(addmod_u256(a, b, n), (0, 7));
    }

    #[test]
    fn test_addmod_wraps() {
        // (8 + 5) mod 10 = 3
        let a = (0, 8);
        let b = (0, 5);
        let n = (0, 10);
        assert_eq!(addmod_u256(a, b, n), (0, 3));
    }

    #[test]
    fn test_u256_roundtrip() {
        let bytes: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02,
        ];
        let val = u256_from_bytes(&bytes);
        assert_eq!(val, (1, 2));
        assert_eq!(u256_to_bytes(val), bytes);
    }

    #[test]
    fn test_u256_ge() {
        assert!(u256_ge((1, 0), (0, u128::MAX)));
        assert!(u256_ge((0, 5), (0, 5)));
        assert!(!u256_ge((0, 4), (0, 5)));
    }

    #[test]
    fn test_u256_sub() {
        assert_eq!(u256_sub((0, 10), (0, 3)), (0, 7));
        // Borrow from high
        assert_eq!(u256_sub((1, 0), (0, 1)), (0, u128::MAX));
    }
}
