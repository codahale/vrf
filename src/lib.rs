use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use strobe_rs::{SecParam, Strobe};

// https://tools.ietf.org/id/draft-irtf-cfrg-vrf-08.html

const POINT_LEN: usize = 32;
const SCALAR_LEN: usize = 32;
const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;
pub const PROOF_LEN: usize = POINT_LEN + SCALAR_LEN + SCALAR_LEN;

/// Calculate a VRF proof for the given key pair and input.
pub fn prove(d: &Scalar, q: &RistrettoPoint, alpha: &[u8]) -> [u8; PROOF_LEN] {
    // Initialize the protocol.
    let mut vrf = Strobe::new(b"rando.vrf", SecParam::B128);

    // Add the public key as authenticated data.
    vrf.ad(q.compress().as_bytes(), false);

    // Send the input as cleartext.
    vrf.send_clr(alpha, false);

    // Extract a point.
    let h = RistrettoPoint::from_uniform_bytes(&prf_array(&mut vrf));

    // Calculate the proof point.
    let gamma = h * d;

    // Generate a random nonce and calculate the verification points.
    let k = {
        let mut clone = vrf.clone();
        clone.key(d.as_bytes(), false);

        let mut r = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut r);
        clone.key(&r, false);

        Scalar::from_bytes_mod_order_wide(&prf_array(&mut clone))
    };
    let u = G * &k;
    let v = h * k;

    // Include the proof point and verification points as authenticated data. Unlike ECVRF, we don't
    // need to include H here, as it is dependent on the protocol's previous state.
    vrf.ad(gamma.compress().as_bytes(), false);
    vrf.ad(u.compress().as_bytes(), false);
    vrf.ad(v.compress().as_bytes(), false);

    // Extract the challenge scalar and calculate the signature scalar.
    let c = Scalar::from_bytes_mod_order_wide(&prf_array(&mut vrf));
    let s = k - (c * d);

    // Encode the proof point, challenge scalar, and signature scalar.
    let mut proof = [0u8; PROOF_LEN];
    proof[..POINT_LEN].copy_from_slice(gamma.compress().as_bytes());
    proof[POINT_LEN..POINT_LEN + SCALAR_LEN].copy_from_slice(c.as_bytes());
    proof[POINT_LEN + SCALAR_LEN..].copy_from_slice(s.as_bytes());
    proof
}

/// Verify a VRF proof, given a key pair and VRF input.
pub fn verify(q: &RistrettoPoint, alpha: &[u8], proof: &[u8; PROOF_LEN]) -> bool {
    // Parse the proof.
    let (gamma, c, s) = match (
        CompressedRistretto::from_slice(&proof[..POINT_LEN]).decompress(),
        Scalar::from_canonical_bytes(
            proof[POINT_LEN..POINT_LEN + SCALAR_LEN].try_into().expect("invalid scalar len"),
        ),
        Scalar::from_canonical_bytes(
            proof[POINT_LEN + SCALAR_LEN..].try_into().expect("invalid scalar len"),
        ),
    ) {
        (Some(gamma), Some(c), Some(s)) => (gamma, c, s),
        _ => return false,
    };

    // Initialize the protocol.
    let mut vrf = Strobe::new(b"rando.vrf", SecParam::B128);

    // Add the public key as authenticated data.
    vrf.ad(q.compress().as_bytes(), false);

    // Receive the input as cleartext.
    vrf.recv_clr(alpha, false);

    // Extract a point.
    let h = RistrettoPoint::from_uniform_bytes(&prf_array(&mut vrf));

    // Calculate the verification points from the challenge and signature scalars.
    let u = (q * c) + (G * &s);
    let v = (gamma * c) + (h * s);

    // Include the proof point and verification points as authenticated data.
    vrf.ad(gamma.compress().as_bytes(), false);
    vrf.ad(u.compress().as_bytes(), false);
    vrf.ad(v.compress().as_bytes(), false);

    // Extract the challenge scalar from the protocol.
    let c_p = Scalar::from_bytes_mod_order_wide(&prf_array(&mut vrf));

    // Return true iff c' == c.
    c_p == c
}

/// Hash a VRF proof.
pub fn proof_to_hash<const HASH_LEN: usize>(proof: &[u8; PROOF_LEN]) -> [u8; HASH_LEN] {
    let mut vrf = Strobe::new(b"rando.vrf.proof", SecParam::B128);
    vrf.key(&proof[..POINT_LEN], false);
    prf_array(&mut vrf)
}

#[inline]
fn prf_array<const N: usize>(s: &mut Strobe) -> [u8; N] {
    let mut out = [0u8; N];
    s.prf(&mut out, false);
    out
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn vrf_proofs() {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = G * &d;
        let alpha = b"this is a secret";
        let proof = prove(&d, &q, alpha);

        assert!(verify(&q, alpha, &proof));
    }

    #[test]
    fn invalid_public_key() {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = G * &d;
        let alpha = b"this is a secret";
        let proof = prove(&d, &q, alpha);

        let q = RistrettoPoint::random(&mut rand::thread_rng());
        assert!(!verify(&q, alpha, &proof));
    }

    #[test]
    fn wrong_input() {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = G * &d;
        let alpha = b"this is a secret";
        let proof = prove(&d, &q, alpha);

        let alpha = b"wrong lever";
        assert!(!verify(&q, alpha, &proof));
    }

    #[test]
    fn wrong_gamma() {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = G * &d;
        let alpha = b"this is a secret";
        let mut proof = prove(&d, &q, alpha);

        let gamma = RistrettoPoint::random(&mut rand::thread_rng());
        proof[..POINT_LEN].copy_from_slice(gamma.compress().as_bytes());
        assert!(!verify(&q, alpha, &proof));
    }

    #[test]
    fn invalid_gamma() {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = G * &d;
        let alpha = b"this is a secret";
        let mut proof = prove(&d, &q, alpha);

        proof[..POINT_LEN].fill(0xFF);
        assert!(!verify(&q, alpha, &proof));
    }

    #[test]
    fn wrong_c() {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = G * &d;
        let alpha = b"this is a secret";
        let mut proof = prove(&d, &q, alpha);

        let c = Scalar::random(&mut rand::thread_rng());
        proof[POINT_LEN..POINT_LEN + SCALAR_LEN].copy_from_slice(c.as_bytes());
        assert!(!verify(&q, alpha, &proof));
    }

    #[test]
    fn invalid_c() {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = G * &d;
        let alpha = b"this is a secret";
        let mut proof = prove(&d, &q, alpha);

        proof[POINT_LEN..POINT_LEN + SCALAR_LEN].fill(0xFF);
        assert!(!verify(&q, alpha, &proof));
    }

    #[test]
    fn wrong_s() {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = G * &d;
        let alpha = b"this is a secret";
        let mut proof = prove(&d, &q, alpha);

        let s = Scalar::random(&mut rand::thread_rng());
        proof[POINT_LEN + SCALAR_LEN..].copy_from_slice(s.as_bytes());
        assert!(!verify(&q, alpha, &proof));
    }

    #[test]
    fn invalid_s() {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = G * &d;
        let alpha = b"this is a secret";
        let mut proof = prove(&d, &q, alpha);

        proof[POINT_LEN + SCALAR_LEN..].fill(0xFF);
        assert!(!verify(&q, alpha, &proof));
    }
}
