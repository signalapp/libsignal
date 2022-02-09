//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::args::*;
use crate::errors::*;
use crate::proof::*;
use crate::scalar::*;
use crate::shoapi::ShoApi;
use crate::shohmacsha256::ShoHmacSha256;
use crate::simple_types::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use std::collections::HashMap;

// POKSHO implements the "Sigma protocol for arbitrary linear relations" described in section
// 19.5.3 of https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf
//
// We adopt the view that we are proving knowledge of the preimage of a group homomorphism
// from groups G1 -> G2, where elements in G1 are vectors of scalars and elements in G2 are vectors of
// Ristretto "points".  The homomomorphism can be viewed as a system of equations of the form:
//
// P = sP + sP + sP + ...
// P = sP + sP + sP + ...
// P = sP + sP + sP + ...
// ...
//
// Where s are any scalars and P are any points.  The left-hand side of these equations describes
// the element in G2 which is the image of the homomorphism, and the scalars form an element in G1
// which we are proving knowledge of (this preimage in G1 can be viewed as a vector if the system
// of equations is rewritten as matrix multiplication).
//
// We use the term "statement" for the above system of equations written with both points and
// scalars as variables.  For example, the statement for signatures is the single equation:
//
// A = a*G
//
// where "A" is the public key, "a" is the private key, and "G" is the base point.  The
// discrete-log equality statement used in VRFs could be written as:
//
// A = a*G
// B = a*H
//
// We use the term "witness" for a vector of scalars that satisfies a given statement and a given
// set of point assignments (equivalently: a witness is an element in G1 that is a preimage of the
// left-hand-side under the group homomorphism).  In the above cases, "a" is the witness.
//
// The zero-knowledge proof is a standard Fiat-Shamir Sigma/Schnorr proof of knowledge.  To
// implement Fiat-Shamir hashing we use the SHO/HMAC-SHA256 construct, which provides a stateful object
// which we can use to Absorb data, and then Squeeze out arbitrary-length output.  We use a SHO
// object not only to produce the Schnorr challenge, but also to produce the Schnorr nonce by
// hashing some caller-supplied random data, the witness, and the message.  This "synthetic nonce"
// strategy is intended to ensure that the nonce appears random to any attacker and that different
// Schnorr challenges will never be used with the same nonce.
//
// Below we describe the hash inputs to SHO/HMAC-SHA256:
//
//  L : bytes, label = "POKSHO_Ristretto_SHOHMACSHA256"
//  D : bytes, description of statement - see below
//  a : G1, witness scalars for statement
//  A : G2, point values for statement = homomorphism(a)
//  Z : bytes, random = 32 byes of randomness
//  M : bytes, message to be signed, if any
//  r : G1, Schnorr nonce
//  R : G2, Schnorr commitment = homomorphism(r)
//  h : integer, Schnorr challenge

//  sho = SHO(L)
//  sho.AbsorbAndRatchet(D || A)
//         sho2 = sho.Clone()
//         sho2.AbsorbAndRatchet(Z || a)
//         sho2.AbsorbAndRatchet(M)
//         r = sho2.Squeeze(64 * num_scalars)
//  sho.AbsorbAndRatchet(R || M)
//  h = Squeeze(64)
//
//  Description format (D)
//  ---
//  Ne : number of equations (1-255)
//  for i=1..Ne:
//    point_index : 0..255 (0 = base point)
//    Nt : number of terms (1-255)
//    for j=1..Nt:
//      scalar_index: 0-255
//      point_index: 0-255 (0 = base point)
//
//  Point values for statement (A) and commitment (R)
//  ---
//   for index=1..total number of points (excluding base point at index 0):
//     RistrettoPoint
//
//  Witness (a)
//  ---
//  for index=0..total number of scalars:
//   RistrettoScalar

use PokshoError::*;

type ScalarIndex = u8;
type PointIndex = u8;

struct Term {
    scalar: ScalarIndex,
    point: PointIndex,
}

struct Equation {
    lhs: PointIndex,
    rhs: Vec<Term>,
}

pub struct Statement {
    // We store the Schnorr ZKP equations using scalar and point indices
    // which are numbered from zero, and are assigned sequentially based
    // on the order in which the point or scalar appears in the equations
    // (except point index 0 is pre-assigned to "G", the Ristretto base point)
    //
    // We also store maps from string names -> indices, and vectors for
    // the reverse map.  The former map is used when adding new equations,
    // and the latter is used when instantiating these indices with
    // concrete values.
    equations: Vec<Equation>,
    scalar_map: HashMap<String, ScalarIndex>,
    scalar_vec: Vec<String>,
    point_map: HashMap<String, PointIndex>,
    point_vec: Vec<String>,
}

impl Statement {
    pub fn new() -> Self {
        let mut point_map = HashMap::new();
        point_map.insert("G".to_string(), 0); // G is base point
        let point_vec = vec!["G".to_string()];
        Statement {
            equations: Vec::new(),
            scalar_map: HashMap::new(),
            scalar_vec: Vec::new(),
            point_map,
            point_vec,
        }
    }

    // panics on invalid input
    pub fn add(&mut self, lhs_str: &str, rhs_pairs: &[(&str, &str)]) {
        if (lhs_str.is_empty())
            || (rhs_pairs.is_empty())
            || (rhs_pairs.len() > 255)
            || (self.equations.len() >= 255)
        {
            panic!("Unexpected input sizes to add");
        }
        let lhs = self
            .add_point(lhs_str.to_string())
            .expect("add_point succeeds");
        let mut rhs = Vec::<Term>::with_capacity(rhs_pairs.len());
        for pair in rhs_pairs {
            if pair.0.is_empty() || pair.1.is_empty() {
                panic!("Unexpected pair size");
            }
            let scalar = self
                .add_scalar(pair.0.to_string())
                .expect("add_scalar succeeds");
            let point = self
                .add_point(pair.1.to_string())
                .expect("add_point succeeds");
            rhs.push(Term { scalar, point });
        }
        self.equations.push(Equation { lhs, rhs });
    }

    pub fn prove(
        &self,
        scalar_args: &ScalarArgs,
        point_args: &PointArgs,
        message: &[u8],
        randomness: &[u8], // must be 32 bytes
    ) -> Result<Vec<u8>, PokshoError> {
        if randomness.len() != 32 {
            return Err(PokshoError::BadArgs);
        }
        let g1 = self.sort_scalars(scalar_args)?;
        let all_points = self.sort_points(point_args)?;

        // Absorb the protocol label L, description of statement D, and point values A
        let mut sho = ShoHmacSha256::new(b"POKSHO_Ristretto_SHOHMACSHA256"); // L
        sho.absorb(&self.to_bytes()); // D
        for point in &all_points {
            // A
            sho.absorb(&point.compress().to_bytes());
        }

        sho.ratchet(); // Ratchet

        // Random nonce
        // "Synthetic" nonce based on hashing randomness, witness (private scalars) and message
        let mut sho2 = sho.clone();
        sho2.absorb(randomness); // Z
        for scalar in &g1 {
            sho2.absorb(&scalar.to_bytes()); // a
        }
        sho2.ratchet(); // Ratchet
        sho2.absorb_and_ratchet(message); // M
        let blinding_scalar_bytes = sho2.squeeze_and_ratchet(g1.len() * 64);

        let mut nonce = self.g1_new();
        for i in 0..g1.len() {
            nonce.push(scalar_from_slice_wide(
                &blinding_scalar_bytes[i * 64..(i + 1) * 64],
            ))
        }

        // Commitment from nonce by applying homomorphism F: commitment = F(nonce)
        let commitment = self.homomorphism_with_subtraction(&nonce, &all_points, None);

        // Challenge from commitment and message
        for point in &commitment {
            sho.absorb(&point.compress().to_bytes());
        }
        sho.absorb_and_ratchet(message);
        let challenge = scalar_from_slice_wide(&sho.squeeze_and_ratchet(64));

        // Response
        let mut response = self.g1_new();
        for i in 0..g1.len() {
            response.push(nonce[i] + (g1[i] * challenge));
        }

        let proof = Proof {
            challenge,
            response,
        };

        // Verify before returning, since a bad proof could indicate
        // a glitched/faulty response that leaks private keys, or incorrect inputs
        let proof_bytes = proof.to_bytes();
        match self.verify_proof(&proof_bytes, point_args, message) {
            Err(VerificationFailure) => Err(ProofCreationVerificationFailure),
            Err(e) => Err(e),
            Ok(_) => Ok(proof_bytes),
        }
    }

    pub fn verify_proof(
        &self,
        proof_bytes: &[u8],
        point_args: &PointArgs,
        message: &[u8],
    ) -> Result<(), PokshoError> {
        let proof = Proof::from_slice(proof_bytes).ok_or(VerificationFailure)?;
        if proof.response.len() != self.scalar_vec.len() {
            return Err(VerificationFailure);
        }
        let all_points = self.sort_points(point_args)?;

        // Absorb the protocol label L, statement description D, and point values A
        let mut sho = ShoHmacSha256::new(b"POKSHO_Ristretto_SHOHMACSHA256"); // L
        sho.absorb(&self.to_bytes()); // D
        for point in &all_points {
            // A
            sho.absorb(&point.compress().to_bytes());
        }
        sho.ratchet();

        // Reconstruct commitment
        //
        // commitment R = F(s) - h*A
        //
        // F: homomorphism
        // s: response element in G1
        // h: challenge scalar
        // A: element in G2 whose preimage we are proving knowledge of (i.e. LHS of Schnorr eqns)
        let commitment =
            self.homomorphism_with_subtraction(&proof.response, &all_points, Some(proof.challenge));

        // Reconstruct challenge from commitment and message
        for point in &commitment {
            // R
            sho.absorb(&point.compress().to_bytes());
        }
        sho.absorb_and_ratchet(message); // M
        let challenge = scalar_from_slice_wide(&sho.squeeze_and_ratchet(64));

        // Check challenge (const time)
        if challenge == proof.challenge {
            Ok(())
        } else {
            Err(VerificationFailure)
        }
    }

    fn add_scalar(&mut self, scalar_name: String) -> Result<ScalarIndex, PokshoError> {
        match self.scalar_map.get(&scalar_name) {
            Some(index) => Ok(*index),
            None => {
                assert!(self.scalar_map.len() == self.scalar_vec.len());
                let new_index = self.scalar_map.len();
                if new_index > 255 {
                    return Err(BadArgs);
                }
                let new_index = new_index as u8;
                self.scalar_map.insert(scalar_name.clone(), new_index);
                self.scalar_vec.push(scalar_name.clone());
                Ok(new_index)
            }
        }
    }

    fn add_point(&mut self, point_name: String) -> Result<PointIndex, PokshoError> {
        match self.point_map.get(&point_name) {
            Some(index) => Ok(*index),
            None => {
                assert!(self.point_map.len() == self.point_vec.len());
                let new_index = self.point_map.len();
                if new_index > 255 {
                    return Err(BadArgs);
                }
                let new_index = new_index as u8;
                self.point_map.insert(point_name.clone(), new_index);
                self.point_vec.push(point_name.clone());
                Ok(new_index)
            }
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        assert!(
            self.equations.len() <= 255
                && self.scalar_map.len() <= 256
                && self.point_map.len() <= 256
        );
        let mut v = vec![self.equations.len() as u8];
        for Equation { lhs, rhs } in &self.equations {
            assert!(*lhs as usize <= self.point_map.len());
            assert!(rhs.len() <= 255);
            v.push(*lhs);
            v.push(rhs.len() as u8);
            for Term { scalar, point } in rhs {
                assert!((*scalar as usize) < self.scalar_map.len());
                assert!((*point as usize) < self.point_map.len());
                v.push(*scalar);
                v.push(*point);
            }
        }
        v
    }

    fn g1_new(&self) -> G1 {
        G1::with_capacity(self.scalar_vec.len())
    }

    fn g2_new(&self) -> G2 {
        G2::with_capacity(self.equations.len())
    }

    // Applies the homomorphism from G1 -> G2
    // If given a challenge h, also subtracts h*A for efficient recovery of
    // the Schnorr commitment
    fn homomorphism_with_subtraction(
        &self,
        g1: &[Scalar],
        all_points: &[RistrettoPoint],
        challenge: Option<Scalar>,
    ) -> G2 {
        let mut g2 = self.g2_new();
        for e in &self.equations {
            let scalar_iter = e
                .rhs
                .iter()
                .map(|Term { scalar, point: _ }| g1[*scalar as usize]);
            let point_iter = e
                .rhs
                .iter()
                .map(|Term { scalar: _, point }| all_points[*point as usize]);

            // Can this be done without a vector?
            let mut v_scalar = Vec::<Scalar>::with_capacity(1);
            let mut v_point = Vec::<RistrettoPoint>::with_capacity(1);
            if let Some(h) = challenge {
                v_scalar.push(-h);
                v_point.push(all_points[e.lhs as usize]);
            };

            let scalar_iter = scalar_iter.chain(v_scalar);
            let point_iter = point_iter.chain(v_point);

            // Could use vartime_multiscalar_mul in some cases, but in the
            // general case points might be secret (not just scalars!)
            g2.push(RistrettoPoint::multiscalar_mul(scalar_iter, point_iter));
        }
        g2
    }

    fn sort_scalars(&self, scalar_args: &ScalarArgs) -> Result<G1, PokshoError> {
        if scalar_args.0.len() != self.scalar_vec.len() {
            return Err(BadArgsWrongNumberOfScalarArgs);
        }
        let mut g1 = self.g1_new();
        for scalar_name in &self.scalar_vec {
            g1.push(
                *scalar_args
                    .0
                    .get(scalar_name)
                    .ok_or(BadArgsMissingScalarArg)?,
            );
        }
        Ok(g1)
    }

    fn sort_points(&self, point_args: &PointArgs) -> Result<Vec<RistrettoPoint>, PokshoError> {
        if point_args.0.len() != self.point_vec.len() - 1 {
            return Err(BadArgsWrongNumberOfPointArgs);
        }
        let mut all_points = vec![RISTRETTO_BASEPOINT_POINT];
        for point_name in &self.point_vec[1..] {
            all_points.push(*point_args.0.get(point_name).ok_or(BadArgsMissingPointArg)?);
        }
        Ok(all_points)
    }
}

impl Default for Statement {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_snake_case)]

    use super::*;

    #[test]
    fn test_statement_encoding() {
        let mut s = Statement::new();
        s.add("A", &[("a", "G")]);
        assert!(s.to_bytes() == vec![1, 1, 1, 0, 0]);

        let mut s = Statement::new();
        s.add("A", &[("a", "G")]);
        s.add("B", &[("a", "H")]);
        assert!(s.to_bytes() == vec![2, 1, 1, 0, 0, 2, 1, 0, 3]);

        let mut s = Statement::new();
        s.add("A", &[("a", "G"), ("b", "H")]);
        assert!(s.to_bytes() == vec![1, 1, 2, 0, 0, 1, 2]);
    }

    #[test]
    #[allow(
        clippy::needless_range_loop,
        clippy::redundant_clone,
        clippy::unwrap_used
    )]
    fn test_complex_statement() {
        let mut block32 = [0u8; 32];
        let mut block64a = [0u8; 64];
        let mut block64b = [0u8; 64];
        let mut block64c = [0u8; 64];
        let mut block64d = [0u8; 64];
        let mut block64h = [0u8; 64];
        let mut block64i = [0u8; 64];
        let block0 = [0u8; 0];
        for i in 0..32 {
            block32[i] = i as u8;
        }
        for i in 0..64 {
            block64a[i] = 10 + i as u8;
        }
        for i in 0..64 {
            block64b[i] = 20 + i as u8;
        }
        for i in 0..64 {
            block64c[i] = 30 + i as u8;
        }
        for i in 0..64 {
            block64d[i] = 40 + i as u8;
        }
        for i in 0..64 {
            block64h[i] = 50 + i as u8;
        }
        for i in 0..64 {
            block64i[i] = 60 + i as u8;
        }

        let randomness = block32;
        let message = block0;

        let scalar_bytes_a = block64a;
        let scalar_bytes_b = block64b;
        let scalar_bytes_c = block64c;
        let scalar_bytes_d = block64d;

        let scalar_bytes_h_point = block64h;
        let scalar_bytes_i_point = block64i;

        let a = Scalar::from_bytes_mod_order_wide(&scalar_bytes_a);
        let b = Scalar::from_bytes_mod_order_wide(&scalar_bytes_b);
        let c = Scalar::from_bytes_mod_order_wide(&scalar_bytes_c);
        let d = Scalar::from_bytes_mod_order_wide(&scalar_bytes_d);
        let H =
            Scalar::from_bytes_mod_order_wide(&scalar_bytes_h_point) * RISTRETTO_BASEPOINT_POINT;
        let I =
            Scalar::from_bytes_mod_order_wide(&scalar_bytes_i_point) * RISTRETTO_BASEPOINT_POINT;

        let A = a * RISTRETTO_BASEPOINT_POINT + b * H + c * I;
        let B = c * H + d * I;

        let mut st = Statement::new();
        st.add("A", &[("a", "G"), ("b", "H"), ("c", "I")]);
        st.add("B", &[("c", "H"), ("d", "I")]);
        assert!(st.to_bytes() == vec![2, 1, 3, 0, 0, 1, 2, 2, 3, 4, 2, 2, 2, 3, 3]);

        let mut scalar_args = ScalarArgs::new();
        scalar_args.add("a", a);
        scalar_args.add("b", b);
        scalar_args.add("c", c);
        scalar_args.add("d", d);
        let mut point_args = PointArgs::new();
        point_args.add("A", A);
        point_args.add("B", B);
        point_args.add("H", H);
        point_args.add("I", I);

        let mut scalar_args2 = scalar_args.clone();
        scalar_args2.add("abc", a);

        // Test bad args - extra scalar
        assert!(matches!(
            st.prove(&scalar_args2, &point_args, &message, &randomness),
            Err(PokshoError::BadArgsWrongNumberOfScalarArgs)
        ));

        // Good proof
        let mut proof = st
            .prove(&scalar_args, &point_args, &message, &randomness)
            .unwrap();
        st.verify_proof(&proof, &point_args, &message).unwrap();
        /*
        for b in proof.iter() {
            print!("0x{:02x}, ", b);
        }
        println!("");
        */
        assert!(
            proof
                == vec![
                    0x8e, 0xfc, 0x67, 0x6c, 0x33, 0xe6, 0xb2, 0xd0, 0x67, 0x0e, 0xd5, 0x46, 0x1a,
                    0x50, 0x7f, 0x6a, 0x4b, 0xc9, 0x15, 0x3e, 0x26, 0x1d, 0xb8, 0x0f, 0xa4, 0x38,
                    0xf3, 0xcd, 0x80, 0xa5, 0xc9, 0x09, 0xb1, 0x13, 0xcc, 0x0d, 0x79, 0x90, 0xad,
                    0x61, 0x6d, 0x0a, 0x2f, 0xc4, 0xb8, 0x31, 0xd0, 0x63, 0x57, 0xa5, 0xee, 0x5d,
                    0x36, 0xd4, 0x4b, 0x34, 0x27, 0xc7, 0x90, 0x10, 0x61, 0x18, 0x0c, 0x0f, 0xb1,
                    0x79, 0x8c, 0x51, 0x68, 0x0f, 0xe2, 0x1b, 0x9f, 0x98, 0xe9, 0x79, 0x55, 0xb1,
                    0x59, 0x7c, 0x49, 0x31, 0x47, 0x25, 0xc1, 0x54, 0x6a, 0x36, 0x93, 0x28, 0xcf,
                    0x54, 0xda, 0xae, 0x71, 0x0b, 0xfc, 0x4a, 0x99, 0x11, 0x42, 0x2a, 0xa7, 0x7e,
                    0xd6, 0xd7, 0x23, 0x1d, 0xe3, 0x00, 0x3b, 0xa5, 0xae, 0x9d, 0x9f, 0xd0, 0xc5,
                    0x3c, 0xed, 0x7a, 0xd7, 0x82, 0xe2, 0x9b, 0x04, 0x68, 0x4a, 0x07, 0x22, 0x1a,
                    0x6e, 0xf4, 0x7c, 0xe6, 0x1d, 0x81, 0x7f, 0x01, 0x11, 0x7c, 0xf5, 0x9d, 0xf6,
                    0x9a, 0xc3, 0x5b, 0x5b, 0xb5, 0x90, 0xf1, 0xf7, 0xb6, 0xd0, 0x29, 0x71, 0x7b,
                    0xc1, 0xa6, 0x25, 0x01,
                ]
        );

        // Test bad args - extra point
        let mut point_args2 = point_args.clone();
        point_args2.add("xyz", A);
        assert!(matches!(
            st.verify_proof(&proof, &point_args2, &message),
            Err(PokshoError::BadArgsWrongNumberOfPointArgs)
        ));

        // Test bad message
        assert!(matches!(
            st.verify_proof(&proof, &point_args, &block32),
            Err(VerificationFailure)
        ));

        // Test bad proof #1 - extra byte at end
        let mut proof2 = proof.clone();
        proof2.push(0);
        assert!(matches!(
            st.verify_proof(&proof2, &point_args, &message),
            Err(VerificationFailure)
        ));

        // Test bad proof #2 - last byte changed
        let prooflen = proof.len();
        proof[prooflen - 1] += 1;
        assert!(matches!(
            st.verify_proof(&proof, &point_args, &message),
            Err(VerificationFailure)
        ));

        // Test bad proof #3 - incorrect # of scalars (1 too few)
        let mut proof2 = proof.clone();
        proof2.truncate(proof2.len() - 32);
        assert!(matches!(
            st.verify_proof(&proof2, &point_args, &message),
            Err(VerificationFailure)
        ));

        // Test bad proof #3 - incorrect # of scalars (1 too few)
        let mut proof2 = proof.clone();
        proof2.truncate(proof2.len() - 32);
        assert!(matches!(
            st.verify_proof(&proof2, &point_args, &message),
            Err(VerificationFailure)
        ));
    }
}
