use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use hkdf::Hkdf;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};
use std::convert::TryInto;

use crate::svr3::oprf::client::{blind, finalize};
use crate::svr3::ppss::gf256v32::polynomial::lagrange_interpolant;

use super::gf256v32::polynomial::Polynomial;
use super::gf256v32::ring_ops::RingElt;
use super::serversession::ServerSession;

type KeyShare = [u8; 33];
type Secret256 = [u8; 32];

pub fn create_keyshares<const THRESHOLD: usize, R: Rng + CryptoRng>(
    key: &Secret256,
    n: u8,
    rng: &mut R,
) -> Vec<KeyShare> {
    let mut poly = Polynomial::<THRESHOLD>::random(rng);
    poly.set_constant_coefficient(RingElt::bitslice(key));
    let mut result = Vec::<KeyShare>::new();
    for i in 1..=n {
        let share_elt = poly.eval(RingElt::repeated_field_elt(i));
        let x = [i];
        let share = [&x[..], &share_elt.unbitslice()].concat();
        result.push(share.try_into().unwrap());
    }
    result
}

pub fn combine_keyshares<const THRESHOLD: usize>(
    keyshares: &[[u8; 33]; THRESHOLD],
    all_xs: &[u8],
) -> (Secret256, Vec<KeyShare>) {
    assert!(
        THRESHOLD <= keyshares.len(),
        "Not enough keyshares to combine."
    );
    let mut xs = [RingElt::ZERO; THRESHOLD];
    let mut ys = [RingElt::ZERO; THRESHOLD];
    for i in 0..THRESHOLD {
        xs[i] = RingElt::repeated_field_elt(keyshares[i][0]);
        ys[i] = RingElt::bitslice(
            &keyshares[i][1..33]
                .try_into()
                .expect("keyshare is wrong length"),
        );
    }
    let poly = lagrange_interpolant(xs, ys);
    let secret = poly.constant_coefficient().unbitslice();
    let mut shares = Vec::<KeyShare>::with_capacity(all_xs.len());
    for i in 0..all_xs.len() {
        let x = RingElt::repeated_field_elt(all_xs[i]);
        let y = poly.eval(x);
        let share = [&all_xs[i..i + 1], &y.unbitslice()].concat();
        shares.push(share.try_into().expect("keyshare is wrong length"));
    }
    (secret, shares)
}

pub struct MaskedShareSet<const N: usize> {
    pub masked_shares: [[u8; 33]; N],
    pub commitment: [u8; 32],
}

pub struct PPSSSession<const N: usize, const THRESHOLD: usize> {
    servers: [ServerSession; N],
    context: &'static str,
    secret: [u8; 32],
    r: [u8; 32],
    key: [u8; 32],
}

/***
 * A session for N servers and a threshold of T. The protocol requires the set of N servers
 * to be the same at creation and reconstruction.
 */
impl<const N: usize, const T: usize> PPSSSession<N, T> {
    pub fn new(server_ids: &[[u8; 16]; N], context: &'static str) -> Self {
        let servers: [ServerSession; N] = server_ids.map(|id| ServerSession::new(id, context));
        Self {
            servers,
            context,
            secret: [0u8; 32],
            r: [0u8; 32],
            key: [0u8; 32],
        }
    }

    pub fn derive_key<R: Rng + CryptoRng>(
        &mut self,
        evaluated_element_bytes: &[[u8; 32]; N],
        password: &[u8],
        secret: &[u8; 32],
        rng: &mut R,
    ) -> (&[u8; 32], MaskedShareSet<N>) {
        self.secret.copy_from_slice(secret);
        self.finalize_oprf_responses(evaluated_element_bytes);
        self.compute_shares(secret, rng);
        self.derive_key_and_bits_from_secret();

        let commitment = self.compute_commitment(password);
        let mut masked_shares = [[0u8; 33]; N];
        for (masked_share, server) in std::iter::zip(masked_shares.iter_mut(), self.servers.iter())
        {
            masked_share.copy_from_slice(server.get_masked_share());
        }

        (
            &self.key,
            MaskedShareSet::<N> {
                commitment,
                masked_shares,
            },
        )
    }

    pub fn restore_key(
        &mut self,
        server_ids: &[[u8; 16]],
        oprf_responses: &[[u8; 32]],
        password: &[u8],
        masked_share_set: &MaskedShareSet<N>,
    ) -> [u8; 32] {
        self.set_masked_shares(&masked_share_set.masked_shares);
        self.finalize_oprf_responses_for_servers(server_ids, oprf_responses);
        self.reconstruct_secret(server_ids, &masked_share_set.masked_shares);

        self.derive_key_and_bits_from_secret(); // TODO: don't pass secret in here
        let com = self.compute_commitment(password);
        if com == masked_share_set.commitment {
            self.key
        } else {
            // TODO: error handling
            panic!("commitment didn't match")
        }
    }

    pub fn init(&mut self) {
        self.servers.sort();
    }

    pub fn get_blinded_elements(&mut self, password: &[u8]) -> [[u8; 32]; N] {
        let mut result = [[0u8; 32]; N];

        for (i, server) in self.servers.iter_mut().enumerate() {
            server.set_oprf_input(password);
            let (blind, blinded_elt) = blind(server.qualified_oprf_input()).unwrap();
            server.blind = blind;
            result[i].copy_from_slice(blinded_elt.compress().as_bytes());
        }

        result
    }

    pub fn get_blinded_elements_for_servers(
        &mut self,
        server_ids: &[[u8; 16]],
        password: &[u8],
    ) -> Vec<[u8; 32]> {
        let mut result = Vec::<[u8; 32]>::new();

        for server_id in server_ids.iter() {
            let server = &mut self.servers[self.server_index(server_id)];
            server.set_oprf_input(password);
            let (blind, blinded_elt) = blind(server.qualified_oprf_input()).unwrap();
            server.blind = blind;
            result.push(*blinded_elt.compress().as_bytes());
        }

        result
    }

    fn finalize_oprf_responses(&mut self, oprf_responses: &[[u8; 32]; N]) {
        // TODO: error handling
        let evaluated_elements = oprf_responses.map(|bytes| {
            CompressedRistretto::from_slice(&bytes)
                .expect("can create compressed ristretto")
                .decompress()
                .expect("can decompress")
        });
        for (server, evaluated_element) in
            std::iter::zip(self.servers.iter_mut(), evaluated_elements)
        {
            let oprf_input = server.qualified_oprf_input();
            let mask = finalize(oprf_input, &server.blind, &evaluated_element);
            server.set_mask(&mask[..33].try_into().unwrap());
        }
    }

    fn compute_shares<R: Rng + CryptoRng>(&mut self, secret: &[u8; 32], rng: &mut R) {
        let shares = create_keyshares::<T, R>(secret, N.try_into().unwrap(), rng);
        for (server, share) in std::iter::zip(self.servers.iter_mut(), shares) {
            server.set_share(&share);
        }
    }

    fn derive_key_and_bits_from_secret(&mut self) {
        let mut info = Vec::<u8>::new();
        info.extend_from_slice(self.context.as_bytes());
        info.extend_from_slice("keygen".as_bytes());
        let hk = Hkdf::<Sha256>::new(None, &self.secret);
        let mut r_and_k = [0u8; 64];
        hk.expand(info.as_slice(), &mut r_and_k)
            .expect("hkdf expand failed");
        self.r.copy_from_slice(&r_and_k[..32]);
        self.key.copy_from_slice(&r_and_k[32..]);
    }

    fn set_masked_shares(&mut self, masked_shares: &[[u8; 33]; N]) {
        for (server, masked_share) in std::iter::zip(self.servers.iter_mut(), masked_shares) {
            server.set_masked_share(masked_share);
        }
    }

    fn compute_commitment(&self, password: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher = hasher
            .chain_update(self.context.as_bytes())
            .chain_update("commitment".as_bytes())
            .chain_update(password);

        //add the masked shares
        for i in 0..N {
            hasher.update(self.servers[i].get_masked_share());
        }

        // add the secret shares
        for i in 0..N {
            assert_ne!(self.servers[i].get_share(), &[0u8; 33]);
            hasher.update(self.servers[i].get_share());
        }

        hasher.update(self.r);

        hasher.finalize().try_into().expect("Wrong hash length")
    }

    fn server_index(&self, server_id: &[u8; 16]) -> usize {
        for i in 0..N {
            if &self.servers[i].id == server_id {
                return i;
            }
        }
        usize::MAX
    }

    fn finalize_oprf_responses_for_servers(
        &mut self,
        server_ids: &[[u8; 16]],
        oprf_responses: &[[u8; 32]],
    ) {
        // TODO: error handling

        let evaluated_elements: Vec<RistrettoPoint> = oprf_responses
            .iter()
            .map(|bytes| {
                CompressedRistretto::from_slice(bytes)
                    .expect("can create compressed ristretto")
                    .decompress()
                    .expect("can decompress")
            })
            .collect();
        for i in 0..server_ids.len() {
            let server = &mut self.servers[self.server_index(&server_ids[i])];
            let oprf_input = server.qualified_oprf_input();
            let mask = finalize(oprf_input, &server.blind, &evaluated_elements[i]);
            server.set_mask(&mask[..33].try_into().unwrap());
        }
    }

    // Assumes that masks have been set for all servers in list
    fn reconstruct_secret(&mut self, server_ids: &[[u8; 16]], masked_shares: &[[u8; 33]; N]) {
        let mut keyshares = [[0u8; 33]; T];
        for (i, server_id) in server_ids.iter().enumerate() {
            let server_index = self.server_index(server_id);
            let server = &mut self.servers[server_index];
            server.set_masked_share(&masked_shares[server_index]);
            keyshares[i] = *server.get_share();
        }
        let all_xs: Vec<u8> = (1u8..=N as u8).collect();
        let (secret, shares) = combine_keyshares::<T>(&keyshares, all_xs.as_slice());
        self.secret.copy_from_slice(secret.as_slice());

        // Now set the shares on the servers that weren't called
        for (server, share) in std::iter::zip(self.servers.iter_mut(), shares) {
            server.set_share(&share);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use hex::encode;
    use hex_literal::hex;

    const CONTEXT: &str = "signal-svr3-ppss-test";

    fn oprf_eval(secret: &Scalar, blinded_elt: &RistrettoPoint) -> RistrettoPoint {
        secret * blinded_elt
    }

    fn oprf_eval_bytes(secret: &Scalar, blinded_elt_bytes: &[u8; 32]) -> [u8; 32] {
        let blinded_elt = CompressedRistretto::from_slice(blinded_elt_bytes)
            .expect("can create compressed ristretto")
            .decompress()
            .expect("can decompress");
        let eval_elt = oprf_eval(secret, &blinded_elt);
        eval_elt.compress().to_bytes()
    }

    fn test_secret(server_number: u8) -> Scalar {
        Scalar::from_bytes_mod_order_wide(&[server_number; 64])
    }

    #[test]
    fn server_sort() {
        let server_ids = [8u8, 4, 7, 2, 9, 1].map(|n| [n; 16]);
        assert_eq!(server_ids.len(), 6);
        assert_eq!(server_ids[0][0], 8);

        let mut ppss_session = PPSSSession::<6, 4>::new(&server_ids, CONTEXT);
        assert_eq!(ppss_session.servers[0].id[0], 8);

        ppss_session.init();
        assert_eq!(ppss_session.servers[0].id[0], 1);
        assert_eq!(ppss_session.servers[1].id[0], 2);
        assert_eq!(ppss_session.servers[2].id[0], 4);
        assert_eq!(ppss_session.servers[3].id[0], 7);
        assert_eq!(ppss_session.servers[4].id[0], 8);
        assert_eq!(ppss_session.servers[5].id[0], 9);
    }

    #[test]
    fn store_step_by_step() {
        let mut rng = rand_core::OsRng;

        // set up constants - secret, oprf secrets
        let secret = [42u8; 32];
        let password = "supahsecretpassword";
        let oprf_secrets: Vec<Scalar> = (0u8..6).map(test_secret).collect();

        // create a PPSSSession and initialize it
        let server_ids = [8u8, 4, 7, 2, 9, 1].map(|n| [n; 16]);
        let mut ppss_session = PPSSSession::<6, 4>::new(&server_ids, CONTEXT);
        ppss_session.init();

        // get the blinds

        let blinded_elt_bytes = ppss_session.get_blinded_elements(password.as_bytes());

        // eval the oprfs
        let eval_elt_bytes: Vec<[u8; 32]> = blinded_elt_bytes
            .iter()
            .zip(oprf_secrets.iter())
            .map(|(blinded_elt_bytes, oprf_secret)| oprf_eval_bytes(oprf_secret, blinded_elt_bytes))
            .collect();

        //finalize oprf responses (masks should be set)
        ppss_session.finalize_oprf_responses(eval_elt_bytes.as_slice().try_into().unwrap());
        for i in 0..6 {
            assert_ne!(ppss_session.servers[i].get_mask(), &[0u8; 33]);
        }

        // compute shares (shares should be set)
        ppss_session.compute_shares(&secret, &mut rng);
        for i in 0..6 {
            assert_ne!(ppss_session.servers[i].get_share(), &[0u8; 33]);
        }

        for i in 0..6 {
            let server = &ppss_session.servers[i];
            println!(
                "STORING SECRET:\n\tid: {:?}\n\tmask: {:?}\n\t share: {:?}",
                server.id,
                server.get_mask(),
                server.get_share()
            );
        }

        // derive key and bits from secret (key, r should be set)
        ppss_session.secret.copy_from_slice(&secret);
        ppss_session.derive_key_and_bits_from_secret();
        assert_ne!(ppss_session.key, [0u8; 32]);
        assert_ne!(ppss_session.r, [0u8; 32]);

        // compute commitment (doesn't set state, returns C)
        let commitment = ppss_session.compute_commitment(password.as_bytes());

        // record it
        println!("commitment: {}", encode(commitment));
        for i in 0..6 {
            println!("{}", encode(ppss_session.servers[i].get_masked_share()));
        }

        println!("key: {}", encode(ppss_session.key));
    }

    #[test]
    fn store_produces_correct_key() {
        let mut rng = rand_core::OsRng;
        let expected_key = hex!("8a09d11874e784346e5c6c3926005cfe7ba161c66f8a057f65cb589f8a7edb70");

        // begin as in the step-by-step test

        // set up constants - secret, oprf secrets
        let secret = [42u8; 32];
        let password = "supahsecretpassword";
        let oprf_secrets: Vec<Scalar> = (0u8..6).map(test_secret).collect();

        // create a PPSSSession and initialize it
        let server_ids = [8u8, 4, 7, 2, 9, 1].map(|n| [n; 16]);
        let mut ppss_session = PPSSSession::<6, 4>::new(&server_ids, CONTEXT);
        ppss_session.init();

        // get the blinds

        let blinded_elt_bytes = ppss_session.get_blinded_elements(password.as_bytes());

        // eval the oprfs
        let eval_elt_bytes: Vec<[u8; 32]> = blinded_elt_bytes
            .iter()
            .zip(oprf_secrets.iter())
            .map(|(blinded_elt_bytes, oprf_secret)| oprf_eval_bytes(oprf_secret, blinded_elt_bytes))
            .collect();

        let (key, _shareset) = ppss_session.derive_key(
            eval_elt_bytes.as_slice().try_into().unwrap(),
            password.as_bytes(),
            &secret,
            &mut rng,
        );
        assert_eq!(key, &expected_key);
    }

    #[test]
    fn reconstruct_step_by_step() {
        let expected_commitment =
            hex!("b5fcac15a50bb4d42884f638f02bbf449f552b204353f9bc70b7216485d578d4");
        let masked_shares = [
            hex!("73aebf101b0b320b39010bcd4c4bd25002b2b783b702a191d25ec367e93de18a5b"),
            hex!("fa4d6b1551b11fc7e3e9456e27ce8c094b314ffe0ec5f6d360480350894107813c"),
            hex!("9dc6c878cc4f3048ea1eec8e6d1be3c60401ab883bfae2ac6a181c55fdb748e7e3"),
            hex!("f07d637a5d1e4f32ac77586d7c87b22f161cbfe3bddbed8b6c41910b18c98a5720"),
            hex!("79345bc1e80509ec1b1277e60fd29202af11a7e5b409863a5bff426684d02e23cf"),
            hex!("ad499536a2cf06899bca9ebc7512b93a8cffa5dfd9287d743bb78814fa4fb177da"),
        ];
        let expected_key = hex!("8a09d11874e784346e5c6c3926005cfe7ba161c66f8a057f65cb589f8a7edb70");

        // begin as in the step-by-step test

        // set up constants - secret, oprf secrets
        let expected_secret = [42u8; 32];
        let password = "supahsecretpassword";
        let oprf_secrets: Vec<Scalar> = (0u8..6).map(test_secret).collect();

        // create a PPSSSession and initialize it
        let server_ids = [1u8, 2, 4, 7, 8, 9].map(|n| [n; 16]);
        let mut ppss_session = PPSSSession::<6, 4>::new(&server_ids, CONTEXT);
        ppss_session.init();

        // choose a reconstruction subset
        let reconstruction_indices = [1, 3, 4, 5];
        let reconstruction_ids = reconstruction_indices.map(|i| server_ids[i]);
        let reconstruction_oprf_secrets = reconstruction_indices.map(|i| oprf_secrets[i]);

        // get the blinds

        let blinded_elt_bytes =
            ppss_session.get_blinded_elements_for_servers(&reconstruction_ids, password.as_bytes());

        // eval the oprfs
        let eval_elt_bytes: Vec<[u8; 32]> = blinded_elt_bytes
            .iter()
            .zip(reconstruction_oprf_secrets.iter())
            .map(|(bytes, oprf_secret)| oprf_eval_bytes(oprf_secret, bytes))
            .collect();

        ppss_session
            .finalize_oprf_responses_for_servers(&reconstruction_ids, eval_elt_bytes.as_slice());

        ppss_session.set_masked_shares(&masked_shares);
        ppss_session.reconstruct_secret(&reconstruction_ids, &masked_shares);
        ppss_session.derive_key_and_bits_from_secret();
        let commitment = ppss_session.compute_commitment(password.as_bytes());

        assert_eq!(ppss_session.secret, expected_secret);
        assert_eq!(ppss_session.key, expected_key);
        assert_eq!(commitment, expected_commitment);
    }

    #[test]
    fn reconstruct() {
        let expected_commitment =
            hex!("b5fcac15a50bb4d42884f638f02bbf449f552b204353f9bc70b7216485d578d4");
        let masked_shares = [
            hex!("73aebf101b0b320b39010bcd4c4bd25002b2b783b702a191d25ec367e93de18a5b"),
            hex!("fa4d6b1551b11fc7e3e9456e27ce8c094b314ffe0ec5f6d360480350894107813c"),
            hex!("9dc6c878cc4f3048ea1eec8e6d1be3c60401ab883bfae2ac6a181c55fdb748e7e3"),
            hex!("f07d637a5d1e4f32ac77586d7c87b22f161cbfe3bddbed8b6c41910b18c98a5720"),
            hex!("79345bc1e80509ec1b1277e60fd29202af11a7e5b409863a5bff426684d02e23cf"),
            hex!("ad499536a2cf06899bca9ebc7512b93a8cffa5dfd9287d743bb78814fa4fb177da"),
        ];
        let masked_share_set = MaskedShareSet::<6> {
            commitment: expected_commitment,
            masked_shares,
        };
        let expected_key = hex!("8a09d11874e784346e5c6c3926005cfe7ba161c66f8a057f65cb589f8a7edb70");

        // begin as in the step-by-step test

        // set up constants - secret, oprf secrets
        let expected_secret = [42u8; 32];
        let password = "supahsecretpassword";
        let oprf_secrets: Vec<Scalar> = (0u8..6).map(test_secret).collect();

        // create a PPSSSession and initialize it
        let server_ids = [1u8, 2, 4, 7, 8, 9].map(|n| [n; 16]);
        let mut ppss_session = PPSSSession::<6, 4>::new(&server_ids, CONTEXT);
        ppss_session.init();

        // choose a reconstruction subset
        let reconstruction_indices = [1, 3, 4, 5];
        let reconstruction_ids = reconstruction_indices.map(|i| server_ids[i]);
        let reconstruction_oprf_secrets = reconstruction_indices.map(|i| oprf_secrets[i]);

        // get the blinds

        let blinded_elt_bytes =
            ppss_session.get_blinded_elements_for_servers(&reconstruction_ids, password.as_bytes());

        // eval the oprfs
        let eval_elt_bytes: Vec<[u8; 32]> = blinded_elt_bytes
            .iter()
            .zip(reconstruction_oprf_secrets.iter())
            .map(|(bytes, oprf_secret)| oprf_eval_bytes(oprf_secret, bytes))
            .collect();

        ppss_session.restore_key(
            &reconstruction_ids,
            eval_elt_bytes.as_slice(),
            password.as_bytes(),
            &masked_share_set,
        );
        assert_eq!(ppss_session.key, expected_key);
        assert_eq!(ppss_session.secret, expected_secret);
    }
}
