#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

extern crate alloc;

mod key;

use std::path::Path;
use rand::prelude::*;
use hmac::{Hmac, Mac};
use sm3::{Digest, Sm3};

pub use crate::key::{EncodeKey, MasterPrivateKey, MasterPublicKey, UserPrivateKey};
pub use pem_rfc7468::{LineEnding, PemLabel};
pub use sm9_core::{fast_pairing, Fr, Group, Gt, G1, G2};

// Create alias for HMAC-Sm3
type HmacSm3 = Hmac<Sm3>;

/// SM9 identity-based cryptographic
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Sm9;

impl Sm9 {
    // SM9 identity-based cryptographic algorithms
    // Part 4: Key encapsulation mechanism and public key encryption algorithm
    // 5.4 Auxiliary functions
    // 5.4.2.2 Cryptographic function H1() : generate h1 in [1, n-1]
    pub fn hash_1(id: &[u8], hid: u8) -> Option<Fr> {
        let ct = [0u8, 0, 0, 1];
        let mut v = vec![1u8];
        let mut ha = [0u8; 64];
        v.extend_from_slice(id);
        v.push(hid);
        v.extend_from_slice(ct.as_slice());

        let mut sm3 = Sm3::new();
        sm3.update(v.clone());
        let ha1 = sm3.finalize();
        ha[..32].copy_from_slice(&ha1[..]);

        let len = v.len();
        // ct++
        v[len - 1] += 1;
        let mut sm3 = Sm3::new();
        sm3.update(v);
        let ha2 = sm3.finalize();
        ha[32..].copy_from_slice(&ha2[..]);

        Fr::from_hash(&ha[..40])
    }
    // SM9 identity-based cryptographic algorithms
    // Part 3: Key exchange protocol
    // 5.4.3 Key derivation functions
    pub(crate) fn kdf(z: &[u8], mut klen: usize) -> Option<Vec<u8>> {
        if klen == 0 {
            return None;
        }
        // Step 1: Initialize a 32-bit counter 𝑐𝑡=0x00000001.
        let mut ct: u32 = 1;
        let mut u = Vec::<u8>::new();
        let mut v;
        let mut k = Vec::<u8>::new();
        u.extend_from_slice(z);
        // Step 2:For 𝑖=1 to ⌈𝑘𝑙𝑒𝑛/𝑣⌉:
        while klen > 0 {
            // Step 2.1: Compute 𝐻𝑎𝑖=𝐻𝑣(𝑍∥𝑐𝑡);
            v = u.clone();
            v.extend_from_slice(ct.to_be_bytes().as_ref());
            let mut sm3 = Sm3::new();
            sm3.update(v);
            let ha2 = sm3.finalize();
            // Step 3:
            let len = if klen > 32 { 32 } else { klen };
            // Step 4: Set 𝐾=𝐻𝑎1∥𝐻𝑎2∥...
            let hai = &ha2[..len];
            k.extend_from_slice(hai);
            klen -= len;
            // Step 2.2: 𝑐𝑡++;
            ct += 1;
        }
        Some(k)
    }
    pub fn generate_master_private_key_to_pem(path: impl AsRef<Path>) {
        // master encryption private key
        let rng = &mut thread_rng();
        let ke = Fr::random(rng);

        let binding = ke.to_slice();
        let master_private_key = MasterPrivateKey::new(&binding[..]);

        assert!(master_private_key
            .write_pem_file(path, MasterPrivateKey::PEM_LABEL, LineEnding::CRLF)
            .is_ok());
    }
    pub fn generate_master_public_key_to_pem(
        master_private_key_file: impl AsRef<Path>,
        master_public_key_file: impl AsRef<Path>,
    ) {
        let mpk = MasterPrivateKey::read_pem_file(master_private_key_file)
            .expect("read master_private_key_file error");
        mpk.generate_master_public_key_to_pem(master_public_key_file);
    }
    pub fn generate_user_private_key_to_pem(
        master_private_key_file: impl AsRef<Path>,
        user_id: &[u8],
        hid: u8,
        user_private_key_file: impl AsRef<Path>,
    ) {
        let mpk = MasterPrivateKey::read_pem_file(master_private_key_file)
            .expect("read master_private_key_file error");
        mpk.generate_user_private_key_to_pem(user_id, hid, user_private_key_file);
    }

    pub fn sm9_encrypt(
        master_public_key_file: impl AsRef<Path>,
        usr_id: &[u8],
        txt: &[u8],
    ) -> Vec<u8> {
        let mpk = MasterPublicKey::read_pem_file(master_public_key_file)
            .expect("read master_public_key_file error");
        mpk.encrypt(usr_id, txt)
    }
    pub fn sm9_decrypt(
        user_privte_key_file: impl AsRef<Path>,
        usr_id: &[u8],
        m: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let upk = UserPrivateKey::read_pem_file(user_privte_key_file)
            .expect("read user_privte_key_file error");
        upk.decrypt(usr_id, m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_hash1() {
        let id = b"Bob";
        let hid = 3u8;
        let a = Sm9::hash_1(id, hid).unwrap();
        let ex = hex!("9CB1F628 8CE0E510 43CE7234 4582FFC3 01E0A812 A7F5F200 4B85547A 24B82716");
        println!("{:?}", a);
        assert_eq!(a.to_slice(), ex);
    }
    #[test]
    fn test_kdf() {
        // SM9 identity-based cryptographic algorithms
        // Part 5: Parameter definition
        // Annex C: Example of key encapsulation mechanism
        let r0 = hex!(
            "1EDEE2C3 F4659144 91DE44CE FB2CB434 AB02C308 D9DC5E20 67B4FED5 AAAC8A0F"
            "1C9B4C43 5ECA35AB 83BB7341 74C0F78F DE81A533 74AFF3B3 602BBC5E 37BE9A4C"
            "8EAB0CD6 D0C95A6B BB7051AC 848FDFB9 689E5E5C 486B1294 557189B3 38B53B1D"
            "78082BB4 0152DC35 AC774442 CC6408FF D68494D9 953D77BF 55E30E84 697F6674"
            "5AAF5223 9E46B037 3B3168BA B75C32E0 48B5FAEB ABFA1F7F 9BA6B4C0 C90E65B0"
            "75F6A2D9 ED54C87C DDD2EAA7 87032320 205E7AC7 D7FEAA86 95AB2BF7 F5710861"
            "247C2034 CCF4A143 2DA1876D 023AD6D7 4FF1678F DA3AF37A 3D9F613C DE805798"
            "8B07151B AC93AF48 D78D86C2 6EA97F24 E2DACC84 104CCE87 91FE90BA 61B2049C"
            "AAC6AB38 EA07F996 6173FD9B BF34AAB5 8EE84CD3 777A9FD0 0BBCA1DC 09CF8696"
            "A1040465 BD723AE5 13C4BE3E F2CFDC08 8A935F0B 207DEED7 AAD5CE2F C37D4203"
            "4D874A4C E9B3B587 65B1252A 0880952B 4FF3C97E A1A4CFDC 67A0A007 2541A03D"
            "3924EABC 443B0503 510B93BB CD98EB70 E0192B82 1D14D69C CB2513A1 A7421EB7"
            "A018A035 E8FB61F2 71DE1C5B 3E781C63 508C113B 3EAC5378 05EAE164 D732FAD0"
            "56BEA27C 8624D506 4C9C278A 193D63F6 908EE558 DF5F5E07 21317FC6 E829C242 426F62"
        );
        let k = hex!("4FF5CF86 D2AD40C8 F4BAC98D 76ABDBDE 0C0E2F0A 829D3F91 1EF5B2BC E0695480");
        let d = Sm9::kdf(&r0, 32).unwrap();
        println!("{:02X?}", d);
        assert_eq!(k, d.as_slice())
    }
}
