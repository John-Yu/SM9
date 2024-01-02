#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod encapsulating;
mod key;
mod signing;
mod verifying;

use hmac::{Hmac, Mac};
use rand::prelude::*;
use sec1::der::pem::{LineEnding, PemLabel};
use signature::{Signer, Verifier};
use sm3::{Digest, Sm3};
use std::path::Path;

use crate::key::{MasterPrivateKey, MasterSignaturePublicKey, UserSignaturePrivateKey};
use crate::signing::SigningKey;
use crate::verifying::VerifyingKey;

pub use crate::encapsulating::Sm9EncappedKey;
pub use crate::key::{EncodeKey, MasterPublicKey, UserPrivateKey};
pub use kem::{Decapsulator, EncappedKey, Encapsulator};
/// Fn is a prime field with n elements
/// where n is the order of the cyclic groups 𝔾1, 𝔾2 and 𝔾t
pub use sm9_core::Fr as Fn;

const SM9_HID_SIGN: u8 = 1;
const SM9_HID_ENC: u8 = 3;

// Create alias for HMAC-Sm3
type HmacSm3 = Hmac<Sm3>;

#[derive(Copy, Clone, Eq, PartialEq)]
/// SM9 Signature.
pub struct Signature(
    // (h, s)
    pub(crate) [u8; 32 + 65],
);
impl Signature {
    pub fn new(h: &[u8], s: &[u8]) -> Option<Signature> {
        if h.len() != 32 || s.len() != 65 {
            None
        } else {
            let mut sig = Signature([0u8; 32 + 65]);
            sig.0[..32].copy_from_slice(h);
            sig.0[32..].copy_from_slice(s);
            Some(sig)
        }
    }
    pub fn h_as_ref(&self) -> &[u8] {
        self.0[..32].as_ref()
    }
    pub fn s_as_ref(&self) -> &[u8] {
        self.0[32..].as_ref()
    }
}
impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
/// SM9 identity-based cryptographic
pub struct Sm9;

impl Sm9 {
    // SM9 identity-based cryptographic algorithms
    // Part 4: Key encapsulation mechanism and public key encryption algorithm
    // 5.4 Auxiliary functions
    // 5.4.2.2 Cryptographic function H1() : generate h1 in [1, n-1]
    pub(crate) fn hash_1(z: &[u8]) -> Option<Fn> {
        Self::hash(1u8, z)
    }
    // 5.4.2.3 Cryptographic function H2() : generate h2 in [1, n-1]
    pub(crate) fn hash_2(z: &[u8]) -> Option<Fn> {
        Self::hash(2u8, z)
    }
    fn hash(num: u8, z: &[u8]) -> Option<Fn> {
        let ct = [0u8, 0, 0, 1];
        let mut v = vec![num];
        let mut ha = [0u8; 64];
        // Step 3.1: Compute Hai = SM3(num||Z||ct);
        v.extend_from_slice(z);
        v.extend_from_slice(ct.as_slice());

        let mut sm3 = Sm3::new();
        sm3.update(v.clone());
        let ha1 = sm3.finalize();
        ha[..32].copy_from_slice(ha1.as_slice());

        // Step 3.2: ct++
        if let Some(last) = v.last_mut() {
            *last += 1;
        }
        let mut sm3 = Sm3::new();
        sm3.update(v);
        let ha2 = sm3.finalize();
        ha[32..].copy_from_slice(ha2.as_slice());

        Fn::from_hash(&ha[..40])
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
        let mut k = Vec::<u8>::new();
        u.extend_from_slice(z);
        // Step 2:For 𝑖=1 to ⌈𝑘𝑙𝑒𝑛/𝑣⌉:
        while klen > 0 {
            // Step 2.1: Compute 𝐻𝑎𝑖=𝐻𝑣(𝑍∥𝑐𝑡);
            let mut v = u.clone();
            v.extend_from_slice(ct.to_be_bytes().as_ref());
            let mut sm3 = Sm3::new();
            sm3.update(v);
            let ha2 = sm3.finalize();
            // Step 2.2: 𝑐𝑡++;
            ct += 1;
            // Step 3:
            let len = if klen > 32 { 32 } else { klen };
            // Step 4: Set 𝐾=𝐻𝑎1∥𝐻𝑎2∥...
            let hai = &ha2[..len];
            k.extend_from_slice(hai);
            klen -= len;
        }
        Some(k)
    }
    /// generate_master_private_key_to_pem file
    pub fn generate_master_private_key_to_pem(ke: &Fn, path: impl AsRef<Path>) {
        let binding = ke.to_slice();
        let master_private_key = MasterPrivateKey::new(binding.as_ref());

        assert!(master_private_key
            .write_pem_file(path, MasterPrivateKey::PEM_LABEL, LineEnding::CRLF)
            .is_ok());
    }
    /// generate_random_master_private_key_to_pem file
    pub fn generate_random_master_private_key_to_pem(path: impl AsRef<Path>) {
        // master encryption private key
        let rng = &mut thread_rng();
        let ke = Fn::random(rng);
        Self::generate_master_private_key_to_pem(&ke, path);
    }
    /// generate_master_public_key_to_pem file
    pub fn generate_master_public_key_to_pem(
        master_private_key_file: impl AsRef<Path>,
        master_public_key_file: impl AsRef<Path>,
    ) {
        let mpk = MasterPrivateKey::read_pem_file(master_private_key_file)
            .expect("read master_private_key_file error");
        mpk.generate_master_public_key_to_pem(master_public_key_file);
    }
    /// generate_user_private_key_to_pem file
    pub fn generate_user_private_key_to_pem(
        master_private_key_file: impl AsRef<Path>,
        user_id: &[u8],
        user_private_key_file: impl AsRef<Path>,
    ) {
        let mpk = MasterPrivateKey::read_pem_file(master_private_key_file)
            .expect("read master_private_key_file error");
        mpk.generate_user_private_key_to_pem(user_id, user_private_key_file);
    }
    //------------------------------------------------------------------------------
    /// generate_master_signature_public_key_to_pem file
    pub fn generate_master_signature_public_key_to_pem(
        master_signature_private_key_file: impl AsRef<Path>,
        master_signature_public_key_file: impl AsRef<Path>,
    ) {
        let mpk = MasterPrivateKey::read_pem_file(master_signature_private_key_file)
            .expect("read master_private_key_file error");
        mpk.generate_master_signature_public_key_to_pem(master_signature_public_key_file);
    }
    /// generate_user_signature_private_key_to_pem file
    pub fn generate_user_signature_private_key_to_pem(
        master_signature_private_key_file: impl AsRef<Path>,
        user_id: &[u8],
        user_signature_private_key_file: impl AsRef<Path>,
    ) {
        let mpk = MasterPrivateKey::read_pem_file(master_signature_private_key_file)
            .expect("read master_signature_private_key_file error");
        mpk.generate_user_signature_private_key_to_pem(user_id, user_signature_private_key_file);
    }
    /// encrypt, difined in "SM9 identity-based cryptographic algorithms"
    /// Part 4: Key encapsulation mechanism and public key encryption algorithm
    /// 7.1.1 Encryption algorithm
    pub fn encrypt(master_public_key_file: impl AsRef<Path>, usr_id: &[u8], txt: &[u8]) -> Vec<u8> {
        let mpk = MasterPublicKey::read_pem_file(master_public_key_file)
            .expect("read master_public_key_file error");
        assert!(mpk.is_ok());
        mpk.encrypt(usr_id, txt)
    }
    /// decrypt, difined in "SM9 identity-based cryptographic algorithms"
    /// Part 4: Key encapsulation mechanism and public key encryption algorithm
    /// 7.2.1 Decryption algorithm
    pub fn decrypt(
        user_privte_key_file: impl AsRef<Path>,
        usr_id: &[u8],
        m: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let upk = UserPrivateKey::read_pem_file(user_privte_key_file)
            .expect("read user_privte_key_file error");
        assert!(upk.is_ok());
        upk.decrypt(usr_id, m)
    }
    /// sign, difined in "SM9 identity-based cryptographic algorithms"
    /// Part 2: Digital signature algorithm
    /// 6.1 Digital signature generation algorithm
    pub fn sign(
        master_signature_public_key_file: impl AsRef<Path>,
        user_signature_privte_key_file: impl AsRef<Path>,
        m: &[u8],
    ) -> Signature {
        let uspk = UserSignaturePrivateKey::read_pem_file(user_signature_privte_key_file)
            .expect("read UserSignaturePrivateKey error");
        assert!(uspk.is_ok());
        let mspk = MasterSignaturePublicKey::read_pem_file(master_signature_public_key_file)
            .expect("MasterSignaturePublicKey read_pem_file error!");
        assert!(mspk.is_ok());
        let sign_key = SigningKey::new(&uspk, &mspk).unwrap();
        sign_key.sign(m)
    }
    /// verify, difined in "SM9 identity-based cryptographic algorithms"
    /// Part 2: Digital signature algorithm
    /// 7.1 Digital signature verification algorithm
    pub fn verify(
        master_signature_public_key_file: impl AsRef<Path>,
        user_id: &[u8],
        m: &[u8],
        sig: &Signature,
    ) -> bool {
        let mspk = MasterSignaturePublicKey::read_pem_file(master_signature_public_key_file)
            .expect("MasterSignaturePublicKey read_pem_file error!");
        assert!(mspk.is_ok());
        let verify_key = VerifyingKey::new(user_id, &mspk).unwrap();
        verify_key.verify(m, sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use crate::encapsulating::Sm9EncappedKey;

    use super::*;
    use hex_literal::hex;
    use kem::{Decapsulator, EncappedKey, Encapsulator};
    use rand::rngs::OsRng;

    #[test]
    fn test_hash1() {
        let user_id = b"Bob";
        let hid = SM9_HID_ENC;
        let mut z = Vec::<u8>::new();
        z.extend_from_slice(user_id);
        z.push(hid);
        let a = Sm9::hash_1(z.as_slice()).unwrap();
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
    #[test]
    // test data follow "SM9 identity-based cryptographic algorithms"
    // Part 5: Parameter definition
    // Annex C: example of key encapsulation mechanism
    fn test_bob_privte_key_from_pem() {
        let a = UserPrivateKey::read_pem_file("bob_private_key.pem").unwrap();
        println!("{:02X?}", a);
        let de = a.to_g2().expect("UserPrivateKey error");
        let b = hex!(
            "94736ACD 2C8C8796 CC4785E9 38301A13 9A059D35 37B64141 40B2D31E ECF41683"
            "115BAE85 F5D8BC6C 3DBD9E53 42979ACC CF3C2F4F 28420B1C B4F8C0B5 9A19B158"
            "7AA5E475 70DA7600 CD760A0C F7BEAF71 C447F384 4753FE74 FA7BA92C A7D3B55F"
            "27538A62 E7F7BFB5 1DCE0870 4796D94C 9D56734F 119EA447 32B50E31 CDEB75C1"
        );
        println!("{:02X?}", de);
        assert_eq!(de.to_slice(), b);
    }
    #[test]
    // test data follow "SM9 identity-based cryptographic algorithms"
    // Part 5: Parameter definition
    // Annex C: example of key encapsulation mechanism
    fn test_master_public_key_from_pem() {
        let a = MasterPublicKey::read_pem_file("master_public_key.pem").unwrap();
        println!("{:02X?}", a);
        let pube = a.to_g1().expect("MasterPublicKey error");
        let b = hex!(
            "787ED7B8 A51F3AB8 4E0A6600 3F32DA5C 720B17EC A7137D39 ABC66E3C 80A892FF"
            "769DE617 91E5ADC4 B9FF85A3 1354900B 20287127 9A8C49DC 3F220F64 4C57A7B1"
        );
        assert_eq!(pube.to_slice(), b);
    }
    #[test]
    // test data follow "SM9 identity-based cryptographic algorithms"
    // Part 5: Parameter definition
    // Annex C: example of key encapsulation mechanism
    fn test_master_private_key_from_pem() {
        let a = MasterPrivateKey::read_pem_file("master_private_key.pem")
            .expect("MasterPrivateKey read_pem_file error!");
        println!("{:02X?}", a);
        assert_eq!(
            a.as_slice(),
            &hex!("0001EDEE 3778F441 F8DEA3D9 FA0ACC4E 07EE36C9 3F9A0861 8AF4AD85 CEDE1C22")
        )
    }
    #[test]
    // test data follow "SM9 identity-based cryptographic algorithms"
    // Part 5: Parameter definition
    // Annex A: Example of digital signature algorithm
    fn test_master_signature_private_key() {
        let a = MasterPrivateKey::read_pem_file("master_signature_private_key.pem")
            .expect("MasterPrivateKey read_pem_file error!");
        println!("{:02X?}", a);
        assert_eq!(
            a.as_slice(),
            &hex!("000130E7 8459D785 45CB54C5 87E02CF4 80CE0B66 340F319F 348A1D5B 1F2DC5F4")
        )
    }
    #[test]
    // test data follow "SM9 identity-based cryptographic algorithms"
    // Part 5: Parameter definition
    // Annex A: Example of digital signature algorithm
    fn test_master_signature_public_key() {
        let a = MasterSignaturePublicKey::read_pem_file("master_signature_public_key.pem")
            .expect("MasterSignaturePublicKey read_pem_file error!");
        println!("{:02X?}", a);
        let pub_s = a.to_g2().expect("MasterSignaturePublicKey error");
        let b = hex!(
            "9F64080B 3084F733 E48AFF4B 41B56501 1CE0711C 5E392CFB 0AB1B679 1B94C408"
            "29DBA116 152D1F78 6CE843ED 24A3B573 414D2177 386A92DD 8F14D656 96EA5E32"
            "69850938 ABEA0112 B57329F4 47E3A0CB AD3E2FDB 1A77F335 E89E1408 D0EF1C25"
            "41E00A53 DDA532DA 1A7CE027 B7A46F74 1006E85F 5CDFF073 0E75C05F B4E3216D"
        );
        println!("{:02X?}", pub_s);
        assert_eq!(pub_s.to_slice(), b);
    }
    #[test]
    // test data follow "SM9 identity-based cryptographic algorithms"
    // Part 5: Parameter definition
    // Annex A: Example of digital signature algorithm
    fn test_alice_signature_private_key() {
        let a = UserSignaturePrivateKey::read_pem_file("alice_signature_private_key.pem")
            .expect("UserSignaturePrivateKey read_pem_file error!");
        println!("{:02X?}", a);
        let pub_s = a.to_g1().expect("UserSignaturePrivateKey error");
        let b = hex!(
            "A5702F05 CF131530 5E2D6EB6 4B0DEB92 3DB1A0BC F0CAFF90 523AC875 4AA69820"
            "78559A84 4411F982 5C109F5E E3F52D72 0DD01785 392A727B B1556952 B2B013D3"
        );
        println!("{:02X?}", pub_s);
        assert_eq!(pub_s.to_slice(), b);
    }
    #[test]
    fn test_encapsulate_key() {
        let encapper = MasterPublicKey::read_pem_file("master_public_key.pem")
            .expect("read master_public_key_file error");
        let mut pk_recip: <Sm9EncappedKey as EncappedKey>::RecipientPublicKey = [0u8; 128].into();
        let usr_id = b"Bob";
        pk_recip[..3].copy_from_slice(usr_id);
        let mut rng = OsRng;
        let (ek, ss1) = encapper.try_encap(&mut rng, &pk_recip).unwrap();
        println!("Sm9EncappedKey:{:02X?}", ek.as_ref());
        println!("Sm9SharedSecret:{:02X?}", ss1.as_bytes());
        let mut z = Vec::<u8>::new();
        z.extend_from_slice(ek.as_ref());
        z.extend_from_slice(ss1.as_bytes());
        z.extend_from_slice(usr_id);
        let klen = 64;
        let _k1 = Sm9::kdf(z.as_ref(), klen).expect("klen maybe error");
        let (_k2, _) = encapper.key_encapsulation(usr_id, klen);
        // if both use same random for test, then they should be equal
        //assert_eq!(_k1, _k2);
        let upk = UserPrivateKey::read_pem_file("bob_private_key.pem")
            .expect("read user_privte_key_file error");
        assert!(upk.is_ok());
        let ss2 = upk.try_decap(&ek).unwrap();
        // the SharedSecret should be equal
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}
