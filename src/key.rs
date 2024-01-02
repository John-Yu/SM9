//use hex_literal::hex;
use sec1::{
    consts::U32,
    der::{
        self,
        asn1::OctetStringRef,
        pem::{LineEnding, PemLabel},
        Decode, DecodeValue, Document, Encode, EncodeValue, Error, Header, Length, Reader, Result,
        Sequence, Writer,
    },
};
use sm9_core::{fast_pairing, Group, G1, G2};
use std::path::Path;

use crate::*;

/// SEC1 encoded point for G1
pub type EncodedPoint = sec1::EncodedPoint<U32>;

macro_rules! key_impl {
    ($name:ident) => {
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        pub struct $name(Vec<u8>);
        impl $name {
            pub(crate) fn new(private_key: &[u8]) -> Self {
                let mut v: Vec<u8> = Vec::<u8>::new();
                v.extend_from_slice(private_key);
                Self(v)
            }
            pub(crate) fn as_slice(&self) -> &[u8] {
                self.0.as_slice()
            }
        }

        impl EncodeKey for $name {
            fn to_key_der(&self) -> Result<Document> {
                let a = PrivateKey::try_from(self.as_slice())?;
                Document::try_from(&a)
            }
            fn read_pem_file(path: impl AsRef<Path>) -> Result<Self> {
                let (label, doc) = Document::read_pem_file(path)?;
                Self::validate_pem_label(&label)?;
                let key: PrivateKey = doc.decode_msg()?;
                Ok(Self::new(key.private_key))
            }
        }
    };
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivateKey<'a> {
    // Private key data.
    private_key: &'a [u8],
}

const VERSION: u8 = 1;
impl<'a> DecodeValue<'a> for PrivateKey<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            if u8::decode(reader)? != VERSION {
                return Err(der::Tag::Integer.value_error());
            }
            let private_key = OctetStringRef::decode(reader)?.as_bytes();

            Ok(PrivateKey { private_key })
        })
    }
}
impl EncodeValue for PrivateKey<'_> {
    fn value_len(&self) -> der::Result<Length> {
        VERSION.encoded_len()? + OctetStringRef::new(self.private_key)?.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        VERSION.encode(writer)?;
        OctetStringRef::new(self.private_key)?.encode(writer)?;
        Ok(())
    }
}
impl<'a> Sequence<'a> for PrivateKey<'a> {}

impl<'a> TryFrom<&'a [u8]> for PrivateKey<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<PrivateKey<'a>> {
        Ok(Self { private_key: bytes })
    }
}
impl TryFrom<PrivateKey<'_>> for Document {
    type Error = Error;

    fn try_from(private_key: PrivateKey<'_>) -> Result<Self> {
        Document::try_from(&private_key)
    }
}

impl TryFrom<&PrivateKey<'_>> for Document {
    type Error = Error;

    fn try_from(private_key: &PrivateKey<'_>) -> Result<Self> {
        Self::encode_msg(private_key)
    }
}

pub trait EncodeKey: Sized {
    /// Write ASN.1 DER-encoded key to the given path
    fn write_pem_file(
        &self,
        path: impl AsRef<Path>,
        label: &'static str,
        line_ending: LineEnding,
    ) -> Result<()> {
        let doc = self.to_key_der()?;
        doc.write_pem_file(path, label, line_ending)
    }
    /// Serialize a [`Document`] containing a ASN.1 DER-encoded key.
    fn to_key_der(&self) -> Result<Document>;
    /// Read key from given path
    fn read_pem_file(path: impl AsRef<Path>) -> Result<Self>;
}

// SM9 master private key.
key_impl!(MasterPrivateKey);
impl PemLabel for MasterPrivateKey {
    const PEM_LABEL: &'static str = "SM9 MASTER PRIVATE KEY";
}
/// SM9 master encryption/signature private key.
impl MasterPrivateKey {
    pub(crate) fn generate_master_public_key_to_pem(&self, path: impl AsRef<Path>) {
        // master encryption private key
        let ke = Fn::from_slice(self.as_slice()).unwrap();
        // master encryption public key 𝑃𝑝𝑢𝑏−𝑒
        let pub_e = G1::one() * ke;

        let a = pub_e.to_compressed();
        let user_key = MasterPublicKey::new(a.as_ref());

        assert!(user_key
            .write_pem_file(path, MasterPublicKey::PEM_LABEL, LineEnding::CRLF)
            .is_ok());
    }
    pub(crate) fn generate_user_private_key_to_pem(&self, user_id: &[u8], path: impl AsRef<Path>) {
        // master encryption private key
        let ke = Fn::from_slice(self.as_slice()).unwrap();
        let mut z = Vec::<u8>::new();
        z.extend_from_slice(user_id);
        z.push(SM9_HID_ENC);
        let a = Sm9::hash_1(z.as_slice()).unwrap();
        let t1 = a + ke;
        let t2 = ke * t1.inverse().unwrap();
        // encryption private key of the user
        let de = G2::one() * t2;
        let a = de.to_compressed();
        let user_key = UserPrivateKey::new(a.as_ref());
        assert!(user_key
            .write_pem_file(path, UserPrivateKey::PEM_LABEL, LineEnding::CRLF)
            .is_ok());
    }
    // 5.3 Generation of the signature master key and the user's signature private key
    pub(crate) fn generate_master_signature_public_key_to_pem(&self, path: impl AsRef<Path>) {
        // master signature private key
        let ks = Fn::from_slice(self.as_slice()).unwrap();
        // master signature public key Ppub_s
        let pub_s = G2::one() * ks;

        let a = pub_s.to_compressed();
        let key = MasterSignaturePublicKey::new(a.as_ref());

        assert!(key
            .write_pem_file(path, MasterSignaturePublicKey::PEM_LABEL, LineEnding::CRLF)
            .is_ok());
    }
    // 5.3 Generation of the signature master key and the user's signature private key
    pub(crate) fn generate_user_signature_private_key_to_pem(
        &self,
        user_id: &[u8],
        path: impl AsRef<Path>,
    ) {
        // master signature private key
        let ks = Fn::from_slice(self.as_slice()).unwrap();
        let mut z = Vec::<u8>::new();
        z.extend_from_slice(user_id);
        z.push(SM9_HID_SIGN);
        let a = Sm9::hash_1(z.as_slice()).unwrap();
        let t1 = a + ks;
        let t2 = ks * t1.inverse().unwrap();
        // signature private key of the user
        let ds = G1::one() * t2;
        let a = ds.to_compressed();
        let user_key = UserSignaturePrivateKey::new(a.as_ref());
        assert!(user_key
            .write_pem_file(path, UserSignaturePrivateKey::PEM_LABEL, LineEnding::CRLF)
            .is_ok());
    }
}

// SM9 master encryption public key.
key_impl!(MasterPublicKey);
impl PemLabel for MasterPublicKey {
    const PEM_LABEL: &'static str = "SM9 MASTER PUBLIC KEY";
}
/// SM9 master encryption public key.
impl MasterPublicKey {
    pub(crate) fn is_ok(&self) -> bool {
        self.to_g1().is_some()
    }
    pub(crate) fn to_g1(&self) -> Option<G1> {
        let b = self.as_slice();
        match b.len() {
            33 => G1::from_compressed(b).ok(),
            64 => G1::from_slice(b).ok(),
            65 => G1::from_uncompressed(b).ok(),
            _ => None,
        }
    }
    // SM9 identity-based cryptographic algorithms
    // Part 4: Key encapsulation mechanism and public key encryption algorithm
    // 6.1.1 Key encapsulation algorithm
    pub(crate) fn key_encapsulation(&self, usr_id: &[u8], klen: usize) -> (Vec<u8>, G1) {
        // A1: Q = H1(ID||hid,N) * P1 + Ppube
        let mut z = Vec::<u8>::new();
        z.extend_from_slice(usr_id);
        z.push(SM9_HID_ENC);
        let h1 = Sm9::hash_1(z.as_slice()).unwrap();
        let g1 = G1::one() * h1;
        let pube = self.to_g1().expect("MasterPublicKey error");
        let q = g1 + pube;
        // A4: g = e(Ppube, P2)
        let g = fast_pairing(pube, G2::one());

        let mut c;
        let mut k;
        let rng = &mut thread_rng();
        loop {
            // A2: rand r in [1, N-1]
            let r = Fn::random(rng);
            // just for test
            //let r = Fn::from_slice(&hex!("0000AAC0 541779C8 FC45E3E2 CB25C12B 5D2576B2 129AE8BB 5EE2CBE5 EC9E785C")).unwrap();
            // A3: C1 = r * Q
            c = r * q;
            // A5: w = g^r
            let w = g.pow(r);
            // A6: K = KDF(C || w || ID_B, klen), if K == 0, goto A2
            let mut z = Vec::<u8>::new();
            z.extend_from_slice(c.to_slice().as_ref());
            z.extend_from_slice(w.to_slice().as_ref());
            z.extend_from_slice(usr_id);

            k = Sm9::kdf(z.as_ref(), klen).expect("klen maybe error");
            if !k.iter().all(|&e| e == 0) {
                break; // break loop
            }
        }
        // A7: output (K, C)
        (k, c)
    }
    // SM9 identity-based cryptographic algorithms
    // Part 4: Key encapsulation mechanism and public key encryption algorithm
    // 7.1.1 Encryption algorithm
    pub(crate) fn encrypt(&self, usr_id: &[u8], m: &[u8]) -> Vec<u8> {
        // A1 ~ A6(1)
        let klen = m.len() + 32;
        let (k, c1) = self.key_encapsulation(usr_id, klen);
        // A6:(2) compute C2 = M ^ K1
        let mut c2 = Vec::<u8>::new();
        for (b, x) in m.iter().zip(k.iter()) {
            c2.push(*b ^ *x);
        }
        let k2 = &k[m.len()..];
        // A7: compute C3 = MAC(K2,C2)
        let mut mac = HmacSm3::new_from_slice(k2).expect("HMAC can take key of any size");
        mac.update(c2.as_slice());
        let c3 = mac.finalize().into_bytes();
        let mut c = Vec::<u8>::new();
        // C1
        c.extend_from_slice(c1.to_slice().as_ref());
        // C3
        c.extend_from_slice(c3.as_slice());
        // C2
        c.extend_from_slice(c2.as_slice());
        // A8: Output ciphertext C = C1||C3||C2
        c
    }
}

// SM9 encryption private key of the user
key_impl!(UserPrivateKey);
impl PemLabel for UserPrivateKey {
    const PEM_LABEL: &'static str = "SM9 USER PRIVATE KEY";
}
/// SM9 encryption private key of the user
impl UserPrivateKey {
    pub(crate) fn is_ok(&self) -> bool {
        self.to_g2().is_some()
    }
    pub(crate) fn to_g2(&self) -> Option<G2> {
        let b = self.as_slice();
        match b.len() {
            65 => G2::from_compressed(b).ok(),
            128 => G2::from_slice(b).ok(),
            129 => G2::from_uncompressed(b).ok(),
            _ => None,
        }
    }
    // SM9 identity-based cryptographic algorithms
    // Part 4: Key encapsulation mechanism and public key encryption algorithm
    // 6.2.1 Decapsulation algorithm
    pub(crate) fn key_decapsulation(&self, usr_id: &[u8], klen: usize, c: &G1) -> Vec<u8> {
        let de = self.to_g2().expect("UserPrivateKey error");
        // B2: w = e(C, de);
        let w = fast_pairing(*c, de);
        // B3: K = KDF(C || w || ID, klen)
        let mut z = Vec::<u8>::new();
        z.extend_from_slice(c.to_slice().as_ref());
        z.extend_from_slice(w.to_slice().as_ref());
        z.extend_from_slice(usr_id);
        let k = Sm9::kdf(z.as_slice(), klen).expect("klen maybe error");
        // B4: output K
        k
    }
    // SM9 identity-based cryptographic algorithms
    // Part 4: Key encapsulation mechanism and public key encryption algorithm
    // 7.2.1 Decryption algorithm
    pub(crate) fn decrypt(&self, usr_id: &[u8], ciphertext: Vec<u8>) -> Option<Vec<u8>> {
        if ciphertext.len() <= 64 + 32 {
            return None;
        }
        // ciphertext = C1||C3||C2
        let c1 = &ciphertext[..64];
        let c3 = &ciphertext[64..96];
        let c2 = &ciphertext[96..];
        // B1: Convert the data type of C1 to a point on elliptic curve
        let c = G1::from_slice(c1).expect("C1 error,not a point on curve");
        // B2 and B3:(1)
        let klen = c2.len() + 32;
        let k = self.key_decapsulation(usr_id, klen, &c);
        let k2 = &k[c2.len()..];
        // B4: compute u = MAC(K2,C2), if u != C3, report an error and exit
        let mut mac = HmacSm3::new_from_slice(k2).expect("HMAC can take key of any size");
        mac.update(c2);
        let binding = mac.finalize().into_bytes();
        let u = binding.as_slice();
        if u != c3 {
            return None;
        }
        // B3:(2) compute M = C2 ^ K1
        let mut m = Vec::<u8>::new();
        for (b, x) in c2.iter().zip(k.iter()) {
            m.push(*b ^ *x);
        }
        // B5: output plaintext M
        Some(m)
    }
}

// SM9 master signature public key
key_impl!(MasterSignaturePublicKey);
impl PemLabel for MasterSignaturePublicKey {
    const PEM_LABEL: &'static str = "SM9 MASTER SIGNATURE PUBLIC KEY";
}
/// SM9 master signature public key
impl MasterSignaturePublicKey {
    pub(crate) fn is_ok(&self) -> bool {
        self.to_g2().is_some()
    }
    pub(crate) fn to_g2(&self) -> Option<G2> {
        let b = self.as_slice();
        match b.len() {
            65 => G2::from_compressed(b).ok(),
            128 => G2::from_slice(b).ok(),
            129 => G2::from_uncompressed(b).ok(),
            _ => None,
        }
    }
    // SM9 identity-based cryptographic algorithms
    // Part 2: Digital signature algorithm
    // 7.1 Digital signature verification algorithm
    pub(crate) fn verify(&self, usr_id: &[u8], m: &[u8], (oh, os): (Vec<u8>, Vec<u8>)) -> bool {
        // B1: Convert the data type of ℎ to an integer
        let h = Fn::from_slice(oh.as_slice()).expect("signature h error");
        // deal with both compress and uncompress form
        let ep = EncodedPoint::from_bytes(os.as_slice()).expect("signature s error");
        let ep_compressed = ep.compress();
        // B2: Convert the data type of 𝑆′ to a point on the elliptic curve
        // let s = G1::from_uncompressed(os.as_slice()).expect("signature s error");
        let s = G1::from_compressed(ep_compressed.as_bytes()).expect("signature s error");
        // Case 1: Direct conversion. 6.2.8 in GM/T 0044.1‒2016
        // let s = G1::from_slice(os.as_slice()).expect("signature s error");
        // B3: Compute the element 𝑔=𝑒(𝑃1,𝑃𝑝𝑢𝑏−𝑠)
        let pub_s = self.to_g2().expect("MasterSignaturePublicKey error");
        let g = fast_pairing(G1::one(), pub_s);
        // B4: Compute the element 𝑡=𝑔^h
        let t = g.pow(h);
        // B5: Compute the integer ℎ1=𝐻1(𝐼𝐷𝐴||ℎ𝑖𝑑,𝑁);
        let mut z = Vec::<u8>::new();
        z.extend_from_slice(usr_id);
        z.push(SM9_HID_SIGN);
        let h1 = Sm9::hash_1(z.as_slice()).unwrap();
        // B6: Compute the element 𝑃=[ℎ1]𝑃2+𝑃𝑝𝑢𝑏−𝑠
        let p = G2::one() * h1 + pub_s;
        // B7: Compute the element 𝑢=𝑒(𝑆,𝑃)
        let u = fast_pairing(s, p);
        // B8: Compute the element 𝑤′=𝑢∙𝑡
        let w = u * t;
        // B9: Compute an integer ℎ2=𝐻2(𝑀′||𝑤′,𝑁) and check whether ℎ2=ℎ′
        let mut z = Vec::<u8>::new();
        z.extend_from_slice(m);
        z.extend_from_slice(w.to_slice().as_ref());
        let h2 = Sm9::hash_2(z.as_slice()).unwrap();
        h2 == h
    }
}

// SM9 user signature private key.
key_impl!(UserSignaturePrivateKey);
impl PemLabel for UserSignaturePrivateKey {
    const PEM_LABEL: &'static str = "SM9 USER SIGNATURE PRIVATE KEY";
}
/// SM9 user signature private key.
impl UserSignaturePrivateKey {
    pub(crate) fn is_ok(&self) -> bool {
        self.to_g1().is_some()
    }
    pub(crate) fn to_g1(&self) -> Option<G1> {
        let b = self.as_slice();
        match b.len() {
            33 => G1::from_compressed(b).ok(),
            64 => G1::from_slice(b).ok(),
            65 => G1::from_uncompressed(b).ok(),
            _ => None,
        }
    }
    // SM9 identity-based cryptographic algorithms
    // Part 2: Digital signature algorithm
    // 6.1 Digital signature generation algorithm
    pub(crate) fn sign(&self, msp: &MasterSignaturePublicKey, m: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // A1: Compute the element g = e(P1, Ppub_s)
        let pub_s = msp.to_g2().expect("MasterSignaturePublicKey error");
        let g = fast_pairing(G1::one(), pub_s);
        let rng = &mut thread_rng();
        let mut h;
        let mut l;
        loop {
            // A2: Generate a random integer r in [1, N-1]
            let r = Fn::random(rng);
            // just for test
            //let r = Fn::from_slice(&hex!("00033C86 16B06704 813203DF D0096502 2ED15975 C662337A ED648835 DC4B1CBE")).unwrap();
            // A3: Compute the element w = g^r
            let w = g.pow(r);
            // A4: Compute the integer ℎ=𝐻2(𝑀||𝑤,𝑁);
            let mut z = Vec::<u8>::new();
            z.extend_from_slice(m);
            z.extend_from_slice(w.to_slice().as_ref());
            h = Sm9::hash_2(z.as_slice()).unwrap();
            // A5: Compute the integer 𝑙=(𝑟−ℎ) mod 𝑁; if 𝑙=0, go to Step A2;
            l = r - h;
            if !l.is_zero() {
                break;
            }
        }
        // A6: Compute the element 𝑆=[𝑙]𝑑𝑠
        let ds = self.to_g1().expect("UserSignaturePrivateKey error");
        let s = ds * l;
        // A7: Output (ℎ,𝑆)
        let mut oh = Vec::<u8>::new();
        let mut os = Vec::<u8>::new();
        oh.extend_from_slice(h.to_slice().as_ref());
        //6.2.8 in GM/T 0044.1‒2016, uncompressed form
        os.extend_from_slice(s.to_uncompressed().as_ref());
        // Case 1: Direct conversion. //6.2.8 in GM/T 0044.1‒2016
        // os.extend_from_slice(s.to_slice().as_ref());

        (oh, os)
    }
}
