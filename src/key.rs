use std::path::Path;

use der::{
    asn1::OctetStringRef, Decode, DecodeValue, Document, Encode, EncodeValue, Error, Header,
    Length, Reader, Result, Sequence, Writer,
};

use crate::*;
use pem_rfc7468::{LineEnding, PemLabel};
use sm9_core::{fast_pairing, Fr, Group, G1, G2};

macro_rules! key_impl {
    ($name:ident) => {
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        pub struct $name(Vec<u8>);
        impl $name {
            pub fn new(private_key: &[u8]) -> Self {
                let n = private_key.len();
                let mut v: Vec<u8> = vec![0u8; n];
                v.copy_from_slice(private_key);
                Self(v)
            }
            pub fn as_slice(&self) -> &[u8] {
                self.0.as_slice()
            }
        }

        impl EncodeKey for $name {
            fn to_key_der(&self) -> Result<Document> {
                let a = PrivateKey::try_from(self.0.as_slice())?;
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

// SM9 master encryption private key.
key_impl!(MasterPrivateKey);
impl PemLabel for MasterPrivateKey {
    const PEM_LABEL: &'static str = "SM9 MASTER PRIVATE KEY";
}
/// SM9 master encryption private key.
impl MasterPrivateKey {
    pub fn generate_master_public_key_to_pem(&self, path: impl AsRef<Path>) {
        // master encryption private key
        let ke = Fr::from_slice(self.as_slice()).unwrap();
        // master encryption public key 𝑃𝑝𝑢𝑏−𝑒
        let pub_e = G1::one() * ke;

        let a = pub_e.to_compressed();
        let user_key = MasterPublicKey::new(&a[..]);

        assert!(user_key
            .write_pem_file(path, MasterPublicKey::PEM_LABEL, LineEnding::CRLF)
            .is_ok());
    }
    pub fn generate_user_private_key_to_pem(
        &self,
        user_id: &[u8],
        hid: u8,
        path: impl AsRef<Path>,
    ) {
        // master encryption private key
        let ke = Fr::from_slice(self.as_slice()).unwrap();
        let a = Sm9::hash_1(user_id, hid).unwrap();
        let t1 = a + ke;
        let t2 = ke * t1.inverse().unwrap();
        // encryption private key of the user
        let de = G2::one() * t2;
        let a = de.to_compressed();
        let user_key = UserPrivateKey::new(&a[..]);
        assert!(user_key
            .write_pem_file(path, UserPrivateKey::PEM_LABEL, LineEnding::CRLF)
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
    pub fn to_g1(&self) -> Option<G1> {
        let b = self.as_slice();
        match b.len() {
            33 => G1::from_compressed(b).ok(),
            64 => G1::from_slice(b).ok(),
            _ => None,
        }
    }
    // SM9 identity-based cryptographic algorithms
    // Part 4: Key encapsulation mechanism and public key encryption algorithm
    // 6.1.1 Key encapsulation algorithm
    pub fn key_encapsulation(&self, usr_id: &[u8], klen: usize) -> (Vec<u8>, G1) {
        // A1: Q = H1(ID||hid,N) * P1 + Ppube
        let h1 = Sm9::hash_1(usr_id, 3u8).unwrap();
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
            let r = Fr::random(rng);
            // just for test
            // let r = Fr::from_slice(&hex!("0000AAC0 541779C8 FC45E3E2 CB25C12B 5D2576B2 129AE8BB 5EE2CBE5 EC9E785C")).unwrap();
            // A3: C1 = r * Q
            c = q * r;
            // A5: w = g^r
            let w = g.pow(r);
            // A6: K = KDF(C || w || ID_B, klen), if K == 0, goto A2
            let mut z = Vec::<u8>::new();
            z.extend_from_slice(c.to_slice().as_ref());
            z.extend_from_slice(w.to_slice().as_ref());
            z.extend_from_slice(usr_id);

            k = Sm9::kdf(z.as_ref(), klen).expect("klen maybe error");
            let mut not_zero = false;
            for b in k.as_slice() {
                if *b != 0 {
                    not_zero = true;
                    break; // break for
                }
            }
            if not_zero {
                break; // break loop
            }
        }
        // A7: output (K, C)
        (k, c)
    }

    pub fn encrypt(&self, usr_id: &[u8], m: &[u8]) -> Vec<u8> {
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
    pub fn to_g2(&self) -> Option<G2> {
        let b = self.as_slice();
        match b.len() {
            65 => G2::from_compressed(b).ok(),
            128 => G2::from_slice(b).ok(),
            _ => None,
        }
    }
    // SM9 identity-based cryptographic algorithms
    // Part 4: Key encapsulation mechanism and public key encryption algorithm
    // 6.2.1 Decapsulation algorithm
    pub fn key_decapsulation(&self, usr_id: &[u8], klen: usize, c: &G1) -> Vec<u8> {
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

    pub fn decrypt(&self, usr_id: &[u8], ciphertext: Vec<u8>) -> Option<Vec<u8>> {
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
        if c3 != u {
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
