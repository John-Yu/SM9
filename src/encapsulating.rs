use crate::*;
//use hex_literal::hex;
use hmac::digest::typenum;
use kem::{
    generic_array::GenericArray, Decapsulator, EncappedKey, Encapsulator, Error, SharedSecret,
};
use sm9_core::{fast_pairing, Group, G1, G2};

// The size of an encapped key. This is the number of bytes in an uncompressed G1 point
type NEnc = typenum::U64;
// The encapped key is just the byte repr of a G1 point. Impl the appropriate traits
#[derive(Debug)]
pub struct Sm9EncappedKey(GenericArray<u8, NEnc>);
impl EncappedKey for Sm9EncappedKey {
    // This is the number of bytes in an uncompressed Gt point
    type SharedSecretSize = typenum::U384;
    type EncappedKeySize = NEnc;
    type SenderPublicKey = MasterPublicKey;
    type RecipientPublicKey = GenericArray<u8, typenum::U128>; // user id

    fn from_bytes(bytes: &GenericArray<u8, Self::EncappedKeySize>) -> Result<Self, Error> {
        Ok(Sm9EncappedKey(*bytes))
    }
}
impl AsRef<[u8]> for Sm9EncappedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
// Define some convenience types
pub type Sm9SharedSecret = SharedSecret<Sm9EncappedKey>;

// Define an unauthenticated encapsulator.
impl Encapsulator<Sm9EncappedKey> for <Sm9EncappedKey as EncappedKey>::SenderPublicKey {
    fn try_encap<R: RngCore + CryptoRng>(
        &self,
        csprng: &mut R,
        recip_pubkey: &<Sm9EncappedKey as EncappedKey>::RecipientPublicKey,
    ) -> Result<(Sm9EncappedKey, Sm9SharedSecret), Error> {
        // Make a new MasterPublicKey key. This will be the encapped key
        let mut user_id = Vec::<u8>::new();
        for b in recip_pubkey {
            if *b != 0 {
                user_id.push(*b);
            } else {
                break;
            }
        }
        let mut z = Vec::<u8>::new();
        z.extend_from_slice(user_id.as_ref());
        z.push(SM9_HID_ENC);
        let h1 = Sm9::hash_1(z.as_slice()).unwrap();
        let g1 = G1::one() * h1;
        let pube = self.to_g1().expect("MasterPublicKey error");
        let q = g1 + pube;
        // A4: g = e(Ppube, P2)
        let g = fast_pairing(pube, G2::one());

        // A2: rand r in [1, N-1]
        let r = Fn::random(csprng);
        // just for test
        //let r = Fn::from_slice(&hex!("0000AAC0 541779C8 FC45E3E2 CB25C12B 5D2576B2 129AE8BB 5EE2CBE5 EC9E785C")).unwrap();
        // A3: C1 = r * Q
        let c = r * q;
        // A5: w = g^r
        let w = g.pow(r);

        let encapped_key = Sm9EncappedKey::from_bytes(c.to_slice().as_ref().into())?;
        let shared_secret =
            Sm9SharedSecret::new(GenericArray::clone_from_slice(w.to_slice().as_ref()));

        Ok((encapped_key, shared_secret))
    }
}

// Define a decapsulator
impl Decapsulator<Sm9EncappedKey> for UserPrivateKey {
    fn try_decap(&self, encapped_key: &Sm9EncappedKey) -> Result<Sm9SharedSecret, Error> {
        let de = self.to_g2().expect("UserPrivateKey error");
        let c = G1::from_slice(encapped_key.as_ref()).unwrap();
        // B2: w = e(C, de);
        let w = fast_pairing(c, de);
        let shared_secret =
            Sm9SharedSecret::new(GenericArray::clone_from_slice(w.to_slice().as_ref()));
        Ok(shared_secret)
    }
}
