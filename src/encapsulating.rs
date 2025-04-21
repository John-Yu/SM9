use crate::*;
//use hex_literal::hex;
use core::fmt::{Debug, Error};
use generic_array::{ArrayLength, GenericArray, typenum};
use rand_core::RngCore; // Ensure rand_core is added as a dependency in Cargo.toml
use sm9_core::{G1, G2, Group, fast_pairing};

// The size of an encapped key. This is the number of bytes in an uncompressed G1 point
type NEnc = typenum::U64;
// The encapped key is just the byte repr of a G1 point. Impl the appropriate traits
#[derive(Debug)]
pub struct Sm9EncappedKey(GenericArray<u8, NEnc>);

/// Trait impl'd by concrete types that represent an encapsulated key. This is intended to be, in
/// essence, a bag of bytes.
pub trait EncappedKey: AsRef<[u8]> + Debug + Sized {
    /// The size, in bytes, of an encapsulated key.
    type EncappedKeySize: ArrayLength;

    /// The size, in bytes, of the shared secret that this KEM produces.
    type SharedSecretSize: ArrayLength;

    /// Represents the identity key of an encapsulator. This is used in authenticated
    /// decapsulation.
    type SenderPublicKey;

    /// The public key of a decapsulator. This is used in encapsulation.
    type RecipientPublicKey;

    /// Parses an encapsulated key from its byte representation.
    fn from_bytes(bytes: &GenericArray<u8, Self::EncappedKeySize>) -> Result<Self, Error>;

    /// Borrows a byte slice representing the serialized form of this encapsulated key.
    fn as_bytes(&self) -> &GenericArray<u8, Self::EncappedKeySize> {
        // EncappedKey is already AsRef<[u8]>, so we don't need to do any work. This will panic iff
        // the underlying bytestring is not precisely NEnc bytes long.
        GenericArray::from_slice(self.as_ref())
    }
}
/// The shared secret that results from key exchange.
pub struct SharedSecret<EK: EncappedKey>(GenericArray<u8, EK::SharedSecretSize>);

impl<EK: EncappedKey> SharedSecret<EK> {
    /// Constructs a new `SharedSecret` by wrapping the given bytes
    pub fn new(bytes: GenericArray<u8, EK::SharedSecretSize>) -> Self {
        SharedSecret(bytes)
    }

    /// Returns borrowed bytes representing the shared secret of the key exchange
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

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

/// Represents the functionality of a key encapsulator. For unauthenticated encapsulation, `Self`
/// can be an empty struct. For authenticated encapsulation, `Self` is a private key.
pub trait Encapsulator<EK: EncappedKey> {
    /// Attempts to encapsulate a fresh shared secret with the given recipient. The resulting
    /// shared secret is bound to the identity encoded in `Self` (i.e., authenticated wrt `Self`).
    /// If `Self` is empty, then this is equivalent to unauthenticated encapsulation. Returns the
    /// shared secret and encapsulated key on success, or an error if something went wrong.
    fn try_encap<R: RngCore + ?Sized>(
        &self,
        csprng: &mut R,
        recip_pubkey: &EK::RecipientPublicKey,
    ) -> Result<(EK, SharedSecret<EK>), Error>;
}

/// Represents the functionality of a key decapsulator, where `Self` is a cryptographic key.
pub trait Decapsulator<EK: EncappedKey> {
    /// Attempt to decapsulate the given encapsulated key. Returns the shared secret on success, or
    /// an error if something went wrong.
    fn try_decap(&self, encapped_key: &EK) -> Result<SharedSecret<EK>, Error>;
}

// Define an unauthenticated encapsulator.
impl Encapsulator<Sm9EncappedKey> for <Sm9EncappedKey as EncappedKey>::SenderPublicKey {
    fn try_encap<R: RngCore + ?Sized>(
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

        let encapped_key =
            Sm9EncappedKey::from_bytes(GenericArray::from_slice(c.to_slice().as_ref()))?;
        let shared_secret = Sm9SharedSecret::new(*GenericArray::from_slice(w.to_slice().as_ref()));

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
        let shared_secret = Sm9SharedSecret::new(*GenericArray::from_slice(w.to_slice().as_ref()));
        Ok(shared_secret)
    }
}
