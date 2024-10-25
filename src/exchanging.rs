//! SM9 Key exchange protocol Support.
//!
//! SM9 identity-based cryptographic algorithms
//! Part 3: Key exchange protocol
//!

use core::fmt::{Debug, Display};

use crate::*;
use generic_array::{typenum, ArrayLength, GenericArray};
//use hex_literal::hex;
use sm3::{Digest, Sm3};
use sm9_core::{fast_pairing, Group, G1, G2};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Represents KEM errors. This is intentionally opaque to avoid leaking information about private
/// keys through side channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error;

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "error key exchanging!")
    }
}

/// The shared secret that results from key exchange.
#[derive(Clone, Debug, Default, Eq, PartialEq, ZeroizeOnDrop)]
pub struct Secret<N: ArrayLength>(GenericArray<u8, N>);

// Zero the secret on drop
impl<N: ArrayLength> Zeroize for Secret<N> {
    fn zeroize(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}
impl<N: ArrayLength> Secret<N> {
    /// Constructs a new `Secret` by wrapping the given bytes
    pub fn new(bytes: GenericArray<u8, N>) -> Self {
        Secret(bytes)
    }
    /// Converts a slice to a generic array reference with inferred length.
    /// Panics if the slice is not equal to the length of the array.
    pub fn from_slice(slice: &[u8]) -> Self {
        Secret(GenericArray::<u8, N>::from_slice(slice).clone())
    }
    /// Extracts a slice containing the entire array.
    pub const fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}
/// The shared secret that results from key exchange.
pub type SharedSecret = Secret<typenum::U16>;

/// Ephemeral Secret during key exchange process.
pub type EphemeralSecret = Secret<typenum::U64>;

/// Comfirmable Secret during key exchange process.
pub type ComfirmableSecret = Secret<typenum::U32>;

/// The struct used for key exchange
#[derive(Clone, Debug)]
pub struct KeyExchanger {
    public_key: MasterPublicKey,
    user_key: UserPrivateKey,
    user_id: Vec<u8>,
    is_initiator: bool,
    // some intermediate variable
    r: Fn,
    peer_id: Vec<u8>,
    ra: EphemeralSecret,
    rb: EphemeralSecret,
    s1: ComfirmableSecret,
    s2: ComfirmableSecret,
}
impl KeyExchanger {
    pub fn new(
        user_id: &[u8],
        user_key: &UserPrivateKey,
        public_key: &MasterPublicKey,
        is_initiator: bool,
    ) -> Result<Self, Error> {
        if public_key.is_ok() && !user_id.is_empty() && user_key.is_ok() {
            let mut id = Vec::<u8>::new();
            id.extend_from_slice(user_id);
            Ok(Self {
                public_key: public_key.clone(),
                user_id: id,
                user_key: user_key.clone(),
                is_initiator,
                r: Fn::zero(),
                peer_id: Vec::<u8>::new(),
                ra: EphemeralSecret::default(),
                rb: EphemeralSecret::default(),
                s1: ComfirmableSecret::default(),
                s2: ComfirmableSecret::default(),
            })
        } else {
            Err(Error)
        }
    }
    pub fn generate_ephemeral_secret(&mut self, peer_id: &[u8]) -> Result<EphemeralSecret, Error> {
        self.peer_id.clear();
        self.peer_id.extend_from_slice(peer_id);
        // Step 1: compute 𝑄=[𝐻1(𝐼𝐷∥ℎ𝑖𝑑,𝑁)]𝑃1+𝑃𝑝𝑢𝑏−𝑒
        let mut z = Vec::<u8>::new();
        z.extend_from_slice(peer_id);
        z.push(SM9_HID_ENC);
        println!("𝐼𝐷𝐵∥ℎ𝑖𝑑 {:02X?}", z);
        let h1 = Sm9::hash_1(z.as_slice()).unwrap();
        println!("{:02X?}", h1);
        let g1 = G1::one() * h1;
        let pube = self.public_key.to_g1().ok_or(Error).unwrap();
        let q = g1 + pube;
        // Step 2: generate a random number
        let rng = &mut thread_rng();
        let r = Fn::random(rng);
        // just for test
        /*
            let r = if peer_id == b"Bob" {
                Fn::from_slice(&hex!(
                    "00005879 DD1D51E1 75946F23 B1B41E93 BA31C584 AE59A426 EC1046A4 D03B06C8"
                ))
                .unwrap()
            } else {
                Fn::from_slice(&hex!(
                    "00018B98 C44BEF9F 8537FB7D 071B2C92 8B3BC65B D3D69E1E EE213564 905634FE"
                ))
                .unwrap()
            };
        */
        self.r = r;
        //Step 3: compute 𝑅𝐴=[𝑟𝐴]𝑄𝐵
        let ra = (r * q).to_slice();
        println!("ra: {:02X?}", ra);
        self.ra = EphemeralSecret::from_slice(ra.as_ref());
        Ok(self.ra.clone())
    }
    pub fn generate_shared_secret(&mut self, es: &EphemeralSecret) -> Result<SharedSecret, Error> {
        if self.peer_id.is_empty() {
            // call generate_ephemeral_secret first
            Err(Error)
        } else {
            let sk;
            if self.is_initiator {
                self.rb = EphemeralSecret::new(es.0);
                let rb = G1::from_slice(self.rb.as_slice()).unwrap();
                let g1 = fast_pairing(self.public_key.to_g1().unwrap(), G2::one()).pow(self.r);
                let g2 = fast_pairing(rb, self.user_key.to_g2().unwrap());
                let g3 = g2.pow(self.r);
                // Step 7: compute 𝑆𝐾𝐴=𝐾𝐷𝐹(𝐼𝐷𝐴∥𝐼𝐷𝐵∥𝑅𝐴∥𝑅𝐵∥𝑔1′∥𝑔2′∥𝑔3′,𝑘𝑙𝑒𝑛)
                let mut z = Vec::<u8>::new();
                z.extend(&self.user_id);
                z.extend(&self.peer_id);
                z.extend_from_slice(self.ra.as_slice());
                z.extend_from_slice(self.rb.as_slice());
                z.extend_from_slice(g1.to_slice().as_ref());
                z.extend_from_slice(g2.to_slice().as_ref());
                z.extend_from_slice(g3.to_slice().as_ref());

                sk = Sm9::kdf(z.as_ref(), 16).expect("klen maybe error");
                //𝑆1 = 𝐻𝑣(0x82 ∥ 𝑔1′∥ 𝐻𝑣(𝑔2′∥ 𝑔3′∥ 𝐼𝐷𝐴 ∥ 𝐼𝐷𝐵 ∥𝑅𝐴 ∥ 𝑅𝐵))
                let mut u = Vec::<u8>::new();
                u.extend_from_slice(g2.to_slice().as_ref());
                u.extend_from_slice(g3.to_slice().as_ref());
                u.extend(&self.user_id);
                u.extend(&self.peer_id);
                u.extend_from_slice(self.ra.as_slice());
                u.extend_from_slice(self.rb.as_slice());
                let mut sm3 = Sm3::new();
                sm3.update(u);
                let ha2 = sm3.finalize();
                let mut v = Vec::<u8>::new();
                v.extend_from_slice(g1.to_slice().as_ref());
                v.extend_from_slice(ha2.as_slice());
                let mut sm3 = Sm3::new();
                sm3.update([0x82u8]);
                sm3.update(v.clone());
                let ha = sm3.finalize();
                println!("s1: {:02X?}", ha.as_slice());
                self.s1 = ComfirmableSecret::from_slice(ha.as_slice());
                //𝑆1 = 𝐻𝑣(0x83 ∥ 𝑔1′∥ 𝐻𝑣(𝑔2′∥ 𝑔3′∥ 𝐼𝐷𝐴 ∥ 𝐼𝐷𝐵 ∥𝑅𝐴 ∥ 𝑅𝐵))
                let mut sm3 = Sm3::new();
                sm3.update([0x83u8]);
                sm3.update(v);
                let ha = sm3.finalize();
                println!("s2: {:02X?}", ha.as_slice());
                self.s2 = ComfirmableSecret::from_slice(ha.as_slice());

                println!("sk: {:02X?}", sk);
            } else {
                self.rb = EphemeralSecret::new(es.0);
                let rb = G1::from_slice(self.rb.as_slice()).unwrap();
                let g1 = fast_pairing(rb, self.user_key.to_g2().unwrap());
                let g2 = fast_pairing(self.public_key.to_g1().unwrap(), G2::one()).pow(self.r);
                let g3 = g1.pow(self.r);
                // Step 7: compute 𝑆𝐾𝐴=𝐾𝐷𝐹(𝐼𝐷𝐴∥𝐼𝐷𝐵∥𝑅𝐴∥𝑅𝐵∥𝑔1′∥𝑔2′∥𝑔3′,𝑘𝑙𝑒𝑛)
                let mut z = Vec::<u8>::new();
                z.extend(&self.peer_id);
                z.extend(&self.user_id);
                z.extend_from_slice(self.rb.as_slice());
                z.extend_from_slice(self.ra.as_slice());
                z.extend_from_slice(g1.to_slice().as_ref());
                z.extend_from_slice(g2.to_slice().as_ref());
                z.extend_from_slice(g3.to_slice().as_ref());

                sk = Sm9::kdf(z.as_ref(), 16).expect("klen maybe error");
                //𝑆1 = 𝐻𝑣(0x82 ∥ 𝑔1′∥ 𝐻𝑣(𝑔2′∥ 𝑔3′∥ 𝐼𝐷𝐴 ∥ 𝐼𝐷𝐵 ∥𝑅𝐴 ∥ 𝑅𝐵))
                let mut u = Vec::<u8>::new();
                u.extend_from_slice(g2.to_slice().as_ref());
                u.extend_from_slice(g3.to_slice().as_ref());
                u.extend(&self.peer_id);
                u.extend(&self.user_id);
                u.extend_from_slice(self.rb.as_slice());
                u.extend_from_slice(self.ra.as_slice());
                let mut sm3 = Sm3::new();
                sm3.update(u);
                let ha2 = sm3.finalize();
                let mut v = Vec::<u8>::new();
                v.extend_from_slice(g1.to_slice().as_ref());
                v.extend_from_slice(ha2.as_slice());
                let mut sm3 = Sm3::new();
                sm3.update([0x82u8]);
                sm3.update(v.clone());
                let ha = sm3.finalize();
                println!("s1: {:02X?}", ha.as_slice());
                self.s1 = ComfirmableSecret::from_slice(ha.as_slice());
                //𝑆1 = 𝐻𝑣(0x83 ∥ 𝑔1′∥ 𝐻𝑣(𝑔2′∥ 𝑔3′∥ 𝐼𝐷𝐴 ∥ 𝐼𝐷𝐵 ∥𝑅𝐴 ∥ 𝑅𝐵))
                let mut sm3 = Sm3::new();
                sm3.update([0x83u8]);
                sm3.update(v);
                let ha = sm3.finalize();
                println!("s2: {:02X?}", ha.as_slice());
                self.s2 = ComfirmableSecret::from_slice(ha.as_slice());

                println!("sk: {:02X?}", sk);
            }
            Ok(SharedSecret::from_slice(sk.as_ref()))
        }
    }
    pub fn generate_comfirmable_secret(&self) -> Result<ComfirmableSecret, Error> {
        if self.s1 == ComfirmableSecret::default() {
            Err(Error)
        } else if self.is_initiator {
            Ok(self.s2.clone())
        } else {
            Ok(self.s1.clone())
        }
    }
    pub fn comfirm(&self, cs: &ComfirmableSecret) -> Result<bool, Error> {
        if self.s1 == ComfirmableSecret::default() {
            Err(Error)
        } else if self.is_initiator {
            Ok(self.s1 == *cs)
        } else {
            Ok(self.s2 == *cs)
        }
    }
}
