use crate::*;
use signature::{Error, Verifier};

/// SM9 public key used for verifying signatures
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    /// MasterSignaturePublicKey.
    public_key: MasterSignaturePublicKey,
    /// Signer's user id.
    user_id: Vec<u8>,
}
impl VerifyingKey {
    /// Initialize [`VerifyingKey`] from a signer's user id
    /// and master signature public key.
    pub fn new(user_id: &[u8], public_key: &MasterSignaturePublicKey) -> Option<Self> {
        if public_key.is_ok() && !user_id.is_empty() {
            let mut id = Vec::<u8>::new();
            id.extend_from_slice(user_id);
            Some(Self {
                public_key: public_key.clone(),
                user_id: id,
            })
        } else {
            None
        }
    }
}
// `Verifier` trait impls
impl Verifier<Signature> for VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        let mut oh = Vec::<u8>::new();
        oh.extend_from_slice(signature.h_as_ref());
        let mut os = Vec::<u8>::new();
        os.extend_from_slice(signature.s_as_ref());

        if self.public_key.verify(self.user_id.as_ref(), msg, (oh, os)) {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}
