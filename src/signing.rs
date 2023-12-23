use crate::*;
use signature::{Error, Signer};

#[derive(Clone)]
/// SM9 Signature private key
pub struct SigningKey {
    /// UserSignaturePrivateKey.
    user_private_key: UserSignaturePrivateKey,
    /// MasterSignaturePublicKey.
    master_public_key: MasterSignaturePublicKey,
}
impl SigningKey {
    /// Create signing key from a UserSignaturePrivateKey and MasterSignaturePublicKey
    pub fn new(
        user_private_key: &UserSignaturePrivateKey,
        master_public_key: &MasterSignaturePublicKey,
    ) -> Option<Self> {
        if user_private_key.is_ok() && master_public_key.is_ok() {
            Some(Self {
                user_private_key: user_private_key.clone(),
                master_public_key: master_public_key.clone(),
            })
        } else {
            None
        }
    }
}
// `Signer` trait impls
impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let (h, s) = self.user_private_key.sign(&self.master_public_key, msg);
        Signature::new(h.as_ref(), s.as_ref()).ok_or(Error::new())
    }
}
