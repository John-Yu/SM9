use rand::rng;
// establishing secrets between peers.
use sm9::*;

#[test]
fn test_key_encapsulation() {
    let mpk = MasterPublicKey::read_pem_file("master_public_key.pem")
        .expect("read master_public_key_file error");
    let mut pk_recip: <Sm9EncappedKey as EncappedKey>::RecipientPublicKey = [0u8; 128].into();
    let usr_id = b"Bob";
    pk_recip[..3].copy_from_slice(usr_id);
    let mut rng = rng();
    let (ek, ss1) = mpk.try_encap(&mut rng, &pk_recip).unwrap();
    println!("Sm9EncappedKey:{:02X?}", ek.as_ref());
    println!("Sm9SharedSecret:{:02X?}", ss1.as_bytes());
    // now keep the SharedSecret, and send EncappedKey to peer. he will get the same SharedSecret
    let upk = UserPrivateKey::read_pem_file("bob_private_key.pem")
        .expect("read user_privte_key_file error");
    let ss2 = upk.try_decap(&ek).unwrap();
    // the SharedSecrets should be equal
    assert_eq!(ss1.as_bytes(), ss2.as_bytes());
}
