use sm9::*;

#[test]
fn test_encrypt_decrypt() {
    // SM9 identity-based cryptographic algorithms
    // Part 5: Parameter definition
    // Annex D: Example of public key encryption
    let usr_id = b"Bob";
    let txt = b"Chinese IBE standard";
    let m = Sm9::encrypt("master_public_key.pem", usr_id, txt);
    println!("{:02X?}", m);

    let msg = Sm9::decrypt("bob_private_key.pem", usr_id, m).expect("decrypt error");
    println!("{:02X?}", msg);
    assert_eq!(msg.len(), txt.len());
    assert_eq!(txt, msg.as_slice());
}
