use hex_literal::hex;
use sm9::*;

//----------------------------------------------------------------encryption
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex C: example of key encapsulation mechanism
fn generate_master_private_key_to_pem() {
    // master encryption private key
    let ke = Fn::from_slice(&hex!(
        "0001EDEE 3778F441 F8DEA3D9 FA0ACC4E 07EE36C9 3F9A0861 8AF4AD85 CEDE1C22"
    ))
    .unwrap();
    Sm9::generate_master_private_key_to_pem(&ke, "master_private_key.pem");
}

#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex C: example of key encapsulation mechanism
fn generate_master_public_key_to_pem() {
    Sm9::generate_master_public_key_to_pem("master_private_key.pem", "master_public_key.pem");
}
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex D: Example of public key encryption
fn generate_bob_privte_key_to_pem() {
    let user_id = b"Bob";
    Sm9::generate_user_private_key_to_pem("master_private_key.pem", user_id, "bob_private_key.pem");
}

//----------------------------------------------------------------signature
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex A: Example of digital signature algorithm
fn generate_master_signature_private_key_to_pem() {
    // master signature private key
    let ke = Fn::from_slice(&hex!(
        "000130E7 8459D785 45CB54C5 87E02CF4 80CE0B66 340F319F 348A1D5B 1F2DC5F4"
    ))
    .unwrap();
    Sm9::generate_master_private_key_to_pem(&ke, "master_signature_private_key.pem");
}
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex A: Example of digital signature algorithm
fn generate_master_signature_public_key_to_pem() {
    Sm9::generate_master_signature_public_key_to_pem(
        "master_signature_private_key.pem",
        "master_signature_public_key.pem",
    );
}
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex A: Example of digital signature algorithm
fn generate_alice_signature_private_key_to_pem() {
    let user_id = b"Alice";
    Sm9::generate_user_signature_private_key_to_pem(
        "master_signature_private_key.pem",
        user_id,
        "alice_signature_private_key.pem",
    );
}
