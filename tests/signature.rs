use hex_literal::hex;
use sm9::*;
use std::fs;
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex A: Example of digital signature algorithm
fn test_verify_vector() {
    let m = b"Chinese IBS standard";
    let user_id = b"Alice";
    let sig_hex = hex!(
    "823C4B21 E4BD2DFE 1ED92C60 6653E996 66856315 2FC33F55 D7BFBB9B D9705ADB" // h
    "04 73BF9692 3CE58B6A D0E13E96 43A406D8 EB98417C 50EF1B29 CEF9ADB4 8B6D598C 856712F1 C2E0968A B7769F42 A99586AE D139D5B8 B3E15891 827CC2AC ED9BAA05" // s
    );
    let sig = Signature::try_from(&sig_hex).unwrap();

    assert!(Sm9::verify(
        "master_signature_public_key.pem",
        user_id,
        m,
        &sig
    ));
}
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex A: Example of digital signature algorithm
fn test_signature_verify() {
    let m = b"Chinese IBS standard";
    let user_id = b"Alice";
    let sig = Sm9::sign(
        "master_signature_public_key.pem",
        "alice_signature_private_key.pem",
        m,
    );
    println!("{:02X?}", sig.h_as_ref());
    println!("{:02X?}", sig.s_as_ref());

    assert!(Sm9::verify(
        "master_signature_public_key.pem",
        user_id,
        m,
        &sig
    ));
}
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex A: Example of digital signature algorithm
fn test_signature_verify2() {
    let m = b"Chinese IBS standard";
    let user_id = b"Alice";
    let master_signature_public_key = fs::read_to_string("master_signature_public_key.pem")
        .expect("read master_signature_public_key.pem error");
    let alice_signature_private_key = fs::read_to_string("alice_signature_private_key.pem")
        .expect("read alice_signature_private_key.pem error");
    let sig = Sm9::sign2(
        &master_signature_public_key,
        &alice_signature_private_key,
        m,
    );
    println!("{:02X?}", sig.h_as_ref());
    println!("{:02X?}", sig.s_as_ref());

    assert!(Sm9::verify2(&master_signature_public_key, user_id, m, &sig));
}
