use sm9::*;
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
