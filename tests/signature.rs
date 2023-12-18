use sm9::*;
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex A: Example of digital signature algorithm
fn test_signature_verity() {
    let m = b"Chinese IBS standard";
    let user_id = b"Alice";
    let (h, s) = Sm9::sign(
        "master_signature_public_key.pem",
        "alice_signature_private_key.pem",
        m,
    );
    println!("{:02X?}", h);
    println!("{:02X?}", s);
    assert!(Sm9::veriry(
        "master_signature_public_key.pem",
        user_id,
        m,
        (h, s)
    ));
}
