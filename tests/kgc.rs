use hex_literal::hex;
use sm9::*;

#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex C: example of key encapsulation mechanism
fn encode_master_private_key_to_pem() {
    // master encryption private key
    let ke = Fr::from_slice(&hex!(
        "0001EDEE 3778F441 F8DEA3D9 FA0ACC4E 07EE36C9 3F9A0861 8AF4AD85 CEDE1C22"
    ))
    .unwrap();

    let binding = ke.to_slice();
    let user_key = MasterPrivateKey::new(&binding[..]);

    assert!(user_key
        .write_pem_file(
            "master_private_key.pem",
            MasterPrivateKey::PEM_LABEL,
            LineEnding::CRLF
        )
        .is_ok());
}

#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex C: example of key encapsulation mechanism
fn decode_master_private_key_from_pem() {
    let a =
        MasterPrivateKey::read_pem_file("master_private_key.pem").expect("read_pem_file error!");
    println!("{:02X?}", a);
    assert_eq!(
        a.as_slice(),
        &hex!("0001EDEE 3778F441 F8DEA3D9 FA0ACC4E 07EE36C9 3F9A0861 8AF4AD85 CEDE1C22")
    )
}
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex C: example of key encapsulation mechanism
fn encode_master_public_key_to_pem() {
    Sm9::generate_master_public_key_to_pem("master_private_key.pem", "master_public_key.pem");
}
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex C: example of key encapsulation mechanism
fn decode_master_public_key_from_pem() {
    let a = MasterPublicKey::read_pem_file("master_public_key.pem").unwrap();
    println!("{:02X?}", a);
    let pube = a.to_g1().expect("MasterPublicKey error");
    let b = hex!(
        "787ED7B8 A51F3AB8 4E0A6600 3F32DA5C 720B17EC A7137D39 ABC66E3C 80A892FF"
        "769DE617 91E5ADC4 B9FF85A3 1354900B 20287127 9A8C49DC 3F220F64 4C57A7B1"
    );
    assert_eq!(pube.to_slice(), b);
}
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex D: Example of public key encryption
fn encode_bob_privte_key_to_pem() {
    // master encryption private key
    let ke = Fr::from_slice(&hex!(
        "0001EDEE 3778F441 F8DEA3D9 FA0ACC4E 07EE36C9 3F9A0861 8AF4AD85 CEDE1C22"
    ))
    .unwrap();
    let user_id = b"Bob";
    let hid = 3u8;
    let a = Sm9::hash_1(user_id, hid).unwrap();
    let b = Fr::from_slice(&hex!(
        "9CB1F628 8CE0E510 43CE7234 4582FFC3 01E0A812 A7F5F200 4B85547A 24B82716"
    ))
    .unwrap();
    assert_eq!(a, b);
    let c = Fr::from_slice(&hex!(
        "9CB3E416 C459D952 3CAD160E 3F8DCC11 09CEDEDB E78FFA61 D67A01FF F3964338"
    ))
    .unwrap();
    let t1 = a + ke;
    assert_eq!(t1, c);
    let t2 = ke * t1.inverse().unwrap();
    let d = Fr::from_slice(&hex!(
        "864E4D83 91948B37 535ECFA4 4C3F8D4E 545ADA50 2FF8229C 7C32F529 AF406E06"
    ))
    .unwrap();
    assert_eq!(t2, d);
    // encryption private key of the user
    let de = G2::one() * t2;
    let a = de.to_compressed();
    let user_key = UserPrivateKey::new(&a[..]);
    assert!(user_key
        .write_pem_file(
            "bob_private_key.pem",
            UserPrivateKey::PEM_LABEL,
            LineEnding::CRLF
        )
        .is_ok());
}
#[test]
// test data follow "SM9 identity-based cryptographic algorithms"
// Part 5: Parameter definition
// Annex C: example of key encapsulation mechanism
fn decode_bob_privte_key_from_pem() {
    let a = UserPrivateKey::read_pem_file("bob_private_key.pem").unwrap();
    println!("{:02X?}", a);
    let de = a.to_g2().expect("UserPrivateKey error");
    let b = hex!(
        "94736ACD 2C8C8796 CC4785E9 38301A13 9A059D35 37B64141 40B2D31E ECF41683"
        "115BAE85 F5D8BC6C 3DBD9E53 42979ACC CF3C2F4F 28420B1C B4F8C0B5 9A19B158"
        "7AA5E475 70DA7600 CD760A0C F7BEAF71 C447F384 4753FE74 FA7BA92C A7D3B55F"
        "27538A62 E7F7BFB5 1DCE0870 4796D94C 9D56734F 119EA447 32B50E31 CDEB75C1"
    );
    println!("{:02X?}", de);
    assert_eq!(de.to_slice(), b);
}
