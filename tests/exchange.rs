// Key exchange protocol process
// SM9 identity-based cryptographic algorithms
// Part 3: Key exchange protocol
// 6.2 Key exchange process

use sm9::*;

#[test]
fn test_key_exchange() {
    let mpk = MasterPublicKey::read_pem_file("master_exchange_public_key.pem")
        .expect("read master_public_key_file error");
    let alice_id = b"Alice";
    let alice_key = UserPrivateKey::read_pem_file("alice_exchange_private_key.pem")
        .expect("read user_privte_key_file error");
    let bob_id = b"Bob";
    let bob_key = UserPrivateKey::read_pem_file("bob_exchange_private_key.pem")
        .expect("read user_privte_key_file error");
    // the initiator A
    let mut initiator = KeyExchanger::new(alice_id, &alice_key, &mpk, true).unwrap();
    // the responder B
    let mut responder = KeyExchanger::new(bob_id, &bob_key, &mpk, false).unwrap();
    // A Step 3: compute 𝑅𝐴
    let ra = initiator.generate_ephemeral_secret(bob_id).unwrap();
    // A Step 4: send 𝑅𝐴 to B

    // B Step 3: compute 𝑅B
    let rb = responder.generate_ephemeral_secret(alice_id).unwrap();
    //  B Step 4: send 𝑅B to A
    // A compute shared_secret use received rb
    let rb_received = EphemeralSecret::from_slice(rb.as_slice());
    let ska = initiator.generate_shared_secret(&rb_received).unwrap();
    // B compute shared_secret use received ra
    let ra_received = EphemeralSecret::from_slice(ra.as_slice());
    let skb = responder.generate_shared_secret(&ra_received).unwrap();
    // B Step 6: (optional) compute SB, and send it to A
    let sb = responder.generate_comfirmable_secret().unwrap();
    // A (optional) confirmation from B to A
    let sb_received = ComfirmableSecret::from_slice(sb.as_slice());
    let confirmation_a = initiator.comfirm(&sb_received).unwrap();
    // A Step 8: (optional) compute 𝑆𝐴, and send it to B,
    let sa = initiator.generate_comfirmable_secret().unwrap();
    // B (optional) confirmation from A to B
    let sa_received = ComfirmableSecret::from_slice(sa.as_slice());
    let confirmation_b = responder.comfirm(&sa_received).unwrap();
    assert!(confirmation_a);
    assert!(confirmation_b);
    assert_eq!(ska, skb);
}
