# SM9

Pure Rust implementation of the [SM9](https://en.wikipedia.org/wiki/SM9_(cryptography_standard)) identity-based cryptographic algorithms as defined in the Chinese national standard GM/T 0044-2016 as well as [ISO/IEC 11770](https://www.iso.org/standard/82709.html).

## Usage

Add the `sm9` crate to your dependencies in `Cargo.toml`

```toml
[dependencies]
sm9 = "0.3.2"
```

### Examples

#### Example1: Encrypt
(See `encryption.rs` for the full example.)

```rust
    use sm9::*;

    let usr_id = b"Bob";
    let txt = b"Chinese IBE standard";
    let m = Sm9::encrypt("master_public_key.pem", usr_id, txt);
    println!("{:02X?}", m);

    let msg = Sm9::decrypt("bob_private_key.pem", usr_id, m).expect("decrypt error");
    println!("{:02X?}", msg);
    assert_eq!(msg.len(), txt.len());
    assert_eq!(txt, msg.as_slice());

    use std::fs;
    let master_public_key =
        fs::read_to_string("master_public_key.pem").expect("read master_public_key.pem error");
    let m = Sm9::encrypt2(&master_public_key, usr_id, txt);
    println!("{:02X?}", m);

    let bob_private_key =
        fs::read_to_string("bob_private_key.pem").expect("read bob_private_key.pem error");
    let msg = Sm9::decrypt2(&bob_private_key, usr_id, m).expect("decrypt error");
    println!("{:02X?}", msg);
    assert_eq!(msg.len(), txt.len());
    assert_eq!(txt, msg.as_slice());

```

#### Example2: Signature
(See `signature.rs` for the full example.)

```rust
    use sm9::*;
    
    //Sign
    let m = b"Chinese IBS standard";
    let user_id = b"Alice";
    let sig = Sm9::sign(
        "master_signature_public_key.pem",
        "alice_signature_private_key.pem",
        m,
    );
    println!("{:02X?}", sig.h_as_ref());
    println!("{:02X?}", sig.s_as_ref());

    //Verify
    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(sig.h_as_ref());
    bytes.extend_from_slice(sig.s_as_ref());
    let sig_rev = Signature::from_slice(bytes.as_ref()).unwrap();
    assert!(Sm9::verify(
        "master_signature_public_key.pem",
        user_id,
        m,
        &sig_rev
    ));

    use std::fs;
    let master_signature_public_key = fs::read_to_string("master_signature_public_key.pem")
        .expect("read master_signature_public_key.pem error");
    let alice_signature_private_key = fs::read_to_string("alice_signature_private_key.pem")
        .expect("read alice_signature_private_key.pem error");
    let sig = Sm9::sign2(
        &master_signature_public_key,
        &alice_signature_private_key,
        m,
    );

    assert!(Sm9::verify2(&master_signature_public_key, user_id, m, &sig));

```

#### Example3: Key Exchange 
(See `exchange.rs` for the full example.)

```rust
use sm9::*;
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
    assert_eq!(ska, skb);
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
```
## License

Licensed under either of

* [MIT license](http://opensource.org/licenses/MIT)
* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

at your option.

Copyright 2024 [John-Yu](https://github.com/John-Yu).

### Authors

* [John-Yu](https://github.com/John-Yu)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
