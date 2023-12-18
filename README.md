# SM9

Pure Rust implementation of the [SM9](https://en.wikipedia.org/wiki/SM9_(cryptography_standard)) identity-based cryptographic algorithms as defined in the Chinese national standard GM/T 0044-2016 as well as [ISO/IEC 11770](https://www.iso.org/standard/82709.html).

## Usage

Add the `sm9` crate to your dependencies in `Cargo.toml`...

```toml
[dependencies]
sm9 = "0.2.0"
```

...and add an `extern crate` declaration to your crate root:

```rust
extern crate sm9;
```

### Examples

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
```

(See `signature.rs` for the full example.)

```rust
    use sm9::*;
    
    let m = b"Chinese IBS standard";
    let user_id = b"Alice";
    let (h, s) = Sm9::sign(
        "master_signature_public_key.pem",
        "alice_signature_private_key.pem",
        m,
    );
    println!("{:02X?}", h);
    println!("{:02X?}", s);
    assert!(Sm9::veriry("master_signature_public_key.pem", user_id, m, (h, s)));
```

## License

Licensed under either of

* [MIT license](http://opensource.org/licenses/MIT)
* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

at your option.

Copyright 2023 [John-Yu](https://github.com/John-Yu).

### Authors

* [John-Yu](https://github.com/John-Yu)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.