use arbitrary::{Arbitrary, Unstructured};
use encryptor::{Argon2Config, derive_key, encrypt_decrypt, encrypt_decrypt_in_place};
use libfuzzer_sys::fuzz_target;
#[cfg(feature = "afl")]
use afl::fuzz;

#[derive(Debug)]
struct FuzzInput {
    password: String,
    salt: [u8; 16],
    nonce: [u8; 12],
    data: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let password = String::arbitrary(u)?;
        let mut salt = [0u8; 16];
        u.fill_buffer(&mut salt)?;
        let mut nonce = [0u8; 12];
        u.fill_buffer(&mut nonce)?;
        let data = Vec::<u8>::arbitrary(u)?;
        Ok(Self {
            password,
            salt,
            nonce,
            data,
        })
    }
}

fn process_input(input: FuzzInput) {
    let cfg = Argon2Config::default();
    let key = match derive_key(&input.password, &input.salt, &cfg) {
        Ok(k) => k,
        Err(_) => return,
    };

    let mut buf = input.data.clone();
    let mut counter = 1u32;
    encrypt_decrypt_in_place(&mut buf, &key, &input.nonce, &mut counter);
    counter = 1u32;
    encrypt_decrypt_in_place(&mut buf, &key, &input.nonce, &mut counter);
    assert_eq!(buf, input.data);

    let ct = encrypt_decrypt(&input.data, &key, &input.nonce);
    let pt = encrypt_decrypt(&ct, &key, &input.nonce);
    assert_eq!(pt, input.data);
}

fuzz_target!(|input: FuzzInput| { process_input(input) });

#[cfg(feature = "afl")]
fn main() {
    fuzz!(|data: FuzzInput| {
        process_input(data);
    });
}

