use rpassword::prompt_password;
use std::{
    env::args,
    fs::{read, write, remove_file},
};
use tindercrypt::cryptors::RingCryptor;

const ENCRYPTED_FILE_SUFFIX: &str = "_enc";

enum Action {
    Encrypt,
    Decrypt,
}

fn main() {
    let args: Vec<String> = args().collect();

    let input = if !args[1..].is_empty() {
        args[1..].join(" ")
    } else {
        println!("Usage: file-encryptor FILE");
        return;
    };

    println!("File: {}", input);

    let contents = match read(input.clone()) {
        Ok(s) => s,
        Err(e) => {
            println!("Got an error when opening file: {}", e.to_string());
            return;
        }
    };

    let action = if input.clone().ends_with(ENCRYPTED_FILE_SUFFIX) {
        println!("File ends with `{ENCRYPTED_FILE_SUFFIX}`, attempting to decrypt.");
        (
            Action::Decrypt,
            input
                .strip_suffix(ENCRYPTED_FILE_SUFFIX)
                .expect("Failed to remove suffix from file name")
                .to_owned(),
        )
    } else {
        println!("File does not end with `{ENCRYPTED_FILE_SUFFIX}`, attempting to encrypt.");
        (Action::Encrypt, input.clone() + ENCRYPTED_FILE_SUFFIX)
    };

    let password = prompt_password("Password: ").unwrap();
    let cryptor = RingCryptor::new();
    let data = if matches!(action.0, Action::Decrypt) {
        match cryptor.open(password.as_bytes(), contents.as_slice()) {
            Ok(d) => d,
            Err(e) => {
                println!(
                    "Got an error when decrypting (password might be incorrect): {}",
                    e.to_string()
                );
                return;
            }
        }
    } else if matches!(action.0, Action::Encrypt) {
        match cryptor.seal_with_passphrase(password.as_bytes(), contents.as_slice()) {
            Ok(d) => d,
            Err(e) => {
                println!("Got an error when encrypting: {}", e.to_string());
                return;
            }
        }
    } else {
        panic!("action is not encrypt or decrypt")
    };

    drop(password);
    drop(contents);

    write(action.1.as_str(), data).expect("Failed to write data to file!");

    println!(
        "Successfully {} {} to {}!",
        if matches!(action.0, Action::Decrypt) {
            "decrypted"
        } else {
            "encrypted"
        },
        input.clone(),
        action.1
    );

    if matches!(action.0, Action::Encrypt) {
        println!("Deleting {}", input.clone());
        remove_file(input).expect("Failed to delete file");
        println!("Success!");
    }
}
