use clap::{arg, command};
use cwd::cwd;
use rfd::FileDialog;
use rpassword::prompt_password;
use std::{
    fs::{read, remove_file, write},
    io::{stdin, stdout, Read, Write},
    process::exit,
};
use tindercrypt::cryptors::RingCryptor;

enum Action {
    Encrypt,
    Decrypt,
}

fn enter_to_exit() {
    let mut stdout = stdout();

    write!(stdout, "Press Enter to exit...").unwrap();
    stdout.flush().unwrap();

    stdin().read(&mut [0u8]).unwrap();
}

fn main() {
    let args = command!()
        .arg(
            arg!([FILE] "File to encrypt/decrypt. If the file name ends with `_enc`, it will default to decryption. Otherwise, it will encrypt and then delete the file.")
        )
        .arg(
            arg!(-n --"no-delete" "If specified, the file won't be deleted after encrypting it.")
            .required(false)
        )
        .arg(
            arg!(-e --"force-encrypt" "If specified, the file will be encrypted, even if the file name ends with `_enc`.")
            .required(false)
            .conflicts_with("force-decrypt")
        )
        .arg(
            arg!(-d --"force-decrypt" "If specified, the file will be decrypted, even if the file name doesn't ends with `_enc`. The output file name will have `_dec` appended.")
            .required(false)
            .conflicts_with("force-encrypt")
        )
        .get_matches();

    let input = match args.get_one::<String>("FILE") {
        Some(s) => s.to_owned(),
        None => {
            println!("FILE argument not specified, opening a file dialog.");
            match FileDialog::new().set_directory(cwd()).pick_file() {
                Some(p) => p.to_str().unwrap().to_owned(),
                None => {
                    println!("No file chosen.");
                    enter_to_exit();
                    exit(1);
                }
            }
        }
    };

    println!("Input file: {}", input);

    let contents = match read(&input) {
        Ok(s) => s,
        Err(e) => {
            println!("Got an error when opening input file: {}", e.to_string());
            enter_to_exit();
            return;
        }
    };

    let action = if args.get_flag("force-decrypt") {
        println!("force-decrypt specified, attempting to decrypt.");
        Action::Decrypt
    } else if args.get_flag("force-encrypt") {
        println!("force-encrypt specified, attempting to encrypt.");
        Action::Encrypt
    } else if input.ends_with("_enc") {
        println!("Input file ends with `_enc`, attempting to decrypt.");
        Action::Decrypt
    } else {
        println!("Input file does not end with `_enc`, attempting to encrypt.");
        Action::Encrypt
    };

    let output = match action {
        Action::Decrypt => match input.strip_suffix("_enc") {
            Some(s) => s.to_owned(),
            None => {
                if !args.get_flag("force-decrypt") {
                    println!("Failed to remove _enc suffix from input file name. Using original input file name");
                    input.to_owned()
                } else {
                    input.to_owned() + "_dec"
                }
            }
        },
        Action::Encrypt => input.to_owned() + "_enc",
    };

    let password = prompt_password("Password: ").unwrap();
    let cryptor = RingCryptor::new();
    let data = match action {
        Action::Decrypt => match cryptor.open(password.as_bytes(), contents.as_slice()) {
            Ok(d) => d,
            Err(e) => {
                println!(
                    "Got an error when decrypting (password might be incorrect): {}",
                    e.to_string()
                );
                enter_to_exit();
                return;
            }
        },
        Action::Encrypt => {
            match cryptor.seal_with_passphrase(password.as_bytes(), contents.as_slice()) {
                Ok(d) => d,
                Err(e) => {
                    println!("Got an error when encrypting: {}", e.to_string());
                    enter_to_exit();
                    return;
                }
            }
        }
    };

    drop(password);
    drop(contents);

    match write(&output, data) {
        Ok(_) => {}
        Err(e) => {
            println!(
                "Got an error when writing to output file ({}): {}",
                &output,
                e.to_string()
            );
            enter_to_exit();
            return;
        }
    }

    println!(
        "Successfully {} {} to {}!",
        match action {
            Action::Decrypt => "decrypted",
            Action::Encrypt => "encrypted",
        },
        &input,
        &output
    );

    if matches!(action, Action::Encrypt) {
        if args.get_flag("no-delete") {
            println!("Skipping input file deletion because no-delete was specified");
        } else {
            println!("Deleting input file {}", &input);
            match remove_file(&input) {
                Ok(_) => {}
                Err(e) => {
                    println!(
                        "Got an error when deleting input file ({}): {}",
                        &input,
                        e.to_string()
                    );
                    enter_to_exit();
                    return;
                }
            }
            println!("Success!");
        }
    }

    enter_to_exit();
}
