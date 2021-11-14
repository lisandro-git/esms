use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, TryRecvError, Sender};
use std::thread;
use std::time::Duration;
use std::str::from_utf8;
use rand::rngs::OsRng;

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::RngCore;

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 4096;
const IV_LEN: usize = 16;

fn sleep_time(time: u64){
    thread::sleep(Duration::from_millis(time));
}

fn handle_connection() -> TcpStream {
    let client =
        TcpStream::connect(LOCAL)
            .expect("Stream failed to connect");
    client
        .set_nonblocking(true)
        .expect("failed to initiate non-blocking");
    return client
}

fn write_message(tx: &Sender<String>) -> String {
    loop {
        let mut buff = String::new();
        io::stdin()
            .read_line(&mut buff)
            .expect("reading from stdin failed");
        let msg =
            buff
            .trim()
            .to_string();
        if msg == "" { continue }
        else if msg == ":quit" || tx.send(String::from(&msg)).is_err() {
            panic!("Cannot send message, exiting program...")
        } else { return msg }
    }
}

fn handle_message_received(client: &mut TcpStream, first_co: &mut bool, key: &Vec<u8>) -> bool{
    let mut buff = vec![0; MSG_SIZE];
    match client.read_exact(&mut buff) {
        Ok(_) => {
            let msg =
                buff
                    .into_iter()
                    .collect::<Vec<_>>();
            let msg = decrypt_msg_aes(msg, key);
            if *first_co {
                println!("Connected to -> {} | as -> {}", LOCAL, from_utf8(&msg).unwrap()); // edode : receive IP from server
                *first_co = false;
            } else {
                println!("-> {}", from_utf8(&msg).unwrap());
            }
        },
        Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
        Err(_) => {
            println!("connection with server was severed");
            return true;
        }
    }
    return false;
}

fn send_message(server: &mut TcpStream, mut msg: Vec<u8>) {
    msg.resize(MSG_SIZE, 0);
    server
        .write_all(&msg)
        .expect("writing to socket failed");
}

fn generate_random_iv() -> Vec<u8> {
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);
    return iv.to_vec();
}

fn add_iv_and_encrypted_msg(iv: Vec<u8>, enc_msg: &Vec<u8>) -> Vec<u8> {
    // merge the IV and the encrypted message to a single message that will be sent afterward

    let total_msg_len = iv.len() + enc_msg.len();
    let mut msg_len: usize= 0;
    // edode : creating an array of <total_msg_len> containing only zeros
    let mut res = std::iter::repeat(0).take(total_msg_len).collect::<Vec<_>>();

    for i in iv.iter(){
        res[msg_len] = *i;
        msg_len+=1;
    }
    for i in enc_msg.iter(){
        if msg_len == MSG_SIZE || msg_len == total_msg_len {
            break;
        }
        res[msg_len] = *i;
        msg_len+=1;
    }
    return res.to_owned();
}

fn encrypt_message(msg: &Vec<u8>, key: &Vec<u8>) -> Vec<u8>{
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    let iv = generate_random_iv();
    let cipher = match Aes256Cbc::new_from_slices(&key, &iv) {
        Ok(cipher) => cipher,
        Err(err) => panic!("{}", err)
    };
    let mut buffer = [0u8; MSG_SIZE];
    buffer[.. msg.len()].copy_from_slice(msg.as_slice());

    let enc_data = match cipher.encrypt(&mut buffer, msg.len()) {
        Ok(enc_data) => enc_data.to_vec(),
        Err(err) => {
            println!("Could not encrypt message : {:?}", err);
            return b"".to_vec();
        }
    };
    return add_iv_and_encrypted_msg(iv.clone(), &enc_data).to_owned();
}

fn get_iv(text: Vec<u8>) -> (Vec<u8>, Vec<u8>){
    // Separate the IV and the Data from the receivec string

    let new_text = remove_trailing_zeros(&mut text.to_owned());
    let mut i:usize = 0;
    let mut iv:Vec<u8> = vec![];
    let mut data:Vec<u8> = vec![];
    for t in new_text.iter(){
        if i >= IV_LEN{
            data.push(*t);
        } else {
            iv.push(*t);
            i += 1;
        }
    }
    return (iv, data);
}

fn remove_trailing_zeros(data: &mut Vec<u8>) -> Vec<u8> {
    // Used to remove the zeros at the end of the received encrypted message
    // but not inside the message (purpose of the 'keep_push' var

    let mut transit:Vec<u8> = vec![];
    let mut res:Vec<u8> = vec![];
    let mut keep_push = false;
    for d in data.iter().rev() {
        if *d == 0 && !keep_push{
            continue;
        } else {
            transit.push(*d);
            keep_push = true;
        }
    }
    for t in transit.iter().rev() {
        res.push(*t);
    }
    return res.to_owned();
}

fn decrypt_msg_aes(msg: Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let (iv, mut enc_data) = get_iv(msg);
    let mut zero: Vec<u8> = vec![0];
    let cipher = match Aes256Cbc::new_from_slices(&key, &iv) {
        Ok(cipher) => cipher,
        Err(err) => panic!("{}", err)
    };
    enc_data = remove_trailing_zeros(&mut enc_data);
    for i in 0..2{
        match cipher.clone().decrypt(&mut enc_data) {
            Ok(decrypted_data) => {
                return decrypted_data.to_vec();
            },
            Err(err) => {
                if i == 1{
                    println!("An error as occured : {:?}", err);
                    return b"".to_vec();
                }
            }
        };
        enc_data.append(&mut zero);
    }
    return b"".to_vec();
}

fn encrypt_and_send_message(server: &mut TcpStream, msg: Vec<u8>, key: &Vec<u8>){
    let enc_pass = encrypt_message(&msg,  &key);
    send_message(server, enc_pass);
}

fn send_password_challenge(server: &mut TcpStream) -> Vec<u8> {
    let mut server_pass_and_key = String::new();

    println!("Server's password : ");
    io::stdin()
        .read_line(&mut server_pass_and_key)
        .expect("Failed to read line");
    server_pass_and_key.pop(); // edode : remove the \n at the end of the script

    let enc_pass = encrypt_message(&server_pass_and_key.clone().into_bytes(),  &server_pass_and_key.clone().into_bytes());

    send_message(server, enc_pass);
    return server_pass_and_key.into_bytes().to_owned();
}

fn main() {
    //send_password_challenge(&mut server);
    let mut server = handle_connection();
    let mut first_co: bool = true;
    let (tx, rx) = mpsc::channel::<String>();
    let key = send_password_challenge(&mut server);

    thread::spawn(move ||
        loop {
            let disconnect = handle_message_received(&mut server, &mut first_co, &key);
            if disconnect { break }

            match rx.try_recv() {
                Err(TryRecvError::Empty) => ( continue ),
                Ok(msg) => {
                    //println!("message received : {}", msg);
                    encrypt_and_send_message(&mut server, msg.into_bytes(), &key);
                },
                Err(TryRecvError::Disconnected) => { break }
            }
            //sleep_time(1000);
        });
    sleep_time(1000);

    loop {
        write_message(&tx);
    }
}















