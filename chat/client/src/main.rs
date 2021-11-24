use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener,TcpStream,SocketAddr};
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
const MAX_MSG_SIZE: usize = 4096;
const iv: &[u8; 16] = b"1243154275471243";
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

fn handle_incomming_msg(server:&mut TcpStream, address: &mut bool, key: &Vec<u8>) -> bool{
    let mut buffer =vec![0; MAX_MSG_SIZE];

    match server.read_exact(&mut buffer) {
        Ok(_) => {
            let MSG =buffer.into_iter().collect::<Vec<_>>();
            println!("recv enc_msg{:?}", MSG);
            let (x, y) = decrypt_message(MSG, key);
            println!("recv dec_msg{:?}",from_utf8(&x).unwrap().to_string());
            return false; // if buffer is not empty return msg and bool to specify whether client is disconnected.
        },
        Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
        Err(err) => {
            println!("closing connection with: {}, {}", address, err);
            return true;
        }
    }
    return true; // client disconnected
}

fn send_message(server: &mut TcpStream, mut msg: Vec<u8>) {
    msg.resize(MAX_MSG_SIZE, 0);
    server
        .write_all(&msg)
        .expect("writing to socket failed");
}
fn encrypt_message(message:Vec<u8>, key:&Vec<u8>) -> Vec<u8>{
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    // let iv = generate_random_iv(); // random iv to make the message hard to decipher.
    // creating cipher:
    let cipher_text = match Aes256Cbc::new_from_slices(&key,iv){
        Ok(cipher_text) => cipher_text,
        Err(err)=>panic!(" Error : \n {}",err)
    };

    let mut buffer = [0u8; MAX_MSG_SIZE]; // Creating a buffer to store the
    buffer[.. message.len()].copy_from_slice(message.as_slice());

    let encoded_data = match cipher_text.encrypt(&mut buffer, message.len()) {
        Ok(encoded_data) => encoded_data.to_vec(),
        Err(error)=>{
            println!("Failed message encryption : {:?}",error);
            return b"".to_vec();
        }
    };
    println!("sent_msg : {:?}", encoded_data);
    return encoded_data.to_owned();
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
fn unpadding(data: &mut Vec<u8>) -> Vec<u8>{
    // Removing unwanted zeros at the end of the payload.
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
fn decrypt_message(mut message:Vec<u8>, key:&Vec<u8>) -> (Vec<u8>, bool){
    let mut message = unpadding(&mut message);
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let cipher = match Aes256Cbc::new_from_slices(&key, iv) {
        Ok(cipher) => {cipher},
        Err(err) => {
            println!("decrypt err : {}", err);
            return (b"".to_vec(), false)
        }
    };
    match cipher.decrypt(&mut message) {
        Ok(decrypted_data) => {
            println!("decrypted data : {:?}",decrypted_data);
            return (decrypted_data.to_vec(), true);
        }
        Err(err) => {
            println!("An error as occured : {:?}", err);
            return (b"".to_vec(), false);
        }
    };
}

fn encrypt_and_send_message(server: &mut TcpStream, msg: Vec<u8>, key: &Vec<u8>){
    let enc_pass = encrypt_message(msg,  &key);
    send_message(server, enc_pass);
}

fn send_password_challenge(server: &mut TcpStream) -> Vec<u8> {
    let mut server_pass_and_key = String::new();

    println!("Server's password : ");
    io::stdin()
        .read_line(&mut server_pass_and_key)
        .expect("Failed to read line");
    server_pass_and_key.pop();

    let enc_pass = encrypt_message(server_pass_and_key.clone().into_bytes(),  &server_pass_and_key.clone().into_bytes());

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
            let disconnect = handle_incomming_msg(&mut server, &mut first_co, &key);
            if disconnect {
                break
            }
            match rx.try_recv() {
                Err(TryRecvError::Empty) => {
                    println!("No message received");
                }
                Ok(msg) => {
                    println!("message received : {}", msg);
                    encrypt_and_send_message(&mut server, msg.into_bytes(), &key);
                },
                Err(TryRecvError::Disconnected) => {
                    break
                }
            }
            //sleep_time(1000);
        });
    sleep_time(1000);

    loop {
        write_message(&tx);
    }
}















