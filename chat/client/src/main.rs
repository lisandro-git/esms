use std::io::{self, ErrorKind, Read, Write, prelude::Read as read_file};
use std::net::TcpStream;
use std::sync::mpsc::{self, TryRecvError, Sender, Receiver};
use std::thread;
use std::time::Duration;
use std::str::from_utf8;
use std::{fs, fs::File};
use std::ops::Deref;
use rand::rngs::OsRng;
use std::io::prelude::Write as w;

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
        let mut buff = String::new();
        io::stdin()
            .read_line(&mut buff)
            .expect("reading from stdin failed");
        let msg =
            buff
            .trim()
            .to_string();
        if msg == ":quit" || tx.send(String::from(&msg)).is_err() { panic!("Cannot send message, exiting program...") }
        else { return msg }
}

fn handle_message_received(client: &mut TcpStream, first_co: &mut bool) -> bool{
    let mut buff = vec![0; MSG_SIZE];
    match client.read_exact(&mut buff) {
        Ok(_) => {
            println!("In 'ok' handle_message_received");
            let msg =
                buff
                    .into_iter()
                    .take_while(|&x| x != 0)
                    .collect::<Vec<_>>();
            if *first_co {
                println!("Connected to -> {} | as -> {}", LOCAL, from_utf8(&msg).unwrap()); // edode : receive IP from server
                *first_co = false;
            } else {
                // lisandro : add screen clearing (carefull to multi-messages)
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

// encryption part
fn generate_random_iv() -> Vec<u8> {
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);
    return iv.to_vec();
}

fn encrypt_msg_aes(msg: &Vec<u8>, iv: &Vec<u8>, key: &Vec<u8>) -> Vec<u8>{
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let mut buffer = [0u8; MSG_SIZE];
    buffer[..msg.len()].copy_from_slice(msg.as_slice());
    return cipher.clone().encrypt(&mut buffer,  msg.len()).unwrap().to_vec();
}
// server: &mut TcpStream
fn send_password_challenge(server: &mut TcpStream) {
    type Aes128Cbc = Cbc<Aes256, Pkcs7>;
    let mut iv = generate_random_iv();
    //println!("before change iv : {:?}", iv);
    let mut server_pass_and_key = String::new();
    println!("Server's password : ");
    io::stdin()
        .read_line(&mut server_pass_and_key)
        .expect("Failed to read line");
    server_pass_and_key.pop();
    let enc_pass = encrypt_msg_aes(&server_pass_and_key.clone().into_bytes(), &iv, &server_pass_and_key.clone().into_bytes());
    iv.extend(enc_pass.as_slice());
    //println!("iv : {:?}", iv);
    //println!("enc_pass : {:?}", enc_pass);
    send_message(server, iv);
}

fn main() {
    //send_password_challenge(&mut server);
    let mut server = handle_connection();
    let mut first_co: bool = true;
    let (tx, rx) = mpsc::channel::<String>();
    send_password_challenge(&mut server);

    thread::spawn(move ||
        loop {
            let disconnect = handle_message_received(&mut server, &mut first_co);
            if disconnect { break }

            match rx.try_recv() {
                Err(TryRecvError::Empty) => ( continue ),
                Ok(msg) => { send_message(&mut server, Vec::from(msg)) },
                Err(TryRecvError::Disconnected) => { break }
            }

            sleep_time(100);
        });
    sleep_time(1000);

    loop {
        let buff = write_message(&tx);
        println!("-> {}", buff)
    }
}















