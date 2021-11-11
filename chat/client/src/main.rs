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
use xsalsa20poly1305::XSalsa20Poly1305;
use xsalsa20poly1305::aead::{AeadInPlace, NewAead, generic_array::GenericArray};
use xsalsa20poly1305::aead::heapless::Vec as salsa_v;

use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::ToRsaPublicKey, pkcs8::{FromPrivateKey, FromPublicKey, ToPrivateKey, ToPublicKey}, PaddingScheme, PublicKey, PublicKeyParts};

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 4096;
struct x {}
fn gen_rsa_key_pair(key_lenght: usize) -> std::io::Result<()>{
    let mut rng = OsRng;
    let bits = key_lenght;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let mut file = File::create("/root/.config/esms/key.pri")?;
    file.write_all(private_key.to_pkcs8_pem().unwrap().as_bytes())?;
    let mut file = File::create("/root/.config/esms/key.pub")?;
    file.write_all(public_key.to_public_key_pem().unwrap().as_bytes())?;

    return Ok(());
}

fn read_rsa_keys() -> (RsaPrivateKey, RsaPublicKey){
    let priv_key = fs::read_to_string("/root/.config/esms/1024_key.pri")
        .expect("Something went wrong reading the file");
    let rsa_priv_key = rsa::RsaPrivateKey::from_pkcs8_pem(&priv_key)
        .expect("Cannot read RSA Private Key");

    let pub_key = fs::read_to_string("/root/.config/esms/1024_key.pub")
        .expect("Something went wrong reading the file");
    let rsa_pub_key = rsa::RsaPublicKey::from_public_key_pem(&pub_key)
        .expect("Cannot read RSA Public Key");

    return (rsa_priv_key, rsa_pub_key);
}

fn encrypt_string_salsa(msg: String) -> String{
    let key = GenericArray::from_slice(b"ac example very very secret key.");
    let cipher = XSalsa20Poly1305::new(key);

    let nonce = GenericArray::from_slice(b"extra long unique nonce!"); // 24-bytes; unique

    let mut buffer: salsa_v<u8, 32> = salsa_v::new();
    buffer.extend_from_slice(msg.as_bytes());

    // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
    cipher.encrypt_in_place(nonce, b"", &mut buffer).expect("encryption failure!");

    let x = from_utf8(&buffer);
    println!("x : {:?}", &x);
    let y = x.unwrap();
    println!("y : {}", y);
    return y.to_string();
}

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
    //let mut buff = msg
    //    .clone()
    //    .into_bytes();
    msg.resize(MSG_SIZE, 0);
    server
        .write_all(&msg)
        .expect("writing to socket failed");
}

fn encrypt_chunk(msg: &[u8], server_pub_key: &RsaPublicKey) -> Vec<u8> {
    let mut rng = OsRng;
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let encrypted_chunk = server_pub_key
        .encrypt(&mut rng, padding, (&msg[..]).as_ref())
        .expect("failed to encrypt");
    return encrypted_chunk;
}

fn parse_chunk(k: usize, data: &str, server_pub_key: &RsaPublicKey) -> Vec<u8>{
    let mut msg: Vec<u8> = vec![];
    let mut encrypted_msg:Vec<u8> = vec![];
    let mut i: usize = 0;

    for c in data.as_bytes() {
        if i == k {
            encrypted_msg.extend(encrypt_chunk(&msg[..], &server_pub_key));
            msg.clear();
            i = 0;
        }
        msg.push(*c);
        i+=1;
    }
    encrypted_msg.extend(encrypt_chunk(&msg[..], &server_pub_key));
    return encrypted_msg.to_owned();
}

fn client_server_handshake(server: &mut TcpStream, server_pub_key: RsaPublicKey, client_pub_key: RsaPublicKey) {
    /*
    1 - encrypt client's public key with server's public key (done)
    2 - send encrypted output to server
    3 - server sends AES or Salsa password using client's public key
    4 - client sends password using AES or Salsa password
     */

    let k = server_pub_key.size();
   let data = client_pub_key.to_pkcs1_pem().unwrap();


    let mut enc_data: Vec<u8> = vec![];
    if k == 128 { enc_data = parse_chunk(k-11, &data.as_str(), &server_pub_key) }
    if k == 256 { enc_data = parse_chunk(k-11, &data.as_str(), &server_pub_key) }
    if k == 512 { enc_data = parse_chunk(k-11, &data.as_str(), &server_pub_key) }
    println!("size of msg : {}", enc_data.len());
    println!("size of msg : {:?}", &enc_data[..]);
    send_message(server, enc_data) // 19111999 : shit happens here
}

fn encrypt_msg_aes(cipher: Cbc<Aes128, Pkcs7>, clear_data: &Vec<u8>) -> Vec<u8>{
    let mut buffer = [0u8; 4096];
    let pos = clear_data.len();
    buffer[..pos].copy_from_slice(clear_data.as_slice());
    let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
    return ciphertext.to_vec();
}

fn send_password_challenge(server: &mut TcpStream) {
    type Aes128Cbc = Cbc<Aes128, Pkcs7>;

    println!("Please input your guess.");
    let mut client_pass = String::new();
    io::stdin()
        .read_line(&mut client_pass)
        .expect("Failed to read line");

    client_pass
        .pop()
        .unwrap()
        .to_string();
    let key = client_pass.clone().into_bytes();
    //let key: Vec<u8> = b"Hello world!5555".to_vec();
    //let server_pass = b"Hello world!5555".to_vec();
    let iv = b"1111111111111111";

    let cipher = Aes128Cbc::new_from_slices(&key.as_slice(), &iv.to_vec().as_slice()).unwrap();
    println!("{}", client_pass);
    // encrypt
    let mut enc_data = encrypt_msg_aes(cipher.clone(), &client_pass.into_bytes());
    println!("{:?}", enc_data);
    println!("{}", enc_data.len());
    send_message(server, enc_data);
}
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
fn main() {
    /*
    let server_public_key:RsaPublicKey;
    {
        let server_public_key_string = String::from("\
    -----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkAp5Wm5Tn7z6V7BwRp9NHcZMs
NJ7MEZDcVYffRbhHrk8Jf4oWOMWUjTyhD1BJHmsoTKqsRQllV08aZJs2FOCtTaFl
uN2aOWbsfHgD0sB990zjn+k/ax/eXCF/nLFSz3i+lJi3kdsCWGoljMqIomYwdhDz
vgKW+pgwYOKsqtpaEwIDAQAB
-----END PUBLIC KEY-----");
        server_public_key = rsa::RsaPublicKey::from_public_key_pem(&server_public_key_string).unwrap();
    }
    */
    let mut server = handle_connection();
    let mut first_co: bool = true;
    let (tx, rx) = mpsc::channel::<String>();
    send_password_challenge(&mut server);
    //let (priv_key, pub_key) = read_rsa_keys();
    //client_server_handshake(&mut server, server_public_key, pub_key);

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















