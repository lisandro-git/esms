use std::io::{self, ErrorKind, Read, Write, prelude::Read as read_file};
use std::net::TcpStream;
use std::sync::mpsc::{self, TryRecvError, Sender, Receiver};
use std::thread;
use std::time::Duration;
use std::str::from_utf8;
use std::{fs, fs::File};

use rand::rngs::OsRng;

use xsalsa20poly1305::XSalsa20Poly1305;
use xsalsa20poly1305::aead::{AeadInPlace, NewAead, generic_array::GenericArray};
use xsalsa20poly1305::aead::heapless::Vec as salsa_v;

use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{FromPrivateKey, FromPublicKey, ToPrivateKey, ToPublicKey}};

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 32;

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

fn encrypt_string(msg: String) -> String{
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

fn send_message(server: &mut TcpStream, rx: &Receiver<String>) {
    match rx.try_recv() {
        Ok(msg) => {
            let mut buff = msg
                .clone()
                .into_bytes();
            buff.resize(MSG_SIZE, 0);
            server
                .write_all(&buff)
                .expect("writing to socket failed");
        },

        Err(TryRecvError::Empty) => (),
        Err(TryRecvError::Disconnected) => {}
    }
}

fn read_rsa_keys() -> (RsaPrivateKey, RsaPublicKey){
    let priv_key = fs::read_to_string("/root/.config/esms/key.pri")
        .expect("Something went wrong reading the file");
    let rsa_priv_key = rsa::RsaPrivateKey::from_pkcs8_pem(&priv_key)
        .expect("Cannot read RSA Private Key");

    let pub_key = fs::read_to_string("/root/.config/esms/key.pub")
        .expect("Something went wrong reading the file");
    let rsa_pub_key = rsa::RsaPublicKey::from_public_key_pem(&pub_key)
        .expect("Cannot read RSA Public Key");

    return (rsa_priv_key, rsa_pub_key);
}

fn main() {
    let (priv_key, pub_key) = read_rsa_keys();
    let mut server = handle_connection();
    let mut first_co: bool = true;
    let (tx, rx) = mpsc::channel::<String>();


    thread::spawn(move ||
        loop {
            let disconnect = handle_message_received(&mut server, &mut first_co);
            if disconnect { break }

            send_message(&mut server, &rx);
            sleep_time(100);
        });
    sleep_time(1000);

    loop {
        let buff = write_message(&tx);
        println!("-> {}", buff)
    }
}















