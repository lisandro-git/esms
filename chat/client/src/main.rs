use std::convert::TryFrom;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, TryRecvError, Sender};
use std::thread;
use std::time::Duration;
use std::str::from_utf8;
use std::thread::spawn;
use rand::rngs::OsRng;

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::RngCore;

use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 4096;
const IV_LEN: usize = 16;
const USERNAME_LENGTH: usize = 10;

struct User {
    connection: TcpStream,
    first_connection: bool,
    connected: bool,
    authenticated: bool,
    MSG: Message,
}
impl User {
    fn new(con: TcpStream) -> User {
        User {
            connection: con,
            first_connection: true,
            connected: false,
            authenticated: false,
            MSG: Message::new(vec![], vec![]),
        }
    }
    fn delete(&mut self) {
        self.connection.shutdown(std::net::Shutdown::Both).unwrap();
        self.first_connection = false;
        self.connected = false;
        self.authenticated = false;
        self.MSG.delete();
    }
    fn clone(&self) -> User {
        User {
            connection: self.connection.try_clone().unwrap(),
            first_connection: self.first_connection,
            connected: self.connected,
            authenticated: self.authenticated,
            MSG: self.MSG.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Message {
    username: Vec<u8>,
    data: Vec<u8>,
}

impl Message {
    fn new(username: Vec<u8>, data: Vec<u8>) -> Message {
        Message {
            username,
            data,
        }
    }
    fn delete(&mut self) {
        self.username.clear();
        self.data.clear();
    }
    fn clone(&self) -> Message {
        Message {
            username: self.username.clone(),
            data: self.data.clone(),
        }
    }
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
        } else {
            return msg
        }
    }
}

fn handle_message_received<'a>(U: &'a mut User) -> &'a mut User{
    let mut buff = vec![0; MSG_SIZE];
    match U.connection.read_exact(&mut buff) {
        Ok(_) => {
            U.MSG.data = buff.into_iter().collect::<Vec<_>>();
            if U.first_connection {
                println!("Connected to -> {} | as -> {} : ({})", LOCAL, from_utf8(&U.MSG.data).unwrap(), from_utf8(&U.MSG.username).unwrap());
                U.first_connection = false;
                U.authenticated = true;
            } else {
                println!("{} -> {}", from_utf8(&U.MSG.username).unwrap(), from_utf8(&U.MSG.data).unwrap());
            };
            return U;
        },
        Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
        Err(_) => {
            println!("connection with server was severed");
            U.connected = false;
        }
    }
    return U;
}

fn send_message(server: &mut TcpStream, data: &mut Vec<u8>) {
    data.resize(MSG_SIZE, 0);
    server
        .write_all(data)
        .expect("writing to socket failed");
}

fn generate_random_iv() -> Vec<u8> {
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);
    return iv.to_vec();
}

fn encrypt_message(iv: Vec<u8>, data: &Message, key: &Vec<u8>) -> Vec<u8> {
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    let cipher = match Aes256Cbc::new_from_slices(&key, &iv) {
        Ok(cipher) => cipher,
        Err(err) => panic!("{}", err)
    };
    let ser_data = serialize_data(data);
    let mut buffer = [0u8; MSG_SIZE];
    buffer[.. ser_data.len()].copy_from_slice(ser_data.as_slice());

    let enc_data = match cipher.encrypt(&mut buffer, ser_data.len()) {
        Ok(enc_data) => enc_data.to_vec(),
        Err(err) => {
            println!("Could not encrypt message : {:?}", err);
            return Vec::new();
        }
    };
    return enc_data;
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

fn decrypt_message<'a>(M: &'a mut Message, key: &'a Vec<u8>) -> &'a mut Message {
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let iv = &M.data[0..IV_LEN];

    let cipher = match Aes256Cbc::new_from_slices(&key, iv) {
        Ok(cipher) => cipher,
        Err(err) => panic!("{}", err)
    };

    let mut enc_data = remove_trailing_zeros(&mut M.data);
    let x = match cipher.clone().decrypt(&mut enc_data) {
        Ok(decrypted_data) => {
            println!("{}", from_utf8(&decrypted_data).unwrap());
            deserialize_data(decrypted_data);
        },
        Err(err) => {
            println!("An error as occured during the decryption : {:?}", err);
        },
    };
    return M;
}

/*
fn encrypt_and_send_message(server: &mut TcpStream, M: &mut Message, mut key: &Vec<u8>) {
    data = M.data.to_vec();
    M.data  = encrypt_message(M.iv.clone(), data, &key);
    send_message(server, &mut M.data);
}
*/

fn serialize_data(M: &Message) -> Vec<u8>{
    return serialize(&M).unwrap();
}

fn deserialize_data(data: &[u8]) -> Message {
    return deserialize(data).unwrap()
}

fn send_password_challenge(server: &mut TcpStream) -> (Vec<u8>, Vec<u8>){
    let mut server_pass_and_key = String::new();

    println!("Server's password : ");
    io::stdin()
        .read_line(&mut server_pass_and_key)
        .expect("Failed to read line");
    server_pass_and_key.pop(); // edode : remove the \n at the end of the script

    let mut iv = generate_random_iv();
    let username = create_username();
    let mut M = Message::new(
        username.clone(),
        server_pass_and_key.as_bytes().to_vec(),
    );

    let mut data = encrypt_message(iv.clone(), &M, &server_pass_and_key.clone().into_bytes());

    iv.append(&mut data);
    println!("sending authentication request");
    send_message(server, &mut iv);

    return (username, server_pass_and_key.into_bytes().to_owned());
}

fn create_username() -> Vec<u8> {
    let mut username = String::with_capacity(1);
    println!("Username : ");
    io::stdin()
        .read_line(&mut username)
        .expect("Failed to read line");
    username.pop();
    let x = truncate_in_place(username, USERNAME_LENGTH);
    return x.to_owned();
}

fn truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        None => s,
        Some((idx, _)) => &s[..idx],
    }
}

fn truncate_in_place(mut s: String, max_chars: usize) -> Vec<u8>{

    let bytes = truncate(&s, max_chars).len();
    s.truncate(bytes);
    let mut buffer = [0u8; 10];
    buffer[.. s.len()].copy_from_slice(s.as_bytes());
    return buffer.to_vec();
}


fn main() {
    let mut server = handle_connection();
    let (username, key) = send_password_challenge(&mut server);

    let mut U = User::new(server);

    loop {
        let (tx, rx) = mpsc::channel::<String>();
        let mut U = U.clone();
        let key = key.clone();
        spawn(move || loop {
            handle_message_received(&mut U);
            match rx.try_recv() {
                Ok(msg) => {
                    decrypt_message(&mut U.MSG, &key);
                    println!("message received : {}", msg);
                },
                Err(TryRecvError::Empty) => { },
                Err(TryRecvError::Disconnected) => {
                    println!("Disconnected");
                    break;
                }
            }
        });
        write_message(&tx.clone());
    }


}















