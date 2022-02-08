use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::channel;
use std::thread::{sleep, spawn};

use aes::Aes256;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::{RngCore, rngs::OsRng};

use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 4096;
const IV_LEN: usize = 16;
const PASS: &[u8; 32] = b"12345678901234567890123556789011";
const USERNAME_LENGTH: usize = 10;

struct User {
    sock: TcpStream, // lisandro : make it a simple tcp stream (see lisandro in send_message_to_all_clients() )
    authenticated: bool,
    connected: bool,
    MSG: Message,
}
impl User {
    fn new(sock: TcpStream) -> User {
        User {
            sock,
            authenticated: false,
            connected: false,
            MSG: Message::new(vec![], vec![]),
        }
    }
    fn delete(&mut self) {
        self.sock.shutdown(Shutdown::Both).unwrap();
        self.MSG.delete();
    }
    fn clone(&self) -> User {
        User {
            sock: self.sock.try_clone().unwrap(),
            authenticated: self.authenticated,
            connected: self.connected,
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
        Message { username, data }
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

fn idle() {
    sleep(::std::time::Duration::from_millis(100));
}

fn handle_connection() -> TcpListener{
    let server =
        TcpListener::bind(LOCAL)
            .expect("Listener failed to bind");
    server
        .set_nonblocking(true)
        .expect("failed to initialize non-blocking");
    return server;
}

fn add_client(mut clients: Vec<TcpStream>, new_user: &TcpStream) -> Vec<TcpStream> {
    // add the newly connected client to the array

    clients.push(new_user
        .try_clone()
        .expect("failed to clone client")
    );
    return clients;
}

fn send_message_to_all_clients(clients: &Vec<TcpStream>, U: &mut User) {
    // Used to send a message to all other clients

    for mut c in clients{
        if U.sock.peer_addr().unwrap().to_string() != *c.peer_addr().unwrap().to_string() { // lisandro : compare using tcpstream and not string
            U.MSG.data.resize(MSG_SIZE, 0);
            c.write_all(&U.MSG.data).ok();
        } else {

        }
    };
}

fn send_message_to_client(U: &mut User) {
    // Used to send to a specific client

    U.MSG.data.resize(MSG_SIZE, 0);
    U.sock.write_all(&U.MSG.data).ok();
}

fn handle_message_received<'a>(mut U: &'a mut User, addr: &'a SocketAddr) -> &'a User  {
    let mut buff = vec![0; MSG_SIZE];
    match U.sock.read_exact(&mut buff) {
        Ok(_) => {
            U.MSG.data = buff.into_iter().collect::<Vec<_>>();
            U.connected = true;
            return U;
        },
        Err(ref err) if err.kind() == ErrorKind::WouldBlock => (println!("shit happens")),
        Err(x) => {
            println!("Client {:?} disconnected : {:?}", addr, x);
        },
    };
    U.connected = false;
    return U;
}

fn remove_trailing_zeros(data: Vec<u8>) -> Vec<u8> {
    // Used to remove the zeros at the end of the received encrypted message
    // but not inside the message (purpose of the 'keep_push' var

    let mut transit: Vec<u8> = vec![];
    let mut res: Vec<u8> = vec![];
    let mut keep_push: bool = false;
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
    //res.push(0);
    return res.to_owned();
}

fn generate_random_iv() -> Vec<u8> {
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);
    return iv.to_vec();
}

fn serialize_data(M: &Message) -> Vec<u8>{
    return serialize(&M).unwrap();
}

fn deserialize_data(data: &[u8]) -> Message {
    return deserialize(data).unwrap()
}

fn encrypt_message(iv: Vec<u8>, data: &Message, key: &Vec<u8>) -> Vec<u8> {
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    let cipher = match Aes256Cbc::new_from_slices(&key, &iv) {
        Ok(cipher) => cipher,
        Err(err) => panic!("{}", err)
    };
    let ser_data = serialize_data(&data);

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

fn decrypt_message<'a>(U: &'a mut User, key: &'a Vec<u8>) -> &'a mut User {
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    // print data
    println!("decrypting data : {:?}", U.MSG.data);
    let iv = &U.MSG.data[0..IV_LEN];
    let data = &U.MSG.data[IV_LEN..];

    let cipher = match Aes256Cbc::new_from_slices(&key, iv) {
        Ok(cipher) => cipher,
        Err(err) => panic!("{}", err)
    };

    let mut enc_data = remove_trailing_zeros(remove_trailing_zeros(data.to_vec()));
    U.MSG.delete();
    match cipher.clone().decrypt(&mut enc_data) {
        Ok(decrypted_data) => {
            U.MSG = deserialize_data(decrypted_data);
            return U;
        },
        Err(err) => {
            println!("An error as occured during the decryption : {:?}", err);
        },
    };
    U.authenticated = false;
    return U;
}

fn handle_authentication<'a>(U: &'a mut User, addr: &'a SocketAddr, server_password: &Vec<u8>) -> &'a mut User {
    if !U.authenticated {
        handle_message_received(U, &addr);
        // edode : receive the first message even though the client is not connected
        decrypt_message(U, &server_password);
        if U.connected {
            let iv = generate_random_iv();
            let mut welcome_message = U.sock.peer_addr().unwrap().to_string().into_bytes();
            println!("Client {}({:?}) connected and successfully authenticated", addr, U.MSG.username);

            welcome_message.extend_from_slice(b"\nSuccessfully authenticated");
            U.MSG.data = welcome_message;
            U.authenticated = true;
            encrypt_message(iv, &U.MSG, &server_password);
        } else {
            println!("Client {} failed password challenge", addr);
            U.MSG.data = b"from server :\n\tIncorect password, please try again".to_vec();
        }
        send_message_to_client(U);
    }
    return U;
}

fn main() {
    let server = handle_connection();
    let mut clients = vec![];
    let (tx, rx) = channel::<User>();

    loop {
        if let Ok((mut socket, addr)) = server.accept() {

            let mut U = User::new(socket.try_clone().unwrap());
            let tx = tx.clone();
            clients = add_client(clients, &socket);
            spawn(move || loop {
                let server_password = PASS.to_vec();

                if !U.authenticated {
                    handle_authentication(&mut U, &addr, &server_password);
                    continue;
                };

                handle_message_received(&mut U, &addr);

                if U.connected {
                    decrypt_message(&mut U, &server_password);
                    match tx.send(U.clone()) {
                        Ok(_) => {},
                        Err(err) => {
                            println!("Error sending message to channel : {:?}", err);
                        }
                    };
                } else {
                    println!("Client {:?} disconnected", U.sock);
                    break;
                };
                idle();
            });
        };

        if let Ok(mut U) = rx.try_recv() {
            let iv = generate_random_iv();
            U.MSG.data = encrypt_message(iv, &U.MSG, &PASS.to_vec());
            send_message_to_all_clients(&clients, &mut U);
        };

        idle();
    }
}




























