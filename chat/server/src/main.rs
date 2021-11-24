use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::channel;
use std::thread::{sleep, spawn};

use aes::Aes256;

use block_modes::{
    BlockMode,
    Cbc,
    block_padding::Pkcs7};

use rand::{
    RngCore,
    rngs::OsRng
};

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 4096;
const IV_LEN: usize = 16;
const PASS: &[u8; 32] = b"12345678901234567890123556789011";

struct User {
    ip: String,
    data: Vec<u8>,
    authenticated: bool,
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

fn send_message_to_all_clients(clients: &Vec<TcpStream>, u: &mut User) {
    // Used to send a message to all other clients

    for mut c in clients{
        if u.ip != c.peer_addr().unwrap().to_string() {
            u.data.resize(MSG_SIZE, 0);
            c.write_all(&u.data).ok();
        };
    };
}

fn send_message_to_client(client: &mut TcpStream, u: &mut User) {
    // Used to send to a specific client

    u.data.resize(MSG_SIZE, 0);
    client.write_all(&u.data).ok();
}

fn handle_message_received(socket: &mut TcpStream, addr: &SocketAddr) -> (Vec<u8>, bool) {
    let mut buff = vec![0; MSG_SIZE];

    match socket.read_exact(&mut buff) {
        Ok(_) => {
            let msg = buff.into_iter().collect::<Vec<_>>();
            return (msg, false);
        },
        Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
        Err(x) => {
            println!("closing connection with: {}, {}", addr, x);
            return (buff, true);
        }
    }
    return (buff, true);
}

fn get_iv(text: Vec<u8>) -> (Vec<u8>, Vec<u8>){
    // Separate the IV and the Data from the receivec string

    let text = remove_trailing_zeros(&mut text.to_owned());
    let mut i:usize = 0;
    let mut iv:Vec<u8> = vec![];
    let mut data: Vec<u8> = vec![];

    for t in text.iter(){
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

fn encrypt_message(msg: Vec<u8>, key: &Vec<u8>) -> Vec<u8>{
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
            println!("Could not decrypt message : {:?}", err);
            return b"".to_vec();
        }
    };

    return add_iv_and_encrypted_msg(iv, &enc_data).to_owned();
}

fn decrypt_message(msg: Vec<u8>, key: &Vec<u8>) -> (Vec<u8>, bool) {

    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let (iv, mut enc_data) = get_iv(msg.clone());
    let cipher = match Aes256Cbc::new_from_slices(&key, &iv) {
        Ok(cipher) => cipher,
        Err(err) => {
            println!("decrypt err : {}", err);
            return (b"".to_vec(), false)
        }
    };
    match cipher.decrypt(&mut enc_data) {
        Ok(decrypted_data) => {
            return (decrypted_data.to_vec(), true);
        }
        Err(err) => {
            println!("Could not decrypt message : {:?}", err);
            return (b"".to_vec(), false);
        }
    };
}

fn main() {
    println!("Started server, and listening to {}", LOCAL);
    let server = handle_connection();
    let mut clients = vec![];
    let mut authenticated = false;
    let (tx, rx) = channel::<User>();

    loop {
        if let Ok((mut socket, addr)) = server.accept() {
            let tx = tx.clone();
            clients = add_client(clients, &socket);

            spawn(move || loop {
                let mut u = User{
                    ip: socket.peer_addr().unwrap().to_string(),
                    data: vec![],
                    authenticated,
                };
                let server_password = PASS.to_vec();
                if !u.authenticated {
                    // edode : receive the first message even though the client is not connected
                    let (data, _) = handle_message_received(&mut socket, &addr);
                    let (_, auth_passed) = decrypt_message(data, &server_password);
                    if auth_passed {
                        println!("Client {} connected and successfully authenticated", addr);

                        let mut welcome_message = socket.peer_addr().unwrap().to_string().into_bytes();
                        welcome_message.extend_from_slice(b"\nSuccessfully authenticated");
                        u.data = encrypt_message(welcome_message, &server_password);
                        send_message_to_client(&mut socket, &mut u);
                        authenticated = true;
                        continue;
                    } else {
                        println!("Client {} failed password challenge", addr);
                        u.data = b"from server :\n\tIncorect password, please try again".to_vec();
                        send_message_to_client(&mut socket, &mut u);
                        break;
                    }
                }

                let (msg , disconnect) = handle_message_received(&mut socket, &addr);

                if !disconnect {
                    let (msg, _) = decrypt_message(msg, &server_password);
                    u.data = msg;
                    match tx.send(u) {
                        Ok(_) => {},
                        Err(err) => {
                            println!("Error sending message to channel : {:?}", err);
                        }
                    }
                } else { break };

                idle();
            });
        }
        if let Ok(mut u) = rx.try_recv() {
            u.data = encrypt_message(u.data.to_owned(), &PASS.to_vec());
            send_message_to_all_clients(&clients, &mut u);
        };
        idle();
    }
}




























