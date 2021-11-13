use std::borrow::Borrow;
use std::io::{ErrorKind, Read, Write};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::str::from_utf8;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::RngCore;
use rand::rngs::OsRng;
//jfdzhoydbfmkdjhfpkhjbfds
const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 4096;
const IV_LEN: usize = 16;
const PASS: &[u8; 32] = b"12345678901234567890123556789011";

fn sleep() {
    thread::sleep(::std::time::Duration::from_millis(100));
}
/* communication part */
fn handle_connection() -> TcpListener{
    let server =
        TcpListener::bind(LOCAL)
            .expect("Listener failed to bind");
    server
        .set_nonblocking(true)
        .expect("failed to initialize non-blocking");
    return server;
}

fn send_first_message(clients: &Vec<TcpStream>) {
    let mut client_ip = &clients[clients.len()-1];
    let mut buff = client_ip
        .peer_addr()
        .unwrap()
        .to_string()
        .into_bytes();
    buff.resize(MSG_SIZE, 0);
    client_ip.write_all(&buff).ok();
}

fn add_client(mut clients: Vec<TcpStream>, new_user: &TcpStream) -> Vec<TcpStream> {
    clients.push(new_user
            .try_clone()
            .expect("failed to clone client")
        );
    return clients;
}

fn send_message_to_all_clients(mut clients: Vec<TcpStream>, msg: &mut Vec<u8>) -> Vec<TcpStream>{
    clients = clients
        .into_iter()
        .filter_map(|mut client| {
            println!("{:?}", client);
            msg.resize(MSG_SIZE, 0);
            client.write_all(&msg).map(|_| client).ok()
        }).collect::<Vec<_>>();
    return clients;
}

fn send_message_to_client(client: &mut TcpStream, msg: &[u8]) {
    let mut buff = msg.to_vec();
    buff.resize(MSG_SIZE, 0);
    client.write_all(&buff).ok();
}
/* END communication part */

fn handle_message_received(tx: &Sender<String>, socket: &mut TcpStream, addr: &SocketAddr) -> (bool, Vec<u8>) {
    let mut buff = vec![0; MSG_SIZE];

    match socket.read_exact(&mut buff) {
        Ok(_) => {
            // edode : removing the trailing zeros at the end of the received message
            let msg = buff.into_iter()
                    .take_while(|&x| x != 0)
                    .collect::<Vec<_>>();
            return (false, msg);
        },
        Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
        Err(x) => {
            println!("closing connection with: {}, {}", addr, x);
            return (true, buff);
        }
    }
    return return (false, buff);
}

/* AES part */
fn get_iv(text: Vec<u8>) -> (Vec<u8>, Vec<u8>){
    let mut i:usize = 0;
    let mut iv:Vec<u8> = vec![];
    let mut text_to_encrypt: Vec<u8> = vec![];
    for t in text.iter(){
        if i >= IV_LEN{
            text_to_encrypt.push(*t);
        } else {
            iv.push(*t);
            i += 1;
        }
    }
    return (iv, text_to_encrypt);
}

fn verify_password(client: &TcpStream, iv_and_enc_data: &mut [u8], key: &Vec<u8>) -> bool{
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let (mut iv, mut enc_data) = get_iv(iv_and_enc_data.to_vec());
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let decrypted_ciphertext = cipher.decrypt(&mut enc_data);
    match decrypted_ciphertext {
        Err(_) => {
            return false;
        },
        Ok(_) => {
            return true;
        }
    }
}

// 19111999 : send the msg after receiving a new one
fn generate_random_iv() -> Vec<u8> {
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);
    return iv.to_vec();
}

fn add_iv_and_encrypted_msg(iv: Vec<u8>, enc_msg: &Vec<u8>) -> Vec<u8> {
    let mut res = std::iter::repeat(0).take(MSG_SIZE).collect::<Vec<_>>();
    let mut msg_len: usize= 0;
    for i in iv.iter(){
        res[msg_len] = *i;
        msg_len+=1;
    }
    for i in enc_msg.iter(){
        if msg_len == MSG_SIZE {
            break;
        }
        res[msg_len] = *i;
        msg_len+=1;
    }
    return res.to_owned();
}

fn encrypt_message(msg: &Vec<u8>, key: &Vec<u8>) -> Vec<u8>{
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let mut iv = generate_random_iv();
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    println!("Sent IV {:?}", iv);
    let mut buffer = [0u8; MSG_SIZE];
    buffer[.. msg.len()].copy_from_slice(msg.as_slice());
    let enc_data = cipher.encrypt(&mut buffer,  msg.len()).unwrap().to_vec();
    let x = add_iv_and_encrypted_msg(iv, &enc_data);
    // 19111999 : only the encrypted text is returned, have to return iv+enc_data
    return x.to_owned();
}

fn decrypt_message(msg: Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let (iv, enc_data) = get_iv(msg.clone());
    let cipher = match Aes256Cbc::new_from_slices(&key, &iv) {
        Ok(cipher) => cipher,
        Err(err) => {
            println!("{}", err);
            return b"".to_vec();
        }
    };
    let mut buf = msg.to_vec();

    let x = match cipher.decrypt(&mut buf) {
        Ok(decrypted_data) => {
            return decrypted_data.to_vec();
        }
        Err(decrypted_data) => {
            return b"".to_vec();
        }
    };
}
/* END AES part */

fn main() {
    let server = handle_connection();
    let mut clients = vec![];
    let mut authenticated = false;
    let mut auth_passed = false;
    let (tx, rx) = mpsc::channel::<String>();

    loop {
        if let Ok((mut socket, addr)) = server.accept() {
            let tx = tx.clone();
            clients = add_client(clients, &socket);
            if authenticated{
                send_first_message(&clients);
            }

            thread::spawn(move || loop {
                let mut server_password = PASS.to_vec();
                if !&authenticated {
                    let (_, mut buff) = handle_message_received(&tx, &mut socket, &addr);
                    auth_passed = verify_password(&socket, &mut buff[..], &server_password);
                    if auth_passed {
                        println!("Client {} connected and successfully authenticated", addr);

                        authenticated = true;
                        let mut x = socket.peer_addr().unwrap().to_string().into_bytes();
                        x.extend_from_slice(b"\nSuccessfully authenticated");
                        send_message_to_client(&mut socket, &x);
                        continue;
                    }
                    else {
                        println!("Client {} connected failed password challenge", addr);
                        let buff = b"from server :\n\tIncorect password, please try again".to_vec();
                        send_message_to_client(&mut socket, &buff);
                        break;
                    }
                }

                let (disconnect, msg) = handle_message_received(&tx, &mut socket, &addr);

                if !disconnect {
                    // edode : if not has not been disconnected, send client's message to all other clients
                    //println!("msg received : {:?}", msg);
                    let msg = decrypt_message(msg, &server_password);
                    let (_, clear_msg) = get_iv(msg);
                    match from_utf8(clear_msg.as_slice()) {
                        Ok(str_msg) => {
                            println!("{}: {:?}", addr, str_msg);
                            tx.send(str_msg.to_string()).expect("failed to send msg to rx");;
                        }
                        Err(_) => {
                            println!("Could not read clear message");
                        }
                    };
                }
                else { break }

                sleep();
            });
        }

        if let Ok(mut msg) = rx.try_recv() {
            let key = PASS;
            let mut msg = encrypt_message(&msg.into_bytes(), &key.to_vec());
            clients = send_message_to_all_clients(clients, &mut msg)
        }
        sleep();
    }
}




























