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
use rsa::{PaddingScheme, RsaPrivateKey};
use rsa::pkcs8::FromPrivateKey;
use xsalsa20poly1305::aead::{AeadInPlace, generic_array::GenericArray, NewAead};
use xsalsa20poly1305::aead::heapless::Vec as salsa_v;
use xsalsa20poly1305::aead::rand_core::OsRng;
use xsalsa20poly1305::XSalsa20Poly1305;

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 4096;
const IV_LEN: usize = 16;

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

fn send_message_to_all_clients(mut clients: Vec<TcpStream>, msg: String) -> Vec<TcpStream>{
    clients = clients
        .into_iter()
        .filter_map(|mut client| {
            println!("{:?}", client);
            let mut buff = msg
                .clone()
                .into_bytes();
            buff.resize(MSG_SIZE, 0);
            client.write_all(&buff).map(|_| client).ok()
        }).collect::<Vec<_>>();
    return clients;
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
    println!("iv : {:?}", iv);
    println!("enc_data : {:?}", enc_data);
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let decrypted_ciphertext = cipher.decrypt(&mut enc_data);
    println!("decrypted_text : {:?}", decrypted_ciphertext);
    return true;
}
/* END AES part */

fn main() {
    let server = handle_connection();
    let mut clients = vec![];
    let mut authenticated = false;
    let mut server_password = b"aaaaaaaaaaaaaaaa".to_vec();
    let (tx, rx) = mpsc::channel::<String>();

    loop {
        if let Ok((mut socket, addr)) = server.accept() {

            println!("Client {} connected", addr);
            let tx = tx.clone();
            clients = add_client(clients, &socket);

            send_first_message(&clients);

            thread::spawn(move || loop {
                let mut server_password = b"12345678901234567890123556789011".to_vec();
                if !&authenticated {
                    let (_, mut buff) = handle_message_received(&tx, &mut socket, &addr);
                    authenticated = verify_password(&socket, &mut buff[..], &server_password);
                    continue;
                }

                let (disconnect, msg) = handle_message_received(&tx, &mut socket, &addr);

                if !disconnect {
                    // edode : if not has not been disconnected, send client's message to all other clients
                    let msg = String::from_utf8(msg).expect("Invalid utf8 message");
                    println!("{}: {}", addr, msg);
                    tx.send(msg).expect("failed to send msg to rx");
                }
                else { break }

                sleep();
            });
        }

        if let Ok(mut msg) = rx.try_recv() {
            //msg = encrypt_string(msg);
            clients = send_message_to_all_clients(clients, msg)
        }
        sleep();
    }
}




























