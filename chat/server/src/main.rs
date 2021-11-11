use std::borrow::Borrow;
use std::io::{ErrorKind, Read, Write};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::str::from_utf8;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use aes::Aes128;
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
/* RSA handshake part */
fn decrypt_rsa_string(server_private_key: RsaPrivateKey, enc_data: &[u8]) {
    let mut rng = OsRng;
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let enc_data = server_private_key
        .decrypt(padding, &enc_data)
        .expect("failed to decrypt");
    println!("data : {}", from_utf8(&enc_data[..]).unwrap());
    println!("data : {}", from_utf8(&enc_data[..]).unwrap());
}

fn remove_zeros_from_message(arr: Vec<u8>) -> Vec<u8>{
    let mut inv_arr: Vec<u8> = vec![];

    let mut p: bool = false;
    for a in arr.iter().rev(){
        if *a != 0 { p = true; }
        if p { inv_arr.push(*a); }
    }
    {
        let mut enc_data: Vec<u8> = vec![];
        for i in inv_arr.iter().rev() {
            enc_data.push(*i);
        }
        inv_arr = enc_data;
    }

    return inv_arr;
}

fn server_client_handshake(socket: &mut TcpStream) -> bool{
    // 19111999 : to get the client's public key, you have to invert the received message(see 1), and
    // use the map to remove the zeros. After that, you won't have any problems
    let mut buff = vec![0; MSG_SIZE];
    let mut data: Vec<u8> = vec![];
    match socket.read_exact(&mut buff) {
        Ok(_) => {
            // edode : removing the trailing zeros at the end of the received message
            data = remove_zeros_from_message(buff);
        },
        Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
        Err(x) => {
            println!("closing connection with: {}",  x);
        }
    }

    let server_private_key: RsaPrivateKey;
    {
        let server_private_key_string = String::from("\
        -----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKQCnlablOfvPpXs
HBGn00dxkyw0nswRkNxVh99FuEeuTwl/ihY4xZSNPKEPUEkeayhMqqxFCWVXTxpk
mzYU4K1NoWW43Zo5Zux8eAPSwH33TOOf6T9rH95cIX+csVLPeL6UmLeR2wJYaiWM
yoiiZjB2EPO+Apb6mDBg4qyq2loTAgMBAAECgYAQbea4nEs1VKT7VbSWHC6w+HKa
ugayQIw3ViYPOqe0HoTyWaFWiodYUzGgnK0ZNf/cAJoUObIwQae96BgYOc0rxg2G
7G/v2FU9CDZBNWbt0KPi8v57go8Kg0BeckP8D8hlFpjMbQCDGMmwP7+hD0rlht1U
9LBNDXmSxJqL1N7RQQJBAM/PcPzcKuntuUxpOsxo88kSlPPmciPF4wDADufo7Ym+
RYp+eLrcc3w0wh+Qf+Dpg0hTW6jedJjbNfcdlHPq0LMCQQDKCwGQpiMksWqA6+hZ
0v0JY7JY0YgtteO2+9T5yVuSX8a3mB6PXRPIBIbRGMd7VloNJYWZKsYDHNtJ3CmX
CEEhAkEAlqblW3rlZXdgqSN0a/H+IhvlfjfnMUXpfoa9h6SWaBBXa8KqFZVx5257
+NQR0OSYtxsvTOoQjywEIGUCVVK6/wJAYTvywN5zw1Du5KSj6ba0uDQWvM/6LaV/
tax0ztGtFECrreezrWMqBfTHvRGjzyO7quAH77K6IP1eO6mNCnaagQJAY3WOvQRj
4jLa15SAUkjqBP5MmvfO87a59U+ORZVBmeaK7AgdVYMYwODXkTWjO4pmRyzJn6ix
aXgKG0uzEQmweg==
-----END PRIVATE KEY-----");
        server_private_key = rsa::RsaPrivateKey::from_pkcs8_pem(&server_private_key_string).unwrap();
    }
    println!("{:?}", server_private_key);
    decrypt_rsa_string(server_private_key, &data[..]);

    return true;
}
/* END RSA handshake part */

/* AES part */
fn verify_password(client: &TcpStream, enc_key: &mut [u8], key: &Vec<u8>) -> bool{
    type Aes128Cbc = Cbc<Aes128, Pkcs7>;
    let iv = b"1111111111111111";
    let cipher = Aes128Cbc::new_from_slices(key.as_slice(), &iv.to_vec().as_slice()).unwrap();
    println!("{:?}", enc_key);
    let mut dec_key = cipher.decrypt(enc_key).unwrap().to_vec();
    println!("{:?}", &dec_key[..]);
    println!("lkjhekazj");
    return true;
}
/* END AES part */

fn main() {
    let server = handle_connection();
    let mut clients = vec![];
    let mut authenticated = false;
    let mut server_password = b"aaaaaaaaaaaaaaaa".to_vec();
    let iv = b"1234567891711121";
    let (tx, rx) = mpsc::channel::<String>();

    loop {
        if let Ok((mut socket, addr)) = server.accept() {

            println!("Client {} connected", addr);
            let tx = tx.clone();
            clients = add_client(clients, &socket);

            send_first_message(&clients);

            thread::spawn(move || loop {
                let mut server_password = b"aaaaaaaaaaaaaaaa".to_vec();
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




























