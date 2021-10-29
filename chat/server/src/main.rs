use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::sync::mpsc;
use std::thread;
use std::sync::mpsc::{Sender, Receiver};
use std::str::from_utf8;
use xsalsa20poly1305::XSalsa20Poly1305;
use xsalsa20poly1305::aead::{AeadInPlace, NewAead, generic_array::GenericArray};
use xsalsa20poly1305::aead::heapless::Vec as salsa_v;

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 32;

fn sleep() {
    thread::sleep(::std::time::Duration::from_millis(100));
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

fn handle_message_received(tx: &Sender<String>, socket: &mut TcpStream, addr: &SocketAddr) -> bool {
    let mut buff = vec![0; MSG_SIZE];

    match socket.read_exact(&mut buff) {
        Ok(_) => {
            let msg =
                buff
                    .into_iter()
                    .take_while(|&x| x != 0)
                    .collect::<Vec<_>>();

            let mut msg =
                String::from_utf8(msg)
                    .expect("Invalid utf8 message");

            println!("{}: {}", addr, msg);
            tx.send(msg)
                .expect("failed to send msg to rx");
        },
        Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
        Err(x) => {
            println!("closing connection with: {}, {}", addr, x);
            return true;
        }
    }
    return false;
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
    clients
        .push(new_user
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

fn main() {
    let server = handle_connection();
    let mut clients = vec![];
    let (tx, rx) = mpsc::channel::<String>();

    loop {
        if let Ok((mut socket, addr)) = server.accept() {

            println!("Client {} connected", addr);
            let tx = tx.clone();
            clients = add_client(clients, &socket);
            send_first_message(&clients);

            thread::spawn(move || loop {
                let disconnect = handle_message_received(&tx, &mut socket, &addr);
                if disconnect { break }
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




























