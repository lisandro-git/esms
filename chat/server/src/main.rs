use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::sync::mpsc;
use std::thread;
use std::sync::mpsc::Sender;
use std::str::from_utf8;

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

            let msg =
                String::from_utf8(msg)
                    .expect("Invalid utf8 message");

            println!("{}: {:?}", addr, msg);
            tx.send(msg)
                .expect("failed to send msg to rx");
        },
        Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
        Err(_) => {
            println!("closing connection with: {}", addr);
            return true;
        }
    }
    return false
}


fn main() {
    let mut clients = vec![];
    let (tx, rx) = mpsc::channel::<String>();
    let server = handle_connection();
    loop {
        if let Ok((mut socket, addr)) = server.accept() {
            println!("Client {} connected", addr);

            let tx = tx.clone();
            clients
                .push(socket
                    .try_clone()
                    .expect("failed to clone client")
                );

            thread::spawn(move || loop {
                let disconnect = handle_message_received(&tx, &mut socket, &addr);
                if disconnect{ break }
                sleep();
            });
        }

        if let Ok(msg) = rx.try_recv() {
            clients = clients
                    .into_iter()
                    .filter_map(|mut client| {
                let mut buff = msg
                        .clone()
                        .into_bytes();
                buff.resize(MSG_SIZE, 0);
                client.write_all(&buff).map(|_| client).ok()
            }).collect::<Vec<_>>();
        }

        sleep();
    }
}

/*
        if let Ok(msg) = rx.try_recv() {
            clients = clients
                    .into_iter()
                    .filter_map(|mut client| {
                let mut buff = msg
                        .clone()
                        .into_bytes();
                buff.resize(MSG_SIZE, 0);
                client.write_all(&buff).map(|_| client).ok()
            }).collect::<Vec<_>>();
 */