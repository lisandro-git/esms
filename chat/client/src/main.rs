use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, TryRecvError, Sender, Receiver};
use std::thread;
use std::time::Duration;

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 32;

fn handle_connection() -> TcpStream {
    let client =
        TcpStream::connect(LOCAL)
            .expect("Stream failed to connect");
    client
        .set_nonblocking(true)
        .expect("failed to initiate non-blocking");
    return client
}

fn get_message(tx: &Sender<String>) -> String {
        let mut buff = String::new();
        io::stdin()
            .read_line(&mut buff)
            .expect("reading from stdin failed");
        let msg =
            buff
            .trim()
            .to_string();

        if msg == ":quit" || tx.send(String::from(&msg)).is_err() { std::process::exit(0) }
        else { return msg }
}

fn handle_message_received(client: &mut TcpStream) -> bool{
    let mut buff = vec![0; MSG_SIZE];
    match client.read_exact(&mut buff) {
        Ok(_) => {
            let msg =
                buff
                    .into_iter()
                    .take_while(|&x| x != 0)
                    .collect::<Vec<_>>();
            println!("message recv {:?}", msg);
        },
        Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
        Err(_) => {
            println!("connection with server was severed");
            return true;
        }
    }
    return false;
}

fn handle_message_sent(client: &mut TcpStream, rx: &Receiver<String>) {
    match rx.try_recv() {
        Ok(msg) => {
            let mut buff = msg
                .clone()
                .into_bytes();

            buff.resize(MSG_SIZE, 0);
            client
                .write_all(&buff)
                .expect("writing to socket failed");
            println!("message sent {:?}", msg);
        },
        Err(TryRecvError::Empty) => (),
        Err(TryRecvError::Disconnected) => {}
    }
}

fn main() {
    let mut client = handle_connection();

    let (tx, rx) = mpsc::channel::<String>();

    thread::spawn(move ||
        loop {
            let disconnect = handle_message_received(&mut client);
            if disconnect { break }
            handle_message_sent(&mut client, &rx);
            thread::sleep(Duration::from_millis(100));
        });

    println!("Write a Message:");
    loop {
        let buff = get_message(&tx);
        println!("{}", buff)
    }
}















