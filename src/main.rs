use std::io::{self, Read};

use crust::Interface;

fn main() -> Result<(), io::Error> {
    let mut i = Interface::new()?;
    let port = 8080;
    let mut l = i.bind(port)?;
    let jh = std::thread::spawn(move || {
        while let Ok(mut stream) = l.accept() {
            let mut buf = [0; 512];
            println!("Got connection from {port}");
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                println!("Connection Closed!")
            } else {
                println!("recv: {:?}", String::from_utf8_lossy(&buf[..n]));
            }
        }
    });

    jh.join().unwrap();
    Ok(())
}
