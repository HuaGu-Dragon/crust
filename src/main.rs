use std::io::{self, Read, Write};

use crust::Interface;

fn main() -> Result<(), io::Error> {
    let mut i = Interface::new()?;
    let port = 8080;
    let mut l = i.bind(port)?;
    while let Ok(mut stream) = l.accept() {
        println!("Got connection from {port}");
        let mut data = Vec::new();
        loop {
            let mut buf = [0; 512];
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                println!("Connection Closed!");
                break;
            } else {
                data.extend_from_slice(&buf[..n]);
            }
        }
        println!("recv: {}", String::from_utf8_lossy(&data[..]))
    }

    Ok(())
}
