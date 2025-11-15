use std::io::{self, Read};

use crust::Interface;

fn main() -> Result<(), io::Error> {
    let mut i = Interface::new()?;
    let port = 8080;
    let mut l = i.bind(port)?;
    let jh = std::thread::spawn(move || {
        while let Ok(mut stream) = l.accept() {
            println!("Got connection from {port}");
            let n = stream.read(&mut [0]).unwrap();
            assert_eq!(n, 0);
            println!("Connection closed");
        }
    });

    jh.join().unwrap();
    Ok(())
}
