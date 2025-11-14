use std::io;

use crust::Interface;

fn main() -> Result<(), io::Error> {
    let mut i = Interface::new()?;
    let mut l = i.bind(8082)?;
    let jh = std::thread::spawn(move || {
        while let Ok(_stream) = l.accept() {
            println!("Got connection from 8000");
        }
    });

    jh.join().unwrap();
    Ok(())
}
