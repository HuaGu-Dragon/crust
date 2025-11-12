use std::{
    io::{self},
    net::Ipv4Addr,
};

use crust::Interface;

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> Result<(), io::Error> {
    let mut i = Interface::new()?;
    let mut l1 = i.bind(8000)?;
    let mut l2 = i.bind(8001)?;
    let jh1 = std::thread::spawn(move || {
        while let Ok(_stream) = l1.accept() {
            println!("Got connection from 8000");
        }
    });
    let jh2 = std::thread::spawn(move || {
        while let Ok(_stream) = l2.accept() {
            println!("Got connection from 8001");
        }
    });

    jh1.join().unwrap();
    jh2.join().unwrap();
    Ok(())
}
