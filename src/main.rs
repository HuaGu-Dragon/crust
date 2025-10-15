use std::io::{self};

fn main() -> Result<(), io::Error> {
    let mut config = tun::Configuration::default();
    config
        .tun_name("tun0")
        .address((192, 168, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let dev = tun::create(&config)?;
    let mut buf = [0u8; 1500];

    loop {
        let n = dev.recv(&mut buf)?;
        let version = buf[0] >> 4;
        match version {
            4 => println!("Received an IPv4 packet"),
            6 => println!("Received an IPv6 packet"),
            _ => println!("Unknown IP version: {}", version),
        }
        println!("Read {} bytes", n);
    }
}
