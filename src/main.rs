use std::io::{self};

fn main() -> Result<(), io::Error> {
    let mut config = tun::Configuration::default();
    config
        .tun_name("tun0")
        .address((192, 168, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let dev = tun::create(&config)?;
    let mut buf = [0u8; 1504];

    loop {
        let n = dev.recv(&mut buf)?;
        println!("Read {} bytes: {:x?}", n, &buf[..n]);
    }
}
