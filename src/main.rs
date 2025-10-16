use std::{
    collections::HashMap,
    io::{self},
    net::Ipv4Addr,
};

use etherparse::IpNumber;

mod tcp;

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> Result<(), io::Error> {
    let mut config = tun::Configuration::default();
    config
        .tun_name("tun0")
        .address((192, 168, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let dev = tun::create(&config)?;
    let mut buf = [0u8; 1500];

    let mut connections = HashMap::<Quad, tcp::TcpState>::new();

    loop {
        let n = dev.recv(&mut buf)?;
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..n]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                println!(
                    "Received packet: {} -> {}, protocol: {:?}, length: {}",
                    src,
                    dst,
                    iph.protocol(),
                    iph.total_len()
                );

                if iph.protocol() == IpNumber::TCP {
                    match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..n]) {
                        Ok(tcp_h) => {
                            let data = &buf[iph.slice().len() + tcp_h.slice().len()..n];
                            connections
                                .entry(Quad {
                                    src: (src, tcp_h.source_port()),
                                    dst: (dst, tcp_h.destination_port()),
                                })
                                .or_default()
                                .on_packet(iph, tcp_h, data);
                        }
                        Err(e) => {
                            eprintln!("ignoring non-TCP packet: {:?}", e);
                            continue;
                        }
                    }
                }
            }

            Err(e) => {
                eprintln!("Failed to parse IPv4 header: {:?}", e);
                continue;
            }
        }
    }
}
