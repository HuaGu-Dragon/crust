use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    io::{self, Read, Write},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    thread,
};

use tun::Device;

pub mod tcp;

type InterfaceHandle = Arc<Mutex<ConnectionManager>>;

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

pub struct Interface {
    ih: InterfaceHandle,
    jh: thread::JoinHandle<()>,
}

#[derive(Default)]
pub struct ConnectionManager {
    connection: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let mut config = tun::Configuration::default();
        config
            .tun_name("tun0")
            .address((192, 168, 0, 1))
            .netmask((255, 255, 255, 0))
            .up();

        let nic = Device::new(&config)?;
        let ih: InterfaceHandle = Arc::default();
        let jh = {
            let handle = ih.clone();
            thread::spawn(move || {
                let nic = nic;
                let handle = handle;
                let buf = [0u8; 1500];
            })
        };

        Ok(Self { ih, jh })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        let mut ih = self.ih.lock().unwrap();
        match ih.pending.entry(port) {
            Entry::Occupied(mut occupied_entry) => {
                occupied_entry.insert(VecDeque::new());
            }
            Entry::Vacant(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "port already bound",
                ));
            }
        }
        drop(ih);
        Ok(TcpListener(port, self.ih.clone()))
    }
}

pub struct TcpStream(Quad, InterfaceHandle);

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut ih = self.1.lock().unwrap();
        let conn = ih.connection.get_mut(&self.0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;
        todo!()
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}

pub struct TcpListener(u16, InterfaceHandle);

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut ih = self.1.lock().unwrap();
        if let Some(quad) = ih.pending.get_mut(&self.0).unwrap().pop_front() {
            Ok(TcpStream(quad, self.1.clone()))
        } else {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no connections available",
            ))
        }
    }
}
