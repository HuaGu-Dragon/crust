use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    io::{self, Read, Write},
    net::Ipv4Addr,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Instant,
};

use etherparse::IpNumber;
use tun_rs::{DeviceBuilder, SyncDevice};

use crate::tcp::{Available, Connection};

mod tcp;

const SENDQUEUE_SIZE: usize = 1024;

type InterfaceHandle = Arc<Handler>;

#[derive(Default)]
struct Handler {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    rcv_var: Condvar,
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

pub struct Interface {
    ih: Option<InterfaceHandle>,
    jh: Option<thread::JoinHandle<std::io::Result<()>>>,
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminate = true;

        drop(self.ih.take());
        self.jh.take().unwrap().join().unwrap().unwrap();
    }
}

#[derive(Default)]
pub struct ConnectionManager {
    terminate: bool,
    connection: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

fn packet_loop(ih: InterfaceHandle, nic: SyncDevice) -> std::io::Result<()> {
    let mut buf = [0u8; 1500];

    loop {
        let now = Instant::now();

        let n = loop {
            match nic.try_recv(&mut buf) {
                Ok(n) => break n,
                Err(_) => {
                    if now.elapsed().as_millis() > 100 {
                        for con in ih.manager.lock().unwrap().connection.values_mut() {
                            con.on_tick(&nic)?;
                        }
                        continue;
                    }
                }
            };
        };

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..n]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                // println!(
                //     "Received packet: {} -> {}, protocol: {:?}, length: {}",
                //     src,
                //     dst,
                //     iph.protocol(),
                //     iph.total_len()
                // );

                if iph.protocol() == IpNumber::TCP {
                    match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..n]) {
                        Ok(tcp_h) => {
                            let data = &buf[iph.slice().len() + tcp_h.slice().len()..n];
                            let mut lock = ih.manager.lock().unwrap();
                            let cm = &mut *lock;
                            let q = Quad {
                                src: (src, tcp_h.source_port()),
                                dst: (dst, tcp_h.destination_port()),
                            };
                            match cm.connection.entry(q) {
                                Entry::Occupied(mut occupied_entry) => {
                                    let available = occupied_entry
                                        .get_mut()
                                        .on_packet(&nic, iph, tcp_h, data)?;

                                    drop(lock);
                                    if available.contains(Available::READ) {
                                        ih.rcv_var.notify_all();
                                    }
                                }
                                Entry::Vacant(vacant_entry) => {
                                    if let Some(pending) =
                                        cm.pending.get_mut(&tcp_h.destination_port())
                                        && let Some(connection) =
                                            Connection::accept(&nic, iph, tcp_h, data)?
                                    {
                                        vacant_entry.insert(connection);
                                        pending.push_back(q);

                                        drop(lock);
                                        ih.pending_var.notify_all();
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // eprintln!("ignoring non-TCP packet: {:?}", e);
                            continue;
                        }
                    }
                }
            }

            Err(e) => {
                // eprintln!("Failed to parse IPv4 header: {:?}", e);
                continue;
            }
        }
    }
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = DeviceBuilder::new()
            .name("tun0")
            .ipv4(Ipv4Addr::new(192, 168, 0, 1), 24, None)
            .build_sync()?;

        let ih: InterfaceHandle = Arc::default();
        let jh = {
            let handle = ih.clone();
            thread::spawn(move || packet_loop(handle, nic))
        };

        Ok(Self {
            ih: Some(ih),
            jh: Some(jh),
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        let mut ih = self.ih.as_mut().unwrap().manager.lock().unwrap();
        match ih.pending.entry(port) {
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "port already bound",
                ));
            }
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(VecDeque::new());
            }
        }
        drop(ih);
        Ok(TcpListener {
            port,
            h: self.ih.as_ref().unwrap().clone(),
        })
    }
}

pub struct TcpStream {
    quad: Quad,
    h: InterfaceHandle,
}

impl TcpStream {
    pub fn shutdown(&self) -> std::io::Result<()> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connection.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        c.close()
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();
        if cm
            .connection
            .get(&self.quad)
            .expect("connection closed before drop")
            .is_rcv_closed()
        {
            cm.connection.remove(&self.quad);
        }
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut ih = self.h.manager.lock().unwrap();
        loop {
            let conn = ih.connection.get_mut(&self.quad).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "stream was terminated unexpectedly",
                )
            })?;

            if conn.is_rcv_closed() && conn.incomming.is_empty() {
                return Ok(0);
            }

            if !conn.incomming.is_empty() {
                let mut nread = 0;
                let (head, tail) = conn.incomming.as_slices();
                let hread = std::cmp::min(head.len(), buf.len());
                buf[..hread].copy_from_slice(&head[..hread]);
                nread += hread;
                let tread = std::cmp::min(tail.len(), buf.len() - nread);
                buf[hread..][..tread].copy_from_slice(&tail[..tread]);
                nread += tread;
                drop(conn.incomming.drain(..nread));
                return Ok(nread);
            }

            ih = self.h.rcv_var.wait(ih).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut ih = self.h.manager.lock().unwrap();
        let conn = ih.connection.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if conn.unacked.len() >= SENDQUEUE_SIZE {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes buffered",
            ));
        }

        let nwrite = std::cmp::min(buf.len(), SENDQUEUE_SIZE - conn.unacked.len());
        conn.unacked.extend(&buf[..nwrite]);

        // TODO: wake up writer

        Ok(nwrite)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut ih = self.h.manager.lock().unwrap();
        let conn = ih.connection.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if conn.unacked.is_empty() {
            Ok(())
        } else {
            unimplemented!()
        }
    }
}

pub struct TcpListener {
    port: u16,
    h: InterfaceHandle,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();
        let pending = cm
            .pending
            .remove(&self.port)
            .expect("port closed while listener still active");

        for _quad in pending {
            // TODO: terminate all the connections
        }
    }
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut ih = self.h.manager.lock().unwrap();
        loop {
            if let Some(quad) = ih.pending.get_mut(&self.port).unwrap().pop_front() {
                return Ok(TcpStream {
                    quad,
                    h: self.h.clone(),
                });
            }

            ih = self.h.pending_var.wait(ih).unwrap();
        }
    }
}
