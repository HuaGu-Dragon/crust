use std::io::{self, Read, Write};

pub struct TcpStream {}

impl Read for TcpListener {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
    }
}

impl Write for TcpListener {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}

pub struct TcpListener {}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        todo!()
    }
}
