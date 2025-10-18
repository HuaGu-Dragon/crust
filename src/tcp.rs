use std::io::Write;

use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use tun::Device;

enum State {
    SynRcv,
    Established,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match self {
            State::SynRcv => false,
            State::Established => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    iph: Ipv4Header,
    tcp: TcpHeader,
}

struct SendSequenceSpace {
    /// send unacknowledge
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last windows update
    wl1: u32,
    /// segment acknowledge number ussed for last windows update
    wl2: u32,
    /// initial send sequence number
    iss: u32,
}

struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive winodw
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept(
        nic: &Device,
        iph: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        payload: &[u8],
    ) -> Result<Option<Self>, std::io::Error> {
        println!(
            "RST packet: {}:{} -> {}:{}, seq: {}, ack: {}, window: {}, payload length: {}",
            iph.source_addr(),
            tcp_header.source_port(),
            iph.destination_addr(),
            tcp_header.destination_port(),
            tcp_header.sequence_number(),
            tcp_header.acknowledgment_number(),
            tcp_header.window_size(),
            payload.len()
        );
        if !tcp_header.syn() {
            // We only handle SYN packets in LISTEN state
            return Ok(None);
        }

        let iss = 0;
        let wnd = 10;
        let mut c = Connection {
            state: State::SynRcv,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcp_header.sequence_number(),
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),
                up: false,
            },
            iph: Ipv4Header::new(0, 64, IpNumber::TCP, iph.destination(), iph.source()).unwrap(),
            tcp: TcpHeader::new(
                tcp_header.destination_port(),
                tcp_header.source_port(),
                iss, // TODO: use random sequence number
                wnd,
            ),
        };

        c.tcp.syn = true;
        c.tcp.ack = true;
        c.write(nic, &[])?;

        Ok(Some(c))
    }
    pub fn on_packet(
        &mut self,
        nic: &Device,
        iph: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        payload: &[u8],
    ) -> Result<(), std::io::Error> {
        if !between_wrapping(
            self.send.una,
            tcp_header.acknowledgment_number(),
            self.send.nxt.wrapping_add(1),
        ) {
            if !self.state.is_synchronized() {
                self.send_rst(nic)?;
            }
            return Ok(());
        };
        let start = self.recv.nxt.wrapping_sub(1);
        let seqn = tcp_header.sequence_number();
        let end = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let mut n = payload.len() as u32;
        if tcp_header.fin() {
            n += 1;
        }
        if tcp_header.syn() {
            n += 1;
        }
        if n == 0 {
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !between_wrapping(start, seqn, end) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !between_wrapping(start, seqn, end)
                && !between_wrapping(start, seqn.wrapping_add(n - 1), end)
            {
                return Ok(());
            }
        }

        match self.state {
            State::SynRcv => {
                if !tcp_header.ack() {
                    return Ok(());
                }
                todo!()
            }
            State::Established => todo!(),
        }
    }

    fn write(&mut self, nic: &Device, payload: &[u8]) -> std::io::Result<usize> {
        let mut buf = [0u8; 1500];

        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;
        let size = buf.len().min(self.tcp.header_len() + payload.len());
        self.iph
            .set_payload_len(size)
            .expect("Failed to set payload len");

        let mut unwritten = &mut buf[..];
        self.iph.write(&mut unwritten)?;
        self.tcp.write(&mut unwritten)?;
        let n = unwritten.write(payload)?;
        let unwritten = unwritten.len();

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.iph, &payload[..n])
            .expect("failed to compute checksum");

        self.send.nxt = self.send.nxt.wrapping_add(n as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }

        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(n)
    }

    fn send_rst(&mut self, nic: &Device) -> std::io::Result<()> {
        self.tcp.rst = true;
        // TODO: fix sequencee number here
        // TODO: handle synchronized RST
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;
        // TODO: Does it needed?
        // self.tcp.rst = false;
        Ok(())
    }
}

fn between_wrapping<T>(start: T, x: T, end: T) -> bool
where
    T: PartialOrd + Ord,
{
    match start.cmp(&end) {
        std::cmp::Ordering::Less => !(end >= start && end <= x),
        std::cmp::Ordering::Equal => false,
        std::cmp::Ordering::Greater => end < start && end > x,
    }
}
