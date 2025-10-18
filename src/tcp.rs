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
        let mut c = Connection {
            state: State::SynRcv,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
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
        };

        let mut syn_ack = TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            c.send.iss, // TODO: use random sequence number
            c.send.wnd,
        );
        syn_ack.acknowledgment_number = c.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;
        c.iph
            .set_payload_len(syn_ack.header_len())
            .expect("Failed to set payload len");

        syn_ack.checksum = syn_ack
            .calc_checksum_ipv4(&c.iph, &[])
            .expect("failed to compute checksum");

        let mut buf = [0u8; 1500];

        let unwritten = {
            let mut unwritten = &mut buf[..];
            c.iph.write(&mut unwritten).unwrap();
            syn_ack.write(&mut unwritten).unwrap();
            unwritten.len()
        };
        nic.send(&buf[..buf.len() - unwritten])?;
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
                // TODO: send a RST packet
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
            State::Listen => todo!(),
            State::SynRcv => {
                if !tcp_header.ack() {
                    return Ok(());
                }
                todo!()
            }
            State::Established => todo!(),
        }
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
