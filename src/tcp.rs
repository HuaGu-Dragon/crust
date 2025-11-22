use bitflags::bitflags;
use std::{
    collections::VecDeque,
    io::{self, Write},
};
use tun_rs::SyncDevice;

use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

bitflags! {
    pub(crate) struct Available: u8 {
        const READ  = 0b00000001;
        const WRITE = 0b00000010;
    }

}

#[derive(Debug)]
enum State {
    SynRcv,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    TimeWait,
    LastAck,
    Closed,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match self {
            State::SynRcv => false,
            State::Established
            | State::FinWait1
            | State::FinWait2
            | Self::TimeWait
            | Self::Closing
            | Self::CloseWait
            | Self::LastAck
            | Self::Closed => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    iph: Ipv4Header,
    tcp: TcpHeader,

    pub(crate) incomming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,

    closed_at: Option<u32>,
}

struct SendSequenceSpace {
    /// send unacknowledge
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    // /// send urgent pointer
    // up: bool,
    // /// segment sequence number used for last windows update
    // wl1: u32,
    // /// segment acknowledge number ussed for last windows update
    // wl2: u32,
    // /// initial send sequence number
    // iss: u32,
}

struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive winodw
    wnd: u16,
    // /// receive urgent pointer
    // up: bool,
    // /// initial receive sequence number
    // irs: u32,
}

impl Connection {
    pub fn is_rcv_closed(&self) -> bool {
        matches!(self.state, State::TimeWait | State::Closed)
    }

    fn availability(&self) -> Available {
        let mut available = Available::empty();

        if self.is_rcv_closed() || !self.incomming.is_empty() {
            available |= Available::READ;
        }

        available
    }

    pub fn accept(
        nic: &SyncDevice,
        iph: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        _payload: &[u8],
    ) -> Result<Option<Self>, std::io::Error> {
        // println!(
        //     "RST packet: {}:{} -> {}:{}, seq: {}, ack: {}, window: {}, payload length: {}",
        //     iph.source_addr(),
        //     tcp_header.source_port(),
        //     iph.destination_addr(),
        //     tcp_header.destination_port(),
        //     tcp_header.sequence_number(),
        //     tcp_header.acknowledgment_number(),
        //     tcp_header.window_size(),
        //     payload.len()
        // );
        if !tcp_header.syn() {
            // We only handle SYN packets in LISTEN state
            return Ok(None);
        }

        let iss = 0;
        let mut c = Connection {
            state: State::SynRcv,
            send: SendSequenceSpace {
                // iss,
                una: iss,
                nxt: iss,
                wnd: tcp_header.window_size(),
                // up: false,
                // wl1: 0,
                // wl2: 0,
            },
            recv: RecvSequenceSpace {
                // irs: tcp_header.sequence_number(),
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),
                // up: false,
            },
            iph: Ipv4Header::new(0, 64, IpNumber::TCP, iph.destination(), iph.source()).unwrap(),
            tcp: TcpHeader::new(
                tcp_header.destination_port(),
                tcp_header.source_port(),
                iss, // TODO: use random sequence number
                u16::MAX,
            ),
            incomming: Default::default(),
            unacked: Default::default(),
            closed_at: None,
        };

        c.tcp.syn = true;
        c.tcp.ack = true;
        c.write(nic, c.send.nxt, 0)?;

        Ok(Some(c))
    }
    pub(crate) fn on_packet(
        &mut self,
        nic: &SyncDevice,
        _iph: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        payload: &[u8],
    ) -> Result<Available, std::io::Error> {
        // Sequence number validation according to RFC 793
        let seqn = tcp_header.sequence_number();
        let mut seg_len = payload.len() as u32;
        if tcp_header.fin() {
            seg_len += 1;
        }
        if tcp_header.syn() {
            seg_len += 1;
        }

        let rcv_wnd = self.recv.wnd as u32;
        let is_valid = if seg_len == 0 {
            // Zero length segment
            if rcv_wnd == 0 {
                seqn == self.recv.nxt
            } else {
                // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                between_wrapping(
                    self.recv.nxt.wrapping_sub(1),
                    seqn,
                    self.recv.nxt.wrapping_add(rcv_wnd),
                )
            }
        } else {
            // Segment with data
            if rcv_wnd == 0 {
                false
            } else {
                // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                // or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
                let seg_end = seqn.wrapping_add(seg_len - 1);
                between_wrapping(
                    self.recv.nxt.wrapping_sub(1),
                    seqn,
                    self.recv.nxt.wrapping_add(rcv_wnd),
                ) || between_wrapping(
                    self.recv.nxt.wrapping_sub(1),
                    seg_end,
                    self.recv.nxt.wrapping_add(rcv_wnd),
                )
            }
        };

        if !is_valid {
            // Send ACK for invalid sequence number
            if tcp_header.ack() {
                self.write(nic, self.send.nxt, 0)?;
            }
            return Ok(self.availability());
        }

        // Process RST
        if tcp_header.rst() {
            match self.state {
                State::SynRcv => {
                    // Return to LISTEN (connection will be removed)
                    self.state = State::Closed;
                    return Ok(self.availability());
                }
                State::Established | State::FinWait1 | State::FinWait2 | State::CloseWait => {
                    // Close the connection
                    self.state = State::Closed;
                    return Ok(self.availability());
                }
                _ => {}
            }
        }

        // Process SYN in synchronized states
        if tcp_header.syn() && self.state.is_synchronized() {
            // This is an error - send RST and close
            self.state = State::Closed;
            return Ok(self.availability());
        }

        if !tcp_header.ack() {
            if tcp_header.syn() {
                assert!(payload.is_empty());
                self.recv.nxt = seqn.wrapping_add(seg_len);
            }
            return Ok(self.availability());
        }

        // Process ACK
        let ack = tcp_header.acknowledgment_number();

        if let State::SynRcv = self.state {
            if between_wrapping(
                self.send.una.wrapping_sub(1),
                ack,
                self.send.nxt.wrapping_add(1),
            ) {
                // Update send.una to acknowledge the SYN
                self.send.una = ack;
                self.state = State::Established;
            } else {
                // TODO: RST
                return Ok(self.availability());
            }
        }

        // Process ACK in synchronized states
        if let State::Established
        | State::FinWait1
        | State::FinWait2
        | State::CloseWait
        | State::Closing
        | State::LastAck = self.state
            && between_wrapping(self.send.una, ack, self.send.nxt.wrapping_add(1))
        {
            let data_acked = ack.wrapping_sub(self.send.una) as usize;
            self.send.una = ack;
            // Remove acknowledged bytes from unacked queue
            if data_acked > 0 && data_acked <= self.unacked.len() {
                drop(self.unacked.drain(..data_acked));
            }
            // Update send window
            self.send.wnd = tcp_header.window_size();
        }

        // Check if our FIN has been acknowledged
        if let State::FinWait1 = self.state
            && let Some(closed_at) = self.closed_at
            && self.send.una == closed_at.wrapping_add(1)
        {
            self.state = State::FinWait2;
        }

        if let State::Closing = self.state
            && let Some(closed_at) = self.closed_at
            && self.send.una == closed_at.wrapping_add(1)
        {
            self.state = State::TimeWait;
            return Ok(self.availability());
        }

        if let State::LastAck = self.state
            && let Some(closed_at) = self.closed_at
            && self.send.una == closed_at.wrapping_add(1)
        {
            self.state = State::Closed;
            return Ok(self.availability());
        }

        // Process payload data
        if !payload.is_empty() {
            match self.state {
                State::Established | State::FinWait1 | State::FinWait2 => {
                    // Check if this is the data we're expecting
                    if seqn == self.recv.nxt {
                        // In-order data, accept it
                        self.incomming.extend(payload);
                        self.recv.nxt = self.recv.nxt.wrapping_add(payload.len() as u32);
                        // Send ACK for received data
                        self.write(nic, self.send.nxt, 0)?;
                    } else if wrapping_lt(seqn, self.recv.nxt) {
                        // Old/duplicate data
                        // Check if there's any new data in this segment
                        let already_received = self.recv.nxt.wrapping_sub(seqn) as usize;
                        if already_received < payload.len() {
                            // Part of the segment is new data
                            self.incomming.extend(&payload[already_received..]);
                            self.recv.nxt = self
                                .recv
                                .nxt
                                .wrapping_add((payload.len() - already_received) as u32);
                        }
                        // Send ACK (could be duplicate ACK if all data was old)
                        self.write(nic, self.send.nxt, 0)?;
                    }
                    // else: future data, drop it (we don't have out-of-order buffering)
                }
                State::CloseWait | State::Closing | State::LastAck | State::TimeWait => {
                    // Ignore data in these states
                }
                _ => {}
            }
        }

        // Process FIN (must be after payload processing)
        if tcp_header.fin() {
            match self.state {
                State::Established => {
                    // Peer is closing - advance recv.nxt for the FIN
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    // Send ACK for the FIN
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::CloseWait;
                }
                State::FinWait1 => {
                    // Simultaneous close
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.write(nic, self.send.nxt, 0)?;

                    // Check if our FIN was also acknowledged
                    if let Some(closed_at) = self.closed_at {
                        if self.send.una == closed_at.wrapping_add(1) {
                            // Both FINs exchanged
                            self.state = State::TimeWait;
                        } else {
                            // We got FIN but our FIN not acked yet
                            self.state = State::Closing;
                        }
                    }
                }
                State::FinWait2 => {
                    // Normal close - peer sends FIN after we sent ours
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::TimeWait;
                }
                State::CloseWait | State::Closing | State::LastAck => {
                    // FIN already processed
                }
                State::TimeWait => {
                    // Restart TIME-WAIT timer (not implemented yet)
                }
                _ => {}
            }
        }

        Ok(self.availability())
    }

    fn write(&mut self, nic: &SyncDevice, seq: u32, mut limit: usize) -> std::io::Result<usize> {
        let mut buf = [0u8; 1500];

        self.tcp.sequence_number = seq;
        self.tcp.acknowledgment_number = self.recv.nxt;

        // Update receive window based on available buffer space
        let available = (u16::MAX as usize).saturating_sub(self.incomming.len());
        self.tcp.window_size = available.min(u16::MAX as usize) as u16;

        let mut offset = seq.wrapping_sub(self.send.una) as usize;

        eprintln!(
            "DEBUG write(): seq={}, send.una={}, send.nxt={}, offset={}, unacked.len={}, limit={}",
            seq,
            self.send.una,
            self.send.nxt,
            offset,
            self.unacked.len(),
            limit
        );

        if let Some(closed_at) = self.closed_at
            && seq == closed_at.wrapping_add(1)
        {
            // trying to write following FIN
            offset = 0;
            limit = 0;
        }

        let (mut h, mut t) = self.unacked.as_slices();
        if h.len() >= offset {
            h = &h[offset..];
        } else {
            let skipped = h.len();
            h = &[];
            t = &t[offset - skipped..];
        }

        let max_data = std::cmp::min(limit, h.len() + t.len());
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() + self.iph.header_len() + max_data,
        );
        self.iph
            .set_payload_len(size - self.iph.header_len())
            .expect("Failed to set payload len");

        let buf_len = buf.len();
        let mut unwritten = &mut buf[..];

        self.iph.write(&mut unwritten)?;
        let ip_header_end_at = buf_len - unwritten.len();

        unwritten = &mut unwritten[self.tcp.header_len()..];
        let tcp_header_end_at = buf_len - unwritten.len();

        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;

            let head = std::cmp::min(limit, h.len());
            written += unwritten.write(&h[..head])?;
            limit -= written;

            let tail = std::cmp::min(limit, t.len());
            written += unwritten.write(&t[..tail])?;

            written
        };
        let payload_end_at = buf_len - unwritten.len();
        assert!(payload_bytes == payload_end_at - tcp_header_end_at);

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.iph, &buf[tcp_header_end_at..payload_end_at])
            .expect("failed to compute checksum");

        let mut tcp_header_buf = &mut buf[ip_header_end_at..tcp_header_end_at];
        self.tcp.write(&mut tcp_header_buf)?;

        let mut next_seq = seq.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.fin = false;
        }

        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }
        // self.timers.send_times.insert(seq, time::Instant::now());

        nic.send(&buf[..payload_end_at])?;
        // eprintln!(
        //     "DEBUG write(): sent {} bytes, next_seq={}, payload_end_at={}",
        //     payload_bytes, next_seq, payload_end_at
        // );
        Ok(payload_bytes)
    }

    pub(crate) fn on_tick(&mut self, nic: &SyncDevice) -> std::io::Result<()> {
        if !self.unacked.is_empty() {
            self.tcp.psh = true;
            // Calculate how much we can send based on peer's window and data in flight
            let inflight = self.send.nxt.wrapping_sub(self.send.una) as usize;
            let available_window = (self.send.wnd as usize).saturating_sub(inflight);
            let size = std::cmp::min(self.unacked.len(), available_window);
            if size > 0 {
                self.write(nic, self.send.una, size)?;
            }
            self.tcp.psh = false;
        }

        if let State::CloseWait = self.state {
            self.tcp.fin = true;
            self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            self.write(nic, self.send.una, 0)?;
            self.state = State::LastAck;
        }

        Ok(())
    }

    pub(crate) fn close(&mut self) -> std::io::Result<()> {
        match self.state {
            State::SynRcv | State::Established => {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
                self.state = State::FinWait1;
            }

            State::CloseWait => {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
                self.state = State::LastAck;
            }

            State::FinWait1 | State::FinWait2 | State::LastAck => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "already closed",
                ));
            }
        };

        Ok(())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // lhs < rhs in modular arithmetic
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn between_wrapping(start: u32, x: u32, end: u32) -> bool
where
    u32: PartialOrd + Ord,
{
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
