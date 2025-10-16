use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use tun::Device;

pub enum TcpState {
    Closed,
    Listen,
    SynRcv,
    Established,
}

impl Default for TcpState {
    fn default() -> Self {
        Self::Listen
    }
}

impl TcpState {
    pub fn on_packet(
        &mut self,
        nic: &Device,
        iph: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        payload: &[u8],
    ) -> Result<usize, std::io::Error> {
        println!(
            "\tTCP packet: {}:{} -> {}:{}, seq: {}, ack: {}, window: {}, payload length: {}",
            iph.source_addr(),
            tcp_header.source_port(),
            iph.destination_addr(),
            tcp_header.destination_port(),
            tcp_header.sequence_number(),
            tcp_header.acknowledgment_number(),
            tcp_header.window_size(),
            payload.len()
        );
        match self {
            TcpState::Closed => return Ok(0),
            TcpState::Listen => {
                if !tcp_header.syn() {
                    // We only handle SYN packets in LISTEN state
                    return Ok(0);
                }

                let mut syn_ack = TcpHeader::new(
                    tcp_header.destination_port(),
                    tcp_header.source_port(),
                    todo!(),
                    todo!(),
                );
                syn_ack.syn = true;
                syn_ack.ack = true;

                let mut ip = Ipv4Header::new(
                    syn_ack.header_len_u16(),
                    64,
                    IpNumber::TCP,
                    iph.destination(),
                    iph.source(),
                )
                .unwrap();
                let mut buf = [0u8; 1500];

                let unwritten = {
                    let mut unwritten = &mut buf[..];
                    ip.write(&mut unwritten).unwrap();
                    syn_ack.write(&mut unwritten).unwrap();
                    unwritten.len()
                };
                *self = TcpState::SynRcv;
                nic.send(&buf[..unwritten])
            }
            TcpState::SynRcv => todo!(),
            TcpState::Established => todo!(),
        }
    }
}
