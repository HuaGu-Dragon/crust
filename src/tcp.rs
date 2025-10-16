use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

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
    pub fn on_packet(&mut self, iph: Ipv4HeaderSlice, tcp_header: TcpHeaderSlice, payload: &[u8]) {
        match self {
            TcpState::Closed => return,
            TcpState::Listen => {
                if !tcp_header.syn() {
                    // We only handle SYN packets in LISTEN state
                    return;
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
                );
                *self = TcpState::SynRcv;
            }
            TcpState::SynRcv => todo!(),
            TcpState::Established => todo!(),
        }
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
    }
}
