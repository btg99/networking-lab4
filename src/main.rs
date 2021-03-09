use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;

#[derive(Clone)]
struct ICMPMessage<'a> {
    type_: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence_number: u16,
    data: &'a [u8],
}

impl<'a> ICMPMessage<'a> {
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.type_);
        bytes.push(self.code);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.identifier.to_be_bytes());
        bytes.extend_from_slice(&self.sequence_number.to_be_bytes());
        bytes.extend_from_slice(self.data);
        bytes
    }
}

fn compute_checksum(msg: &ICMPMessage) -> u16 {
    let msg = ICMPMessage {
        checksum: 0,
        ..msg.clone()
    };
    let mut overflows: u16 = 0;
    let mut checksum: u16 = 0;
    for byte_pair in msg.as_bytes().chunks(2) {
        match (byte_pair.get(0), byte_pair.get(1)) {
            (Some(lower), Some(upper)) => {
                let (value, overflowed) =
                    checksum.overflowing_add(u16::from_be_bytes([*lower, *upper]));
                checksum = value;
                if overflowed {
                    overflows += 1;
                }
            }
            (Some(lower), None) => {
                let (value, overflowed) =
                    checksum.overflowing_add(u16::from_be_bytes([*lower, 0u8]));
                checksum = value;
                if overflowed {
                    overflows += 1;
                }
            }
            _ => {}
        }
    }
    let (mut checksum, overflowed) = checksum.overflowing_add(overflows);
    if overflowed {
        checksum += 1;
    }
    !checksum
}

fn echo_message<'a>(identifier: u16, sequence_number: u16, data: &'a [u8]) -> ICMPMessage {
    let mut msg = ICMPMessage {
        type_: 8,
        code: 0,
        checksum: 0,
        identifier,
        sequence_number,
        data,
    };
    msg.checksum = compute_checksum(&msg);
    msg
}

fn main() {
    let data = [0, 1, 2, 3];
    let identifier = 15;
    let msg = echo_message(identifier, 5, &data);

    let socket = Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4()))
        .expect("Invalid socket configuration.");
    socket
        .connect(&"172.217.9.78:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    socket.send(&msg.as_bytes()).unwrap();
    let mut buffer = vec![0; 1000];
    socket.recv(&mut buffer).unwrap();
    println!("{:?}", buffer);
}
