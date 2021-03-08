use rawsock::OwnedPacket;
use time::Timespec;

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
        vec![
            self.type_,
            self.code,
        ]
    }
}

fn echo_message<'a>(identifier: u16, sequence_number: u16, data: &'a [u8]) -> ICMPMessage {
    ICMPMessage {
        type_: 8,
        code: 0,
        checksum: 0, // TODO: Implement checksum
        identifier,
        sequence_number,
        data
    }
}

fn main() {
    let data = [0, 1, 2, 3];
    let msg = echo_message(15, 5, &data);
    let packet = OwnedPacket::new(&msg.as_bytes(), Timespec::new(1, 0));
}
