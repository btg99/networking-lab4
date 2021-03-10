use rand::{thread_rng, Fill};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
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
        bytes.extend_from_slice(&self.checksum.to_ne_bytes());
        bytes.extend_from_slice(&self.identifier.to_ne_bytes());
        bytes.extend_from_slice(&self.sequence_number.to_ne_bytes());
        bytes.extend_from_slice(self.data);
        bytes
    }

    fn try_from_bytes(bytes: &'a [u8]) -> Option<ICMPMessage<'a>> {
        Some(ICMPMessage {
            type_: *bytes.get(0)?,
            code: *bytes.get(1)?,
            checksum: u16::from_ne_bytes([*bytes.get(2)?, *bytes.get(3)?]),
            identifier: u16::from_ne_bytes([*bytes.get(4)?, *bytes.get(5)?]),
            sequence_number: u16::from_ne_bytes([*bytes.get(6)?, *bytes.get(7)?]),
            data: &bytes[8..],
        })
    }
}

struct Transmission {
    received: bool,
    round_trip_time: Duration,
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
                    checksum.overflowing_add(u16::from_ne_bytes([*lower, *upper]));
                checksum = value;
                if overflowed {
                    overflows += 1;
                }
            }
            (Some(lower), None) => {
                let (value, overflowed) =
                    checksum.overflowing_add(u16::from_ne_bytes([*lower, 0u8]));
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

fn resolve_hostname(str: &str) -> Option<SocketAddr> {
    Some(
        (str, 0)
            .to_socket_addrs()
            .ok()?
            .filter(SocketAddr::is_ipv4)
            .next()?,
    )
}

fn done(transmitted: usize, max_transmitted: Option<usize>) -> bool {
    match max_transmitted {
        Some(max) => transmitted >= max,
        None => false,
    }
}

fn connect_to(address: SocketAddr, timeout: Duration) -> Socket {
    let socket = Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4()))
        .expect("Invalid socket configuration.");
    socket
        .set_read_timeout(Some(timeout))
        .expect("Failed to set timeout on socket.");
    socket.connect(&address.into()).ok();
    socket
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

fn send_echo_request(identifier: u16, sequence_number: u16, packet_size: usize, socket: &Socket) {
    let mut data = vec![0u8; packet_size];
    data.try_fill(&mut thread_rng())
        .expect("Could not generate random data for packet.");
    let msg = echo_message(identifier, sequence_number, &data);
    socket.send(&msg.as_bytes()).ok();
}

fn extract_icmp_message<'a>(bytes: &'a [u8]) -> Option<&'a [u8]> {
    // The internet header length (IHL) is the least significant 4 bits
    // of the first byte of the IP packet.
    let internet_header_length = bytes.get(0)? & 0b00001111;

    // The IHL gives the number of 32 bit words in the IP header.
    // Each 32 bit word is 4 `u8`s (aka bytes)
    let header_size: usize = internet_header_length as usize * 4;

    Some(&bytes[header_size..])
}

fn extract_ttl(bytes: &[u8]) -> u8 {
    // the ttl field is the 8th byte in the IP packet
    bytes[8]
}

fn receive_echo_reply<'a>(buffer: &'a mut [u8], socket: &Socket) -> Option<(ICMPMessage<'a>, u8)> {
    let length = socket.recv(buffer).ok()?;
    let bytes = extract_icmp_message(&buffer[..length])?;
    let ttl = extract_ttl(bytes);
    let msg = ICMPMessage::try_from_bytes(bytes)?;
    Some((msg, ttl))
}

fn display_frac_millis(duration: &Duration) -> String {
    format!(
        "{}.{:0<3.3}",
        duration.as_millis(),
        duration.subsec_millis().to_string()
    )
}

fn ping_address(
    address: SocketAddr,
    timeout: Duration,
    packet_size: usize,
    max_transmitted: Option<usize>,
) -> Vec<Transmission> {
    let mut transmissions = Vec::new();
    let identifier = std::process::id() as u16;
    let socket = connect_to(address.clone(), timeout);

    while !done(transmissions.len(), max_transmitted) {
        let timer = Instant::now();
        send_echo_request(identifier, transmissions.len() as u16, packet_size, &socket);
        let mut buffer = vec![0; 1024];
        if let Some((reply, ttl)) = receive_echo_reply(&mut buffer, &socket) {
            let elapsed = timer.elapsed();

            println!(
                "{} bytes from {}: icmp_seq={} ttl={} time={} ms",
                reply.data.len(),
                address.ip(),
                transmissions.len(),
                ttl,
                display_frac_millis(&elapsed)
            );

            transmissions.push(Transmission {
                received: true,
                round_trip_time: elapsed,
            })
        } else {
            transmissions.push(Transmission {
                received: false,
                round_trip_time: timer.elapsed(),
            })
        }
    }

    transmissions
}

fn print_stats(transmissions: Vec<Transmission>, time: Duration) {
    let transmitted = transmissions.len();
    let length = if transmitted > 0 { transmitted } else { 1 };
    let received = transmissions.iter().filter(|t| t.received).count();
    let packet_loss = 100.0 - (received as f64 / transmitted as f64 * 100f64);
    let rtt_min = transmissions
        .iter()
        .map(|t| t.round_trip_time)
        .min()
        .unwrap_or_default();
    let rtt_avg: Duration = transmissions
        .iter()
        .map(|t| t.round_trip_time)
        .sum::<Duration>()
        / length as u32;
    let rtt_max = transmissions
        .iter()
        .map(|t| t.round_trip_time)
        .max()
        .unwrap_or_default();
    let rtt_mdev: Duration = Duration::from_nanos(f64::sqrt(
        transmissions
            .iter()
            .map(|t| t.round_trip_time.as_nanos() as f64)
            .map(|x| x - rtt_avg.as_nanos() as f64)
            .map(|x| x * x)
            .sum::<f64>()
            / length as f64,
    ) as u64);

    println!(
        "{} packets transmitted, {} received, {:.0}% packet loss, time {}ms",
        transmitted,
        received,
        packet_loss,
        time.as_millis()
    );
    println!(
        "rtt min/avg/max/mdev = {}/{}/{}/{} ms",
        display_frac_millis(&rtt_min),
        display_frac_millis(&rtt_avg),
        display_frac_millis(&rtt_max),
        display_frac_millis(&rtt_mdev)
    );
}

fn main() {
    let hostname = "google.com";
    let packet_size = 56;
    let estimated_total_size = packet_size + 28;
    let timeout = Duration::from_secs(1);
    let max_transmitted = Some(4);

    if let Some(address) = resolve_hostname(hostname) {
        println!(
            "PING {} ({}) {}({}) bytes of data.",
            hostname,
            address.ip(),
            packet_size,
            estimated_total_size
        );

        let timer = Instant::now();
        let transmissions = ping_address(address, timeout, packet_size, max_transmitted);
        println!("\n--- {} ping statistics ---", hostname);
        print_stats(transmissions, timer.elapsed());
    } else {
        eprintln!("Hostname resolution failed for {}.", hostname);
    }

    /*
    let data = [0, 1, 2, 3];
    let identifier = 15;
    let msg = echo_message(identifier, 5, &data);
    println!("Sent: {:?}", msg);


    socket.send(&msg.as_bytes()).unwrap();
    let mut buffer = vec![0; 1024];
    let length = socket.recv(&mut buffer).unwrap();
    let message = extract_icmp_message(&buffer[..length]).unwrap();
    println!("Got: {:?}", ICMPMessage::from_bytes(message)); */
}
