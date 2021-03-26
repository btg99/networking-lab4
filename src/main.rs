use rand::{thread_rng, Fill};
use socket2::{Domain, Protocol, Socket, Type};
use stats::stddev;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Options {
    hostname: String,
    #[structopt(short = "s", default_value = "56")]
    packet_size: usize,
    #[structopt(short = "w", default_value = "2")]
    timeout: u64,
    #[structopt(short = "c")]
    max_transmitted: Option<usize>,
}

// Represents a logical ICMP packet.
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
    // Converts an ICMP packet struct into the corresponding series of bytes.
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

    // Tries to get an ICMP packet out of a slice of bytes.
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

// Represents an attempted transmission
struct Transmission {
    received: bool,
    round_trip_time: Duration,
}

// Function that computes the checksum using "1's complement addition."
// The code looks really complicated because Rust enforces a lot of
// correctness at the type level, but basically it just adds up all
// the numbers, while keeping track of how many times it overflowed.
// It then adds that number of times to the sum. If that overflows,
// then add 1. Finally invert all the bits.
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
    // Invert all the bits
    !checksum
}

// Tries to convert a hostname to a socket address
fn resolve_hostname(str: &str) -> Option<SocketAddr> {
    Some(
        (str, 0)
            .to_socket_addrs()
            .ok()?
            .filter(SocketAddr::is_ipv4)
            .next()?,
    )
}

// A helper function to determine if we need to stop sending
// ping requests. If no max was specified, it just goes forever.
fn done(transmitted: usize, max_transmitted: Option<usize>) -> bool {
    match max_transmitted {
        Some(max) => transmitted >= max,
        None => false,
    }
}

// Creates a raw socket connected to the specified address with the given timeout
fn connect_to(address: SocketAddr, timeout: Duration) -> Socket {
    let socket = Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4()))
        .expect("Invalid socket configuration.");
    socket
        .set_read_timeout(Some(timeout))
        .expect("Failed to set timeout on socket.");
    socket.connect(&address.into()).ok();
    socket
}

// A helper function for creating an echo request ICMP packet
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

// Sends an echo request ICMP packet to the given raw socket. It fills the
// data section of the packet with randomly generated data and keeps track
// of it so we can compare it later with echo response.
fn send_echo_request(
    identifier: u16,
    sequence_number: u16,
    packet_size: usize,
    socket: &Socket,
) -> Vec<u8> {
    let mut data = vec![0u8; packet_size];
    data.try_fill(&mut thread_rng())
        .expect("Could not generate random data for packet.");
    let msg = echo_message(identifier, sequence_number, &data);
    socket.send(&msg.as_bytes()).ok();
    data
}

// gets the ICMP packet part out of an IP datagram.
fn extract_icmp_message<'a>(bytes: &'a [u8]) -> Option<&'a [u8]> {
    // The internet header length (IHL) is the least significant 4 bits
    // of the first byte of the IP packet.
    let internet_header_length = bytes.get(0)? & 0b00001111;

    // The IHL gives the number of 32 bit words in the IP header.
    // Each 32 bit word is 4 `u8`s (aka bytes)
    let header_size: usize = internet_header_length as usize * 4;

    Some(&bytes[header_size..])
}

// Gets the ttl part of the IP datagram. It's something that the
// ping program reports to the user, but its in the IP datagram,
// not the ICMP packet.
fn extract_ttl(bytes: &[u8]) -> u8 {
    // the ttl field is the 8th byte in the IP packet
    bytes[8]
}

// Gets the ICMP packet and ttl out of the socket. It will block until
// the timeout expires waiting for the host to send a response.
fn receive_echo_reply<'a>(
    buffer: &'a mut [u8],
    data_sent: &[u8],
    socket: &Socket,
) -> Option<(ICMPMessage<'a>, u8)> {
    let length = socket.recv(buffer).ok()?;
    let bytes = extract_icmp_message(&buffer[..length])?;
    let ttl = extract_ttl(bytes);
    let msg = ICMPMessage::try_from_bytes(bytes)?;
    if msg.checksum == compute_checksum(&msg) && msg.data == data_sent {
        Some((msg, ttl))
    } else {
        None
    }
}

// Helped function to display the duration like the unix ping application does.
fn display_frac_millis(duration: &Duration) -> String {
    format!(
        "{}.{:0<3.3}",
        duration.as_millis(),
        (duration.as_micros() % 1000).to_string()
    )
}

// The meat of the program. It sends a request, waits for a response
// and keeps track of all the data that generates.
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
        let data_sent =
            send_echo_request(identifier, transmissions.len() as u16, packet_size, &socket);
        let mut buffer = vec![0; 1024];
        if let Some((reply, ttl)) = receive_echo_reply(&mut buffer, &data_sent, &socket) {
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

// Calculates and prints all the summary stats.
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

    let rtt_mdev: Duration = Duration::from_nanos(stddev(
        transmissions
            .iter()
            .map(|t| t.round_trip_time.as_nanos() as f64),
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
    let options = Options::from_args();
    let hostname = options.hostname;
    let packet_size = options.packet_size;
    let estimated_total_size = packet_size + 28;
    let timeout = Duration::from_secs(options.timeout);
    let max_transmitted = options.max_transmitted;

    if let Some(address) = resolve_hostname(&hostname) {
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
}
