use std::collections::BinaryHeap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::cmp::Reverse;
use clap::{Command, Arg};
use pcap::Capture;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::packet::udp::UdpPacket;

#[derive(Debug)]
struct QuoteMessage {
    packet_time: SystemTime,
    accept_time: SystemTime,
    issue_code: String,
    bids: Vec<(u64, u64)>, // (quantity, price)
    asks: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, Copy)]
enum OutputFormat {
    Default,
    Formatted,
}

fn parse_quote_message(
    packet_data: &[u8],
    packet_time: SystemTime,
) -> Option<QuoteMessage> {
    let mut offset = 0;

    // Check if the packet starts with "B6034"
    if packet_data.len() < 5 || &packet_data[..5] != b"B6034" {
        return None;
    }
    offset += 5;

    // Issue code: 12 bytes
    if packet_data.len() < offset + 12 {
        return None;
    }
    let issue_code = packet_data[offset..offset + 12]
        .iter()
        .map(|&b| if b.is_ascii() && !b.is_ascii_control() { b } else { b'.' })
        .collect::<Vec<u8>>();
    let issue_code = String::from_utf8(issue_code).unwrap_or_else(|_| "INVALID".to_string());
    offset += 12;

    // Skip fields until we reach bids and asks
    // Total of 7 bytes for issue seq no, market status, total bid quote volume
    offset += 3 + 2 + 7;

    let mut bids = Vec::new();
    for _ in 0..5 {
        if packet_data.len() < offset + 5 + 7 {
            return None;
        }
        let price_str = packet_data[offset..offset + 5]
            .iter()
            .map(|&b| if b.is_ascii_digit() { b } else { b'0' })
            .collect::<Vec<u8>>();
        let price = String::from_utf8(price_str)
            .unwrap_or_else(|_| "0".to_string())
            .parse::<u64>()
            .unwrap_or(0);
        offset += 5;

        let qty_str = packet_data[offset..offset + 7]
            .iter()
            .map(|&b| if b.is_ascii_digit() { b } else { b'0' })
            .collect::<Vec<u8>>();
        let qty = String::from_utf8(qty_str)
            .unwrap_or_else(|_| "0".to_string())
            .parse::<u64>()
            .unwrap_or(0);
        offset += 7;
        bids.push((qty, price));
    }

    // Skip total ask quote volume: 7 bytes
    offset += 7;

    let mut asks = Vec::new();
    for _ in 0..5 {
        if packet_data.len() < offset + 5 + 7 {
            return None;
        }
        let price_str = packet_data[offset..offset + 5]
            .iter()
            .map(|&b| if b.is_ascii_digit() { b } else { b'0' })
            .collect::<Vec<u8>>();
        let price = String::from_utf8(price_str)
            .unwrap_or_else(|_| "0".to_string())
            .parse::<u64>()
            .unwrap_or(0);
        offset += 5;

        let qty_str = packet_data[offset..offset + 7]
            .iter()
            .map(|&b| if b.is_ascii_digit() { b } else { b'0' })
            .collect::<Vec<u8>>();
        let qty = String::from_utf8(qty_str)
            .unwrap_or_else(|_| "0".to_string())
            .parse::<u64>()
            .unwrap_or(0);
        offset += 7;
        asks.push((qty, price));
    }

    // Skip No. of best bid/ask valid quote and counts
    offset += 5 + 4 * 5 + 5 + 4 * 5;

    // Quote accept time: 8 bytes (HHMMSSuu)
    if packet_data.len() < offset + 8 {
        return None;
    }
    let time_str = packet_data[offset..offset + 8]
        .iter()
        .map(|&b| if b.is_ascii_digit() { b } else { b'0' })
        .collect::<Vec<u8>>();
    let time_str = String::from_utf8(time_str).unwrap_or_else(|_| "00000000".to_string());

    // Parse accept time
    let accept_time = parse_accept_time(&time_str, packet_time)?;

    Some(QuoteMessage {
        packet_time,
        accept_time,
        issue_code,
        bids,
        asks,
    })
}

fn parse_accept_time(s: &str, packet_time: SystemTime) -> Option<SystemTime> {
    if s.len() != 8 {
        return None;
    }
    let hour = s[0..2].parse::<u64>().ok()?;
    let min = s[2..4].parse::<u64>().ok()?;
    let sec = s[4..6].parse::<u64>().ok()?;
    let micros = s[6..8].parse::<u64>().ok()? * 10_000;

    let packet_midnight = {
        let duration = packet_time.duration_since(UNIX_EPOCH).ok()?;
        let days = duration.as_secs() / 86400;
        UNIX_EPOCH + Duration::from_secs(days * 86400)
    };

    Some(packet_midnight + Duration::from_secs(hour * 3600 + min * 60 + sec) + Duration::from_micros(micros))
}

fn main() {
    let matches = Command::new("parse-quote")
        .version("1.0")
        .author("Market Data Parser")
        .about("Parses KOSPI200 market data from PCAP files")
        .arg(
            Arg::new("input")
                .help("Input PCAP file")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("reorder")
                .short('r')
                .long("reorder")
                .help("Reorder messages by accept time")
                .takes_value(false),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Use formatted output")
                .takes_value(false),
        )
        .get_matches();

    let input_file = matches.value_of("input").unwrap();
    let reorder = matches.is_present("reorder");
    let output_format = if matches.is_present("output") {
        OutputFormat::Formatted
    } else {
        OutputFormat::Default
    };
    
    // Open the pcap file
    let mut cap = Capture::from_file(input_file).expect("Failed to open pcap file");
    
    // Create a binary heap to store messages sorted by accept_time
    let mut message_buffer: BinaryHeap<Reverse<QuoteMessage>> = BinaryHeap::new();
    let mut latest_packet_time = None;

    while let Ok(packet) = cap.next_packet() {
        if let Some(ethernet) = EthernetPacket::new(packet.data) {
            if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        if let Some(udp_packet) = UdpPacket::new(ipv4.payload()) {
                            let dst_port = udp_packet.get_destination();

                            if dst_port == 15515 || dst_port == 15516 {
                                let udp_payload = udp_packet.payload();
                                let packet_time = SystemTime::UNIX_EPOCH + 
                                    Duration::from_secs(packet.header.ts.tv_sec as u64) +
                                    Duration::from_micros(packet.header.ts.tv_usec as u64);
                                    
                                if let Some(msg) = parse_quote_message(udp_payload, packet_time) {
                                    if reorder {
                                        // Update latest accept time seen
                                        latest_packet_time = Some(match latest_packet_time {
                                            Some(t) => std::cmp::max(t, msg.accept_time),
                                            None => msg.accept_time,
                                        });

                                        message_buffer.push(Reverse(msg));
                                        
                                        // Process messages that are ready (older than 3 seconds from latest accept time)
                                        if let Some(latest_time) = latest_packet_time {
                                            while let Some(Reverse(msg)) = message_buffer.peek() {
                                                if latest_time.duration_since(msg.accept_time).unwrap() > Duration::from_secs(3) {
                                                    if let Some(Reverse(msg)) = message_buffer.pop() {
                                                        output_message(&msg, output_format);
                                                    }
                                                } else {
                                                    break;
                                                }
                                            }
                                        }
                                    } else {
                                        // If not reordering, output messages immediately
                                        output_message(&msg, output_format);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Output remaining messages in the buffer if reordering was enabled
    if reorder {
        while let Some(Reverse(msg)) = message_buffer.pop() {
            output_message(&msg, output_format);
        }
    }
}

fn output_message(msg: &QuoteMessage, format: OutputFormat) {
    match format {
        OutputFormat::Default => {
            let mut output = format!("{} {} {}", 
                format_system_time(msg.packet_time),
                format_system_time(msg.accept_time),
                msg.issue_code.trim()
            );
            
            // Add bids (from highest to lowest)
            for &(qty, price) in msg.bids.iter().rev() {
                output.push_str(&format!(" {}@{}", qty, price));
            }
            
            // Add asks (from lowest to highest)
            for &(qty, price) in msg.asks.iter() {
                output.push_str(&format!(" {}@{}", qty, price));
            }
            
            println!("{}", output);
        }
        OutputFormat::Formatted => {
            println!("Packet-Time: {} | Accept-Time: {} | Issue-Code: {}", 
                format_system_time(msg.packet_time),
                format_system_time(msg.accept_time),
                msg.issue_code.trim()
            );
            
            print!("Bids: ");
            for (i, &(qty, price)) in msg.bids.iter().rev().enumerate() {
                if i > 0 {
                    print!(", ");
                }
                print!("{}@{}", qty, price);
            }
            
            print!(" | Asks: ");
            for (i, &(qty, price)) in msg.asks.iter().enumerate() {
                if i > 0 {
                    print!(", ");
                }
                print!("{}@{}", qty, price);
            }
            println!();
        }
    }
}

fn format_system_time(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap();
    format!("{}.{:06}", d.as_secs(), d.subsec_micros())
}

// Implement ordering for QuoteMessage based on accept_time
impl PartialEq for QuoteMessage {
    fn eq(&self, other: &Self) -> bool {
        self.accept_time == other.accept_time
    }
}

impl Eq for QuoteMessage {}

impl PartialOrd for QuoteMessage {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QuoteMessage {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.accept_time.cmp(&other.accept_time)
    }
}
