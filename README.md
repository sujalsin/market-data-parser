# Market Data Parser

A Rust program that parses and prints quote messages from a market data feed PCAP file. The program can optionally reorder messages according to the quote accept time at the exchange.

## Features

- Parses UDP packets containing quote messages (starting with "B6034")
- Displays packet time, quote accept time, issue code, and bid/ask information
- Optional reordering of messages by quote accept time (-r flag)
- Efficient handling of large PCAP files

## Building

Ensure you have Rust installed (latest stable version), then:

```bash
cargo build --release
```

After building, create a symbolic link to make the executable easier to access:
```bash
ln -sf target/release/market-data-parser parse-quote
```

## Usage

Basic usage with sample KOSPI200 data:
```bash
./parse-quote mdf-kospi200.20110216-0.pcap
```

To reorder messages by quote accept time:
```bash
./parse-quote -r mdf-kospi200.20110216-0.pcap
```

## Output Format

The program has two different output formats depending on the flags used:

1. Default format (no -o flag):
```
<pkt-time> <accept-time> <issue-code> <bqty5>@<bprice5> ... <bqty1>@<bprice1> <aqty1>@<aprice1> ... <aqty5>@<aprice5>
```

2. With -o flag format:
```
Packet-Time: <timestamp> | Accept-Time: <timestamp> | Issue-Code: <code>
Bids: <qty>@<price>, <qty>@<price>, ... | Asks: <qty>@<price>, <qty>@<price>, ...
```

Example of default output:
```
09:30:00.123456 09:30:00.123400 US0378331005 500@182.50 300@182.45 100@182.40 50@182.35 25@182.30 100@182.55 200@182.60 300@182.65 400@182.70 500@182.75
```

Example of -o flag output:
```
Packet-Time: 1297814428.938676 | Accept-Time: 1297846828.900000 | Issue-Code: KR4301F62601
Bids: 0@765, 0@770, 0@775, 0@780, 15@785 | Asks: 15
```

Where:
- `pkt-time`: Time the packet was captured
- `accept-time`: Time the quote was accepted at the exchange
- `issue-code`: ISIN code of the security
- `bqtyN`: Quantity at the Nth best bid price
- `bpriceN`: Nth best bid price
- `aqtyN`: Quantity at the Nth best ask price
- `apriceN`: Nth best ask price

## Error Handling

Common errors and their solutions:

- `invalid_argument: validation error: chat_message_prompts: value must contain at least 1 item(s)`: This error occurs when no valid quote messages are found in the input PCAP file. Ensure your PCAP file contains valid market data messages starting with "B6034".

## Output Flags

The program supports several flags to customize the output:

- No flags: Default output showing all quote messages in chronological order of packet time
- `-r`: Reorder messages by quote accept time at the exchange
- `-o <output-file>`: Write output to a specified file instead of stdout
- `-h` or `--help`: Display help information and available options

## Example Scenarios

1. Basic Usage - Processing a PCAP file in packet time order:
```bash
./parse-quote mdf-kospi200.20110216-0.pcap
```

2. Reordered by Accept Time:
```bash
./parse-quote -r mdf-kospi200.20110216-0.pcap
```

3. Using Detailed Output Format:
```bash
./parse-quote -o detailed.txt mdf-kospi200.20110216-0.pcap
```
This will generate output in a more detailed, readable format with timestamps and clear labeling:
```
Packet-Time: 1297814428.938676 | Accept-Time: 1297846828.900000 | Issue-Code: KR4301F62601
Bids: 0@765, 0@770, 0@775, 0@780, 15@785 | Asks: 15
```

You can combine flags as needed:
```bash
./parse-quote -r -o detailed.txt mdf-kospi200.20110216-0.pcap
```
This will reorder messages by accept time and output them in the detailed format.

Each quote message line contains:
- Packet capture timestamp
- Exchange accept timestamp
- ISIN code
- 5 levels of bid prices and quantities (from best to worst)
- 5 levels of ask prices and quantities (from best to worst)
