#![cfg_attr(test, allow(dead_code))]

extern crate getopts;

use std::{env, process};
use getopts::Options;
use std::net::{SocketAddrV4, Ipv4Addr};

mod wol {
    extern crate regex;

    use std;
    use std::net::{UdpSocket, SocketAddrV4, Ipv4Addr};
    use std::error::Error;

    #[cfg(test)]
    mod test {
        use super::{build_packet, send_packet, Mac};
        use std::net::{SocketAddrV4, Ipv4Addr};

        #[test]
        fn mac_struct_tests() {
            let mac = Mac::new("ff:ff:ff:ff:ff:ff");
            assert_eq!(Mac("ff:ff:ff:ff:ff:ff".into()).as_bytes().unwrap(),
                       Mac::new("ff:ff:ff:ff:ff:ff").as_bytes().unwrap());
            assert_eq!(mac.as_bytes().unwrap(), vec![255; 6]);
        }

        #[test]
        fn true_for_valid_mac() {
            assert_eq!(Mac::new("ff:ff:ff:ff:ff:ff").is_valid().unwrap(), true);
            assert_eq!(Mac::new("FF:FF:FF:FF:FF:FF").is_valid().unwrap(), true);
        }

        #[test]
        fn false_for_invalid_mac() {
            assert_eq!(Mac::new("").is_valid().unwrap(), false);
            assert_eq!(Mac::new(":::::").is_valid().unwrap(), false);
            assert_eq!(Mac::new("ff:ff:ff:ff:ff").is_valid().unwrap(), false);
            assert_eq!(Mac::new("zz:zz:zz:zz:zz:zz").is_valid().unwrap(), false);
        }

        #[test]
        fn can_build_magic_packet() {
            let mac = Mac::new("ff:ff:ff:ff:ff:ff");
            assert_eq!(build_packet(&mac).unwrap().is_empty(), false);
            assert_eq!(build_packet(&mac).unwrap().len(), 102);
            assert_eq!(build_packet(&mac).unwrap(), vec![255; 102]);
        }

        #[test]
        fn can_send_packet_loopback() {
            let raddr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9);
            assert_eq!(send_packet(&vec![0xff; 102], &raddr).unwrap(), true);
        }
    }

    #[derive(Debug)]
    pub enum WolError {
        InvalidMacAddress,
        InvalidBufferLength,
        InvalidPacketSize,
        MacValidationFailed,
        MacConversionFailed,
    }

    pub struct Mac(String);

    impl Mac {
        pub fn new(address: &str) -> Mac {
            Mac(address.to_owned())
        }

        fn is_valid(&self) -> Result<bool, regex::Error> {
            let valid_mac = {
                try!(regex::Regex::new("^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$"))
            };

            let &Mac(ref address) = self;

            match valid_mac.is_match(&address) {
                true => return Ok(true),
                _ => return Ok(false),
            }
        }

        fn as_bytes(&self) -> Result<Vec<u8>, std::num::ParseIntError> {
            let &Mac(ref address) = self;

            address.split(":")
                   .map(|e| u8::from_str_radix(e, 16))
                   .collect::<Result<Vec<_>, _>>()
        }
    }

    pub fn build_packet(mac: &Mac) -> Result<Vec<u8>, WolError> {
        match mac.is_valid() {
            Ok(true) => (),
            Ok(false) => return Err(WolError::InvalidMacAddress),
            Err(_) => return Err(WolError::MacValidationFailed),
        }

        let mut packet = vec![0xff; 6];

        let payload = match mac.as_bytes() {
            Ok(p) => p,
            Err(_) => return Err(WolError::MacConversionFailed),
        };

        match payload.len() {
            6 => for _ in 0..16 {
                packet.extend(payload.iter().map(|&e| e));
            },
            _ => return Err(WolError::InvalidBufferLength),
        }

        match packet.len() {
            102 => return Ok(packet),
            _ => return Err(WolError::InvalidPacketSize),
        }
    }

    pub fn send_packet(p: &[u8], r: &SocketAddrV4) -> Result<bool, Box<Error>> {
        let laddr = SocketAddrV4::new(Ipv4Addr::new(0u8, 0, 0, 0), 0);
        let socket = try!(UdpSocket::bind(laddr));

        try!(socket.send_to(&p[0..102], r));

        Ok(true)
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts: Options = Options::new();

    opts.optopt("m", "mac", "MAC address in the form FF:FF:FF:FF:FF:FF", "")
        .optopt("b", "bcast", "broadcast address", "")
        .optflag("h", "help", "display this help");

    let name = args[0].clone();

    let usage = format!("Usage: {}", opts.usage(&(name + " [options]")));

    let exit = |msg: &str, code: i32| -> ! {
        println!("{}", msg);
        process::exit(code);
    };

    let matches = opts.parse(&args[1..])
        .unwrap_or_else(|e| exit(&format!("could not parse arguments: {:?}", e), 1));
    
    if matches.opt_present("help") {
        exit(&usage, 0);
    }

    let mac = match matches.opt_str("mac") {
        Some(m) => wol::Mac::new(&m),
        None => exit(&usage, 1),
    };

    let bcast_s = match matches.opt_str("bcast") {
        Some(b) => b,
        None => exit(&usage, 1),
    };
    
    let bcast_ip: Ipv4Addr = bcast_s.parse()
        .unwrap_or_else(|e| exit(&format!("could not parse ip: {:?}", e), 1));

    let magic_packet = wol::build_packet(&mac)
        .unwrap_or_else(|e| exit(&format!("could not build packet: {:?}", e), 1));
    
    let raddr = SocketAddrV4::new(bcast_ip, 9);
    
    match wol::send_packet(&magic_packet, &raddr) {
        Ok(_) => println!("packet sent Ok"),
        Err(e) => exit(&format!("could not send request: {:?}", e), 1),
    };
}
