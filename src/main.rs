#![cfg_attr(test, allow(dead_code))] 

extern crate getopts;

use std::env;
use getopts::Options;
use std::net::{ SocketAddrV4, Ipv4Addr };

mod wol {
    extern crate regex;

    use std;
    use std::net::{ UdpSocket, SocketAddrV4 };
    use std::error::Error;

    #[cfg(test)]
    mod test {
        use super::{ build_magic_packet, send_magic_packet, Mac };
        use std::net::{ SocketAddrV4, Ipv4Addr };

        #[test]
        fn mac_struct_tests() {
            assert_eq!(Mac::new("ff:ff:ff:ff:ff:ff").address, "ff:ff:ff:ff:ff:ff".to_string());
            assert_eq!(Mac::new("ff:ff:ff:ff:ff:ff").as_bytes().unwrap(), vec![255; 6]);
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
            assert_eq!(build_magic_packet(&Mac::new("ff:ff:ff:ff:ff:ff")).unwrap().is_empty(), false);
            assert_eq!(build_magic_packet(&Mac::new("ff:ff:ff:ff:ff:ff")).unwrap().len(), 102);
            assert_eq!(build_magic_packet(&Mac::new("ff:ff:ff:ff:ff:ff")).unwrap(), vec![255; 102]);
        }  

        #[test]
        fn can_send_packet_loopback() {
            let laddr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0);
            let raddr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9);
            assert_eq!(send_magic_packet(&vec![0xff; 102], &laddr, &raddr).unwrap(), true);
        }  
    }

    #[derive(Debug)]
    pub enum WolError { InvalidMacAddress, InvalidBufferLength, InvalidPacketSize, MacValidationFailed, MacConversionFailed }

    pub struct Mac {
        address: String
    }

    impl Mac {
        pub fn new(address: &str) -> Mac {
            Mac { address: address.to_string() }
        }

        fn is_valid(&self) -> Result<bool, regex::Error> {
            let valid_mac = try!(regex::Regex::new("^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$"));

            match valid_mac.is_match(&self.address) {
                true => return Ok(true),
                _    => return Ok(false),
            };
        }

        fn as_bytes(&self) -> Result<Vec<u8>, std::num::ParseIntError> {
            let mut result: Vec<u8> = Vec::new();
	
            for byte in self.address.split(":").collect::<Vec<&str>>() {
                result.push(try!(u8::from_str_radix(byte,16)))
            }  
        
            Ok(result)
        }   
    }

    pub fn build_magic_packet(mac: &Mac) -> Result<Vec<u8>, WolError> {
        match mac.is_valid() {
            Ok(true)  => true,
            Ok(false) => return Err(WolError::InvalidMacAddress),
            Err(_)    => return Err(WolError::MacValidationFailed) 
        };

        let mut packet  = vec![0xff; 6];
    
        let payload = match mac.as_bytes() {
            Ok(p)  => p,
            Err(_) => return Err(WolError::MacConversionFailed)
        };

        match payload.len() {
            6 => for _ in 0..16 {
	            packet.extend(payload.iter().map( |&e| e ));	
                },
            _ => return Err(WolError::InvalidBufferLength),
        };

        match packet.len() {
            102 => return Ok(packet),
            _   => return Err(WolError::InvalidPacketSize),
        };
    }

    pub fn send_magic_packet(packet: &[u8], laddr: &SocketAddrV4, raddr: &SocketAddrV4) -> Result<bool, Box<Error>> {
        let socket = try!(UdpSocket::bind(laddr));

        try!(socket.send_to(&packet[0..102], raddr));

        Ok(true)
    }
}

fn main() {
    let args     = env::args();
    let mut opts = Options::new();
 
    opts.optflag("h", "help", "display this help");
    opts.optopt("m", "mac", "MAC address in the form ff:ff:ff:ff:ff:ff", "");
    opts.optopt("b", "bcast", "broadcast address", "");

    let print_usage = || print!("{}", opts.usage("Usage: [options]"));
    
    if args.len() != 3 {
        print_usage();
 	return
    };
        
    let matches = match opts.parse(args) {
        Ok(m)  => m,
        Err(e) => panic!("could not parse arguments: {}", e),
    };

    if matches.opt_present("help") {
        print_usage();
        return
    };

    let mac = match matches.opt_str("mac") {
        Some(m) => wol::Mac::new(&m),
        None    => panic!("no MAC address provided"),
    };

    let bcast_string = match matches.opt_str("bcast") {
        Some(b)  => b,
        None     => panic!("no bcast address provided"),
    };

    let bcast: Ipv4Addr = match bcast_string.parse() {
        Ok(r)  => r,
        Err(e) => panic!("could not convert address to Ippv4Addr: {:?}", e),
    };

    let laddr = SocketAddrV4::new(Ipv4Addr::new(0u8, 0, 0, 0),0);
    let raddr = SocketAddrV4::new(bcast, 9);

    let magic_packet = match wol::build_magic_packet(&mac) {
        Ok(p)  => p,
        Err(e) => panic!("could not generate magic packet: {:?}", e),
    };
    
    match wol::send_magic_packet(&magic_packet,&laddr,&raddr) {
        Ok(_)  => println!("Packet sent Ok"),
        Err(e) => panic!("could not send WOL request: {}", e),
    };
}
