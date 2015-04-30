#![cfg_attr(test, allow(dead_code))] 

extern crate getopts;
extern crate regex;

use std::net::{ UdpSocket, SocketAddrV4, Ipv4Addr };
use std::env;
use getopts::Options;
use regex::Regex;
use std::error::Error;

#[cfg(test)]
mod test {
    use super::{ build_magic_packet, send_magic_packet, Mac };
    use std::net::{ SocketAddrV4, Ipv4Addr };

    #[test]
    fn true_for_valid_mac() {
        assert_eq!(Mac::new("ff:ff:ff:ff:ff:ff".to_string()).is_valid().unwrap(), true);
        assert_eq!(Mac::new("FF:FF:FF:FF:FF:FF".to_string()).is_valid().unwrap(), true);
    }  

    #[test]
    fn false_for_invalid_mac() {
        assert_eq!(Mac::new("".to_string()).is_valid().unwrap(), false);
        assert_eq!(Mac::new(":::::".to_string()).is_valid().unwrap(), false);
        assert_eq!(Mac::new("ff:ff:ff:ff:ff".to_string()).is_valid().unwrap(), false);
        assert_eq!(Mac::new("zz:zz:zz:zz:zz:zz".to_string()).is_valid().unwrap(), false);
    }

    #[test]
    fn can_build_magic_packet() {
        assert_eq!(build_magic_packet(Mac::new("ff:ff:ff:ff:ff:ff".to_string())).unwrap().is_empty(), false);
        assert_eq!(build_magic_packet(Mac::new("ff:ff:ff:ff:ff:ff".to_string())).unwrap().len(), 102);
        assert_eq!(build_magic_packet(Mac::new("ff:ff:ff:ff:ff:ff".to_string())).unwrap(), vec![255; 102]);
    }

    #[test]
    fn can_send_packet_loopback() {
        let laddr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0);
        let raddr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9);
        assert_eq!(send_magic_packet(vec![0xff; 102], laddr, raddr).unwrap(), true);
    }
    #[test]
    fn struct_tests() {
        assert_eq!(Mac::new("ff:ff:ff:ff:ff:ff".to_string()).is_valid().unwrap(), true);
        assert_eq!(Mac::new("ff:ff:ff:ff:ff:ff".to_string()).as_bytes().unwrap(), vec![255; 6]);
    }
}

#[derive(Debug)]
enum WolError { InvalidMacAddress, InvalidBufferLength, InvalidPacketSize }

#[derive(Debug)]
enum MacError { ValidationFailed, BytesConversionFailed }
 
struct Mac {
    address: String
}

impl Mac {
    fn new(address: String) -> Mac {
        Mac { address: address }
    }
    fn is_valid(&self) -> Result<bool, MacError> {
        let valid_mac = match Regex::new("^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$") {
            Ok(r)  => r,
            Err(_) => return Err(MacError::ValidationFailed),
        };

        match valid_mac.is_match(&self.address) {
            true => return Ok(true),
            _    => return Ok(false),
        };
    }
    fn as_bytes(&self) -> Result<Vec<u8>, MacError> {
        let mac_as_bytes: Vec<&str> = self.address.split(":").collect();
        let mut result: Vec<u8> = Vec::new();
	
        for byte in mac_as_bytes {
              match u8::from_str_radix(byte, 16) {
                  Ok(b)  => result.push(b),
                  Err(_) => return Err(MacError::BytesConversionFailed)
              }
        }
        return Ok(result);
    }   
}

fn build_magic_packet(mac: Mac) -> Result<Vec<u8>, WolError> {
    match mac.is_valid() {
        Ok(true)  => true,
        Ok(false) => return Err(WolError::InvalidMacAddress),
        Err(e)    => panic!("{:?}", e) 
    };

    let mut packet  = vec![0xff; 6];
    
    let payload = match mac.as_bytes() {
        Ok(p)  => p,
        Err(e) => panic!("{:?}", e)
    };

    match payload.len() {
        6 => for _ in 0..16 {
                 for elem in payload.iter() {
                     packet.push(*elem); 
                 };
             },
        _ => return Err(WolError::InvalidBufferLength),
    };
    
    match packet.len() {
        102 => return Ok(packet),
        _   => return Err(WolError::InvalidPacketSize),
    };
}

fn send_magic_packet(packet: Vec<u8>, laddr: SocketAddrV4, raddr: SocketAddrV4) -> Result<bool, Box<Error>> {
    let socket = try!(UdpSocket::bind(laddr));

    try!(socket.send_to(&packet[0..102], raddr));

    Ok(true)
}

fn print_usage(opts: Options) {
    let summary = format!("Usage: [options]");
    print!("{}", opts.usage(&summary));
}

fn main() {
    let args  = env::args();

    let mut opts = Options::new();
        
    opts.optflag("h", "help", "display this help");
    opts.optopt("m", "mac", "MAC address in the form ff:ff:ff:ff:ff:ff", "");
    opts.optopt("b", "bcast", "broadcast address", "");

    if args.len() != 3 {
        print_usage(opts);
        return
    };
        
    let matches = match opts.parse(args) {
        Ok(m)  => m,
        Err(e) => {
            println!("{}", e);
            return
        }
    };

    if matches.opt_present("help") {
        print_usage(opts);
        return
    };

    let mac = match matches.opt_str("mac") {
        Some(m) => Mac::new(m),
        None    => panic!("no MAC address provided"),
    };

    let bcast_string = match matches.opt_str("bcast") {
        Some(b) => b,
        None    => panic!("no bcast address provided"),
    };

    let bcast: Ipv4Addr = match bcast_string.parse() {
        Ok(r)  => r,
        Err(e) => panic!("could not convert address to Ippv4Addr: {:?}", e),
    };

    let laddr = SocketAddrV4::new(Ipv4Addr::new(0u8, 0, 0, 0),0);
    let raddr = SocketAddrV4::new(bcast, 9);

    let magic_packet = match build_magic_packet(mac) {
        Ok(p)  => p,
        Err(e) => panic!("could not generate magic packet: {:?}", e),
    };
    
    match send_magic_packet(magic_packet,laddr,raddr) {
        Ok(_)  => println!("Packet sent Ok"),
        Err(e) => panic!("could not send WOL request: {}", e),
    };
}
