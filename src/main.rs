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
    use super::{ valid_mac, build_magic_packet };

    #[test]
    fn passes_valid_mac() {
        assert_eq!(valid_mac(&"ff:ff:ff:ff:ff:ff".to_string()), true);
        assert_eq!(valid_mac(&"FF:FF:FF:FF:FF:FF".to_string()), true);
    }  

    #[test]
    fn rejects_invalid_mac() {
        assert_eq!(valid_mac(&"".to_string()), false);
        assert_eq!(valid_mac(&":::::".to_string()), false);
        assert_eq!(valid_mac(&"ff:ff:ff:ff:ff".to_string()), false);
        assert_eq!(valid_mac(&"zz:zz:zz:zz:zz:zz".to_string()), false);
    }

    #[test]
    fn builds_magic_packet() {
        assert_eq!(build_magic_packet("ff:ff:ff:ff:ff:ff".to_string()).unwrap().is_empty(), false);
        assert_eq!(build_magic_packet("ff:ff:ff:ff:ff:ff".to_string()).unwrap().len(), 102);
    }  
}

fn valid_mac(mac: &String) -> bool {
    let valid_mac = match Regex::new("^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$") {
        Ok(r)  => r,
        Err(e) => panic!("could not build regular expression: {}", e),
    };

    match valid_mac.is_match(&mac) {
        true => return true,
        _    => return false,
    };
}

fn build_magic_packet(mac: String) -> Result<Vec<u8>, &'static str> {
    if valid_mac(&mac) == false { 
        return Err("invalid mac address") 
    };

    let mut packet  = vec![0xff; 6];
    let mut payload = Vec::new();
    
    let mac_as_bytes: Vec<&str> = mac.split(":").collect();

    for byte in mac_as_bytes {
        match u8::from_str_radix(byte, 16) {
	    Ok(b)  => payload.push(b),
	    Err(_) => return Err("could not fill buffer"),
        };
    }

    match payload.len() {
        6 => for _ in 0..16 {
                 for elem in &payload {
                     packet.push(*elem); 
                 };
             },
        _ => return Err("invalid buffer length"),
    };
    
    match packet.len() {
        102 => return Ok(packet),
        _   => return Err("invalid packet size"),
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
        Some(m) => m,
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

    let laddr = SocketAddrV4::new(Ipv4Addr::new(0u8, 0u8, 0u8, 0u8),9);
    let raddr = SocketAddrV4::new(bcast, 9);

    let magic_packet = match build_magic_packet(mac) {
        Ok(p)  => p,
        Err(e) => panic!("could not generate magic packet: {}", e),
    };
    
    match send_magic_packet(magic_packet,laddr,raddr) {
        Ok(_)  => println!("Packet sent Ok"),
        Err(e) => panic!("could not send WOL request: {}", e),
    };
}
