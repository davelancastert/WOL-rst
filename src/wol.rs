extern crate getopts;
extern crate regex;

use std::io::net::udp::UdpSocket;
use std::io::net::ip::{Ipv4Addr, SocketAddr};
use std::os;
use getopts::{usage, OptGroup};
use regex::Regex;


fn build_magic_packet(mac: String) -> Result<Vec<u8>, &'static str> {
    let mut packet  = Vec::from_elem(6, 0xff);
    let mut payload = Vec::new();
    
    let valid_mac = match Regex::new("^([0-9A-Za-z]{2}:){5}([0-9A-Za-z]{2})$") {
        Ok(exp) => exp,
        Err(e)  => panic!("{}", e),
    };

    match valid_mac.is_match(mac.as_slice()) {
        true => true,
        _    => return Err("invalid mac address"),
    };

    let mut mac_as_bytes = mac.as_slice().split_str(":");

    for byte in mac_as_bytes {
        match std::num::from_str_radix::<u8>(byte, 16) {
            Some(b) => payload.push(b),
            None    => return Err("could not fill buffer"),
        };
    }

    for _ in range(0u8, 16) {
        match payload.len() {
            6 => packet.push_all(payload.slice(0,6)),
            _ => return Err("invalid buffer length"),
        }; 
    }

    match packet.len() {
        102 => return Ok(packet),
        _   => return Err("invalid packet size"),
    };
}

fn send_magic_packet(packet: Vec<u8>, laddr: SocketAddr, raddr: String) -> Result<(), std::io::IoError> {
    let valid_bcast = match Regex::new("^([0-9]{1,3}.){3}(255)$") {
        Ok(exp) => exp,
        Err(e)  => panic!("{}", e),
    };

    match valid_bcast.is_match(raddr.as_slice()) {
        true => true,
        _    => panic!("invalid broadcast address"),
    };

    let mut socket = match UdpSocket::bind(laddr) {
        Ok(s)  => s,
        Err(e) => panic!("could not bind socket: {}", e),
    };

    let result = socket.send_to(packet.slice(0,102),(raddr.as_slice(), 9u16));
        
    return result
}

fn print_usage(args: &Vec<String>, opts: &[OptGroup]) {
      let summary = format!("Usage: {} [options]", args[0].as_slice());
      print!("{}", usage(summary.as_slice(),opts));
}

fn main() {
    let args  = os::args();
   
    let opts = &[
        getopts::optflag("h", "help", "display this help"),
        getopts::optopt("m", "mac", "MAC address in the form ff:ff:ff:ff:ff:ff", ""),
        getopts::optopt("b", "bcast", "broadcast address", ""),     
    ];
        
    let matches = match getopts::getopts(args.tail(), opts) {
        Ok(m)  => m,
        Err(e) => {
            println!("{}", e);
            os::set_exit_status(1);
            return
        }
    };

    if args.len() != 3 {
        print_usage(&args, opts);
        return
    };

    if matches.opt_present("help") {
        print_usage(&args, opts);
        return
    };

    let mac = match matches.opt_str("mac") {
        Some(m) => m,
        None    => panic!("no MAC address provided"),
    };

    let raddr = match matches.opt_str("bcast") {
        Some(b) => b,
        None    => panic!("no bcast address provided"),
    };

    let laddr = SocketAddr { ip: Ipv4Addr(0, 0, 0, 0), port: 9 };

    let magic_packet = match build_magic_packet(mac.to_string()) {
        Ok(p)  => p,
        Err(e) => panic!("could not generate magic packet: {}", e),
    };
    
    match send_magic_packet(magic_packet,laddr, raddr) {
        Ok(_)  => println!("Packet sent Ok"),
        Err(e) => panic!("could not send WOL request: {}", e),
    };
}