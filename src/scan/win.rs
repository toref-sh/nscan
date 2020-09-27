extern crate pnet;
extern crate pnet_datalink;
extern crate rayon;

use std::sync::{Mutex};
use std::net::{IpAddr, Ipv4Addr};
use pnet_datalink::{Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations};
use pnet::packet::arp::{ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use winping::{Buffer, Pinger};
use indicatif::ProgressBar;
use oui::OuiDatabase;
use rayon::prelude::*;

fn ping(target_addr: IpAddr)-> bool{
    let mut pinger = Pinger::new().unwrap();
    let mut buffer = Buffer::new();
    let host_up: bool;
    
    pinger.set_timeout(1000);

    match pinger.send(target_addr, &mut buffer) {
        Ok(_rtt) => {
            host_up = true; 
            //println!("Response time {} ms.", rtt)
        },
        Err(_err) => {
            host_up = false; 
            //println!("{}.", err)
        },
    }
    return host_up;
}

fn get_mac_by_arp(interface: &NetworkInterface, target_ip: Ipv4Addr) -> MacAddr {
    let source_ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .unwrap();

    let (mut sender, mut receiver) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    sender
        .send_to(ethernet_packet.packet(), None)
        .unwrap()
        .unwrap();

    let mut target_mac_addr: MacAddr = MacAddr::zero();

    for _x in 0..2 {
        let buf = receiver.next().unwrap();
        let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();
        if arp.get_sender_hw_addr() != interface.mac.unwrap() {
            target_mac_addr = arp.get_sender_hw_addr();
        }
    }
    return target_mac_addr;
}

pub fn scan_hosts(interface: &NetworkInterface, hosts: Vec<Ipv4Addr>){
    let source_ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .unwrap();
    let db = OuiDatabase::new_from_file("data/manuf.txt").unwrap();
    let up_hosts: Mutex<Vec<Ipv4Addr>> = Mutex::new(vec![]);
    println!("Scannig...");
    let mut max_val: u64 = 0;
    for _ in 0..hosts.len(){
        max_val += 1;
    }
    let bar = ProgressBar::new(max_val);
    
    hosts.par_iter().for_each(|host|{
        let target_host = host.to_string().parse::<IpAddr>().expect("Could not parse IP Address");
        if ping(target_host){
            up_hosts.lock().unwrap().push(*host);
        };
        bar.inc(1);
    });

    bar.finish();

    println!();
    println!("Scan result (up hosts)");
    println!("==========================================");
    let mut up_hosts = up_hosts.lock().unwrap();
    up_hosts.sort();
    println!("{} host online", up_hosts.len());
    for host in up_hosts.iter(){
        let mut mac_addr = get_mac_by_arp(&interface, *host);
        if host == &source_ip{
            mac_addr = interface.mac.unwrap();
        }
        eprint!("{} {}", host, mac_addr);
        match db.query_by_str(&mac_addr.to_string()).unwrap() {
            Some(vendor_info) => {
                match vendor_info.name_long {
                    Some(vendor_name) => {
                        println!(" {:#?}", vendor_name);
                    }
                    None => {
                        println!(" unknown");
                    }
                }
            }
            None => {
                println!(" unknown");
            }
        }
    }
    println!("==========================================");
}
