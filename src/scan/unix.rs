extern crate pnet;
extern crate pnet_datalink;

use std::net::{IpAddr, Ipv4Addr};
use pnet_datalink::{Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations};
use pnet::packet::arp::{ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use fastping_rs::Pinger;
use fastping_rs::PingResult::{Idle, Receive};
use indicatif::ProgressBar;
use oui::OuiDatabase;

fn fast_ping(host_list: Vec<Ipv4Addr>)-> Vec<IpAddr>{
    let mut up_hosts: Vec<IpAddr> = vec![];
    let mut max_val: u64 = 0;
    let (pinger, results) = match Pinger::new(None, None) {
        Ok((pinger, results)) => (pinger, results),
        Err(e) => panic!("Error creating pinger: {}", e)
    };
    for host in host_list{
        let host_str = host.to_string();
        pinger.add_ipaddr(&host_str);
        max_val += 1;
    }
    let bar = ProgressBar::new(max_val);
    pinger.run_pinger();

    for _ in 0..max_val{
        match results.recv() {
            Ok(result) => {
                match result {
                    Idle{addr: _} => {
                        //println!("Idle Address {}.", addr);
                    },
                    Receive{addr, rtt: _} => {
                        //println!("Receive from Address {} in {:?}.", addr, rtt);
                        up_hosts.push(addr);
                    }
                }
            },
            Err(_) => panic!("Worker threads disconnected before the solution was found!"),
        }
        bar.inc(1);
    }
    bar.finish();
    return up_hosts
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
    let mut up_hosts: Vec<IpAddr>;
    println!("Scannig...");
    up_hosts = fast_ping(hosts);
    up_hosts.sort();

    println!();
    println!("Scan result (up hosts)");
    println!("==========================================");
    println!("{} host online", up_hosts.len());
    for host in up_hosts{
        let target_host = host.to_string().parse::<Ipv4Addr>().expect("Could not parse IP Address");
        let mut mac_addr = get_mac_by_arp(&interface, target_host);
        if target_host == source_ip{
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