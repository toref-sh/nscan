extern crate ipnet;
extern crate pnet;
extern crate pnet_datalink;
extern crate rayon;
extern crate clap;

#[macro_use]
extern crate lazy_static;

use std::{env};
use std::sync::{Mutex};
use std::net::{IpAddr, Ipv4Addr};
use ipnet::{Ipv4Net};
use pnet_datalink::{NetworkInterface};
use local_ipaddress;
use clap::{App, Arg};

mod scan;

#[cfg(target_os = "windows")]
fn get_os_type() -> String{"windows".to_owned()}

#[cfg(target_os = "linux")]
fn get_os_type() -> String{"linux".to_owned()}

#[cfg(target_os = "macos")]
fn get_os_type() -> String{"macos".to_owned()}

lazy_static! {
    static ref WAIT_COUNTER: Mutex<u16> = Mutex::new(0);
    static ref HOST_LIST: Mutex<Vec<String>> = Mutex::new(vec![]);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        if args[1] == "about".to_string(){
            show_app_desc();
            std::process::exit(0);
        }
    }
    let app = get_app_settings();
    let matches = app.get_matches();
    // Get network interfaces
    let interfaces = pnet_datalink::interfaces();

    /*
    for iface in &interfaces {
        if get_os_type() == "windows".to_string() {
            let iface_ip = iface.ips.iter().next().map(|x| match x.ip() {
                IpAddr::V4(ipv4) => Some(ipv4),
                _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
            });
            println!("{}  {}  {}  {:?}", iface.index, iface.name, iface.mac.unwrap(), iface_ip.unwrap().unwrap());
        }else if get_os_type() == "macos".to_string() {
            println!("{}  {}  {}", iface.index, iface.name, iface.mac.unwrap());
        }else if get_os_type() == "linux".to_string() {
            println!("{}  {}  {}", iface.index, iface.name, iface.mac.unwrap());
        }else{
            println!("{}  {}  {}", iface.index, iface.name, iface.mac.unwrap());    
        }
    }
    */

    //eprint!("Select interface index:");

    let def_if_idx: u32 = get_default_if_index();

    let mut if_idx: u32 = def_if_idx;

    if let Some(opt_if_name) = matches.value_of("interface"){
        if_idx = get_if_index_by_name(opt_if_name.to_string());
        if if_idx == 0 {
            println!("Failed to get Interface by name (specified with -i option)");
            //if_idx = def_if_idx;
        }
    }

    // Get network interface by index
    let interface = interfaces.into_iter().filter(|interface: &NetworkInterface| interface.index == if_idx).next().expect("Failed get Inteface");
    //println!("Selected Inteface:{}",interface.name);
    //println!();

    let mut iface_ip: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

    for i in 0..interface.ips.len() {
        let iface_ip_tmp = interface.ips.iter().nth(i).expect(&format!("the interface {} does not have any IP addresses", interface)).ip();
        match iface_ip_tmp {
            IpAddr::V4(ipv4) => {
                iface_ip = ipv4;
                break;
            },
            _ => {
                continue;
            }
        }
    }

    if iface_ip == Ipv4Addr::new(127,0,0,1) {
        panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported");
    }

    //Get network address
    let net: Ipv4Net = Ipv4Net::new(iface_ip, 24).unwrap();
    assert_eq!(Ok(net.network()), "192.168.1.0".parse());
    let nw_addr = Ipv4Net::new(net.network(), 24).unwrap();
    
    //Get host list
    let hosts: Vec<Ipv4Addr> = nw_addr.hosts().collect();

    println!("Scan options");
    println!("==========================================");
    println!("Inteface: {}", interface.name);
    println!("Target: {} to {}", hosts[0], hosts[hosts.len() - 1]);
    println!("==========================================");
    println!();

    //execute scan
    scan::scan_hosts(&interface, hosts);

}

/*
fn read<T: std::str::FromStr>() -> T {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    s.trim().parse().ok().unwrap()
}
*/

fn get_default_if_index() -> u32{
    let mut if_idx: u32 = 0;
    let default_local_ip = local_ipaddress::get().unwrap();
    for iface in pnet::datalink::interfaces() {
        for ip in iface.ips{
            match ip.ip(){
                IpAddr::V4(ipv4) => {
                    if default_local_ip == ipv4.to_string(){
                        if_idx = iface.index;
                    }
                    //println!("V4 {}", ipv4)
                },
                IpAddr::V6(ipv6) => {
                    if default_local_ip == ipv6.to_string(){
                        if_idx = iface.index;
                    }
                },
            }
        }
    }
    return if_idx;
}

fn get_if_index_by_name(if_name: String) -> u32{
    let mut if_idx: u32 = 0;
    for iface in pnet::datalink::interfaces() {
        if iface.name == if_name{
            if_idx = iface.index;
        }
    }
    return if_idx;
}

fn get_app_settings<'a, 'b>() -> App<'a, 'b> {
    let app = App::new("nscan")
        .version("0.1.0")                       
        .author("toref <https://github.com/toref-sh>")     
        .about("Network scanner.")                     
        .arg(Arg::with_name("ip")               
        .help("IP address(one of the target network)")     
        .short("t")                         
        .long("target")
        .takes_value(true)                        
        )
        .arg(Arg::with_name("default")              
            .help("Use local default ip address")              
            .short("d")                         
            .long("default")                        
        )
        .arg(Arg::with_name("interface")              
            .help("Network interface name")              
            .short("i")                         
            .long("if")                        
            .takes_value(true)                  
        )
        .arg(Arg::with_name("start")              
            .help("Start host part number")              
            .short("s")                         
            .long("start")                        
            .takes_value(true)                  
        )
        .arg(Arg::with_name("end")              
            .help("End host part number")              
            .short("e")                         
            .long("end")                        
            .takes_value(true)                  
        )
        ;
        app
}

fn show_app_desc() {
    println!("pscan 0.1.0 (2020/09/27) {}", get_os_type());
    println!("Network scanner.");
    println!("toref <https://github.com/toref-sh>");
    println!();
    println!("'nscan --help' for more information.");
    println!();
}