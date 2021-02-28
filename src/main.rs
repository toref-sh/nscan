#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;

extern crate ipnet;
extern crate nerve_base;
extern crate nerve;

mod util;

use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::fs::read_to_string;
use chrono::{Local, DateTime};
use tokio;
use ipnet::{Ipv4Net};
use clap::{App, AppSettings, Arg, ArgGroup};
use nerve_base::ScanStatus;
use nerve::{PortScanner, HostScanner, UriScanner, DomainScanner};
use nerve::PortScanType;
use util::{option, validator};

const CRATE_UPDATE_DATE: &str = "2021/2/28";
const CRATE_AUTHOR_GITHUB: &str = "toref <https://github.com/toref-sh>";

#[cfg(target_os = "windows")]
fn get_os_type() -> String{"windows".to_owned()}

#[cfg(target_os = "linux")]
fn get_os_type() -> String{"linux".to_owned()}

#[cfg(target_os = "macos")]
fn get_os_type() -> String{"macos".to_owned()}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2{
        show_app_desc();
        std::process::exit(0);
    }
    let app = get_app_settings();
    let matches = app.get_matches();
    show_banner();
    if matches.is_present("port"){
        if let Some(v) = matches.value_of("port") {
            let mut opt = option::PortOption::new();
            opt.set_option(v.to_string());
            if let Some(w) = matches.value_of("word") {
                opt.set_file_path(w.to_string());
            }
            if let Some(i) = matches.value_of("interface") {
                opt.set_if_name(i.to_string());
            }
            if let Some(t) = matches.value_of("timeout") {
                opt.set_timeout(t.to_string());
            }
            handle_port_scan(opt);
        }
    }else if matches.is_present("host") {
        if let Some(v) = matches.value_of("host") {
            let mut opt = option::HostOption::new();
            opt.set_option(v.to_string());
            if let Some(w) = matches.value_of("word") {
                opt.set_file_path(w.to_string());
            }
            if let Some(t) = matches.value_of("timeout") {
                opt.set_timeout(t.to_string());
            }
            handle_host_scan(opt);
        }
    }else if matches.is_present("uri"){
        if let Some(v) = matches.value_of("uri") {
            let mut opt = option::UriOption::new();
            opt.set_option(v.to_string());
            if let Some(w) = matches.value_of("word") {
                opt.set_file_path(w.to_string());
            }
            if let Some(t) = matches.value_of("timeout") {
                opt.set_timeout(t.to_string());
            }
            handle_uri_scan(opt).await;
        }
    }else if matches.is_present("domain"){
        if let Some(v) = matches.value_of("domain") {
            let mut opt = option::DomainOption::new();
            opt.set_option(v.to_string());
            if let Some(w) = matches.value_of("word") {
                opt.set_file_path(w.to_string());
            }
            if let Some(t) = matches.value_of("timeout") {
                opt.set_timeout(t.to_string());
            }
            handle_domain_scan(opt).await;
        }
    }else{
        println!();
        println!("Error: Scan mode not specified.");
        std::process::exit(0);
    }
}

fn get_app_settings<'a, 'b>() -> App<'a, 'b> {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .author(CRATE_AUTHOR_GITHUB)
        .about(crate_description!())
        .arg(Arg::with_name("port")
            .help("Port Scan - Ex: -p 192.168.1.8:1-1000")
            .short("p")
            .long("port")
            .takes_value(true)
            .value_name("ip_addr:port_range")
            .validator(validator::validate_port_opt)
        )
        .arg(Arg::with_name("host")
            .help("Scan hosts in specified network - Ex: -n 192.168.1.0")
            .short("n")
            .long("host")
            .takes_value(true)
            .value_name("ip_addr")
            .validator(validator::validate_host_opt)
        )
        .arg(Arg::with_name("uri")
            .help("URI Scan - Ex: -u http://192.168.1.8/xvwa/ -w common.txt")
            .short("u")
            .long("uri")
            .takes_value(true)
            .validator(validator::validate_uri_opt)
        )
        .arg(Arg::with_name("domain")
            .help("Domain Scan - Ex: -d example.com -w subdomain.txt")
            .short("d")
            .long("domain")
            .takes_value(true)
            .value_name("domain_name")
            .validator(validator::validate_domain_opt)
        )
        .arg(Arg::with_name("timeout")
            .help("Set timeout in ms - Ex: -t 10000")
            .short("t")
            .long("timeout")
            .takes_value(true)
            .value_name("duration")
            .validator(validator::validate_timeout)
        )
        .arg(Arg::with_name("interface")
            .help("Specify network interface by name - Ex: -i en0")
            .short("i")
            .long("interface")
            .takes_value(true)
            .value_name("name")
            .validator(validator::validate_interface)
        )
        .arg(Arg::with_name("word")
            .help("Use word list - Ex: -w common.txt")
            .short("w")
            .long("word")
            .takes_value(true)
            .value_name("file_path")
            .validator(validator::validate_wordlist)
        )
        .arg(Arg::with_name("save")
            .help("Save scan result to file - Ex: -s result.txt")
            .short("s")
            .long("save")
            .takes_value(true)
            .value_name("file_path")
        )
        .group(ArgGroup::with_name("mode")
            .args(&["port", "host", "uri", "domain"])
        )
        .setting(AppSettings::DeriveDisplayOrder)
        ;
        app
}

fn show_app_desc() {
    println!("{} {} ({}) {}", crate_name!(), crate_version!(), CRATE_UPDATE_DATE, get_os_type());
    println!("{}", crate_description!());
    println!("{}", CRATE_AUTHOR_GITHUB);
    println!();
    println!("'{} --help' for more information.", crate_name!());
    println!();
}

fn show_banner() {
    println!("{} {} {}", crate_name!(), crate_version!(), get_os_type());
    let local_datetime: DateTime<Local> = Local::now();
    println!("Scan started at {}", local_datetime);
    println!();
}

// handler 
fn handle_port_scan(opt: option::PortOption) {
    opt.show_options();
    println!();
    println!("Scanning...");
    println!();
    let mut if_name: Option<&str> = None;
    if !opt.if_name.is_empty(){
        if_name = Some(&opt.if_name);
    }
    let mut port_scanner = match PortScanner::new(None, if_name){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    port_scanner.set_target_ipaddr(&opt.ip_addr);
    port_scanner.set_range(opt.start_port, opt.end_port);
    port_scanner.set_scan_type(PortScanType::SynScan);
    port_scanner.set_timeout(opt.timeout);
    port_scanner.run_scan();
    let result = port_scanner.get_result();
    print!("Scan Status: ");
    match result.scan_status {
        ScanStatus::Done => {println!("Normal end")},
        ScanStatus::Timeout => {println!("Timed out")},
        _ => {println!("Error")},
    }
    println!();
    println!("Open Ports:");
    for port in result.open_ports {
        println!("    {}", port);
    }
    println!("Scan Time: {:?}", result.scan_time);
}

fn handle_host_scan(opt: option::HostOption) {
    opt.show_options();
    println!();
    println!("Scanning...");
    println!();
    let mut host_scanner = match HostScanner::new(){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    if opt.scan_host_addr {
        let addr = IpAddr::from_str(&opt.ip_addr);
        match addr {
            Ok(ip_addr) => {
                match ip_addr {
                    IpAddr::V4(ipv4_addr) => {
                        let net: Ipv4Net = Ipv4Net::new(ipv4_addr, 24).unwrap();
                        let nw_addr = Ipv4Net::new(net.network(), 24).unwrap();
                        let hosts: Vec<Ipv4Addr> = nw_addr.hosts().collect();
                        for host in hosts{
                            host_scanner.add_ipaddr(&host.to_string());
                        }
                    },
                    IpAddr::V6(_ipv6_addr) => {
                        error!("Currently not supported.");
                        std::process::exit(0);
                        /*
                        let net: Ipv6Net = Ipv6Net::new(ipv6_addr, 24).unwrap();
                        let nw_addr = Ipv6Net::new(net.network(), 24).unwrap();
                        let hosts: Vec<Ipv6Addr> = nw_addr.hosts().collect();
                        */
                    },
                }
            },
            Err(_) => {
                error!("Invalid IP address");
                std::process::exit(0);
            }
        }
    }else if opt.use_wordlist {
        let data = read_to_string(opt.wordlist_path);
        let text = match data {
            Ok(content) => content,
            Err(e) => {panic!("Could not open or find file: {}", e);}
        };
        let word_list: Vec<&str> = text.trim().split("\n").collect();
        for host in word_list {
            let addr = IpAddr::from_str(&host);
            match addr {
                Ok(_) => {
                    host_scanner.add_ipaddr(&host.to_string());        
                },
                Err(_) => {
                    
                }
            }
        }
    }
    host_scanner.set_timeout(opt.timeout);
    host_scanner.run_scan();
    let result = host_scanner.get_result();
    print!("Scan Status: ");
    match result.scan_status {
        ScanStatus::Done => {println!("Normal end")},
        ScanStatus::Timeout => {println!("Timed out")},
        _ => {println!("Error")},
    }
    println!();
    println!("Up Hosts:");
    for host in result.up_hosts {
        println!("    {}", host);
    }
    println!("Scan Time: {:?}", result.scan_time);
}

async fn handle_uri_scan(opt: option::UriOption) {
    opt.show_options();
    println!();
    println!("Scanning...");
    println!();
    let mut uri_scanner = match UriScanner::new(){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    uri_scanner.set_base_uri(opt.base_uri);
    if opt.use_wordlist {
        let data = read_to_string(opt.wordlist_path);
        let text = match data {
            Ok(content) => content,
            Err(e) => {panic!("Could not open or find file: {}", e);}
        };
        let word_list: Vec<&str> = text.trim().split("\n").collect();
        for word in word_list {
            uri_scanner.add_word(word.to_string());
        }
    }
    uri_scanner.set_timeout(opt.timeout);
    uri_scanner.run_scan().await;
    let result = uri_scanner.get_result();
    print!("Scan Status: ");
    match result.scan_status {
        ScanStatus::Done => {println!("Normal end")},
        ScanStatus::Timeout => {println!("Timed out")},
        _ => {println!("Error")},
    }
    println!();
    println!("URI Scan Result:");
    for (uri, status) in result.responses {
        println!("    {} {}", uri, status);
    }
    println!("Scan Time: {:?}", result.scan_time);
}

async fn handle_domain_scan(opt: option::DomainOption) {
    opt.show_options();
    println!();
    println!("Scanning...");
    println!();
    let mut domain_scanner = match DomainScanner::new(){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    domain_scanner.set_base_domain(opt.base_domain);
    if opt.use_wordlist {
        let data = read_to_string(opt.wordlist_path);
        let text = match data {
            Ok(content) => content,
            Err(e) => {panic!("Could not open or find file: {}", e);}
        };
        let word_list: Vec<&str> = text.trim().split("\n").collect();
        for d in word_list{
            domain_scanner.add_word(d.to_string());
        }
    }
    domain_scanner.set_timeout(opt.timeout);
    domain_scanner.run_scan().await;
    let result = domain_scanner.get_result();
    print!("Scan Status: ");
    match result.scan_status {
        ScanStatus::Done => {println!("Normal end")},
        ScanStatus::Timeout => {println!("Timed out")},
        _ => {println!("Error")},
    }
    println!();
    println!("Domain Scan Result:");
    for (domain, ips) in result.domain_map {
        println!("    {}", domain);
        for ip in ips{
            println!("        {}", ip);
        }
    }
    println!("Scan Time: {:?}", result.scan_time);
}
