#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;

extern crate ipnet;
extern crate nerve_base;
extern crate nerve;

mod util;

use std::io::{stdout, Write};
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::fs::read_to_string;
use std::collections::HashMap;
use chrono::{Local, DateTime};
use tokio;
use ipnet::{Ipv4Net};
use clap::{App, AppSettings, Arg, ArgGroup, SubCommand};
use nerve_base::ScanStatus;
use nerve_base::{interface, arp};
use nerve::{PortScanner, HostScanner, UriScanner, DomainScanner};
use nerve::PortScanType;
use util::{option, validator};
use util::sys::{self, SPACE4};
use util::db;
use crossterm::style::Colorize;
use dns_lookup::lookup_host;

const CRATE_UPDATE_DATE: &str = "2021/3/8";
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
    if args.len() < 2 {
        show_app_desc();
        std::process::exit(0);
    }
    let app = get_app_settings();
    let matches = app.get_matches();
    //Update
    if let Some(sub_matches) = matches.subcommand_matches("update") {
        show_banner();
        print!("Updating... ");
        stdout().flush().unwrap();
        if sub_matches.is_present("database"){
            match db::update_db().await {
                Ok(_) =>{
                    println!("{}", "Done".green());
                    println!("nscan database has been updated.");
                },
                Err(_) => {
                    println!("{}", "Failed".red());
                },
            }
        }else if sub_matches.is_present("service"){
            if let Some(v) = sub_matches.value_of("service") {
                db::init_db();
                match db::update_service(&v.to_string()) {
                    Ok(_) =>{
                        println!("{}", "Done".green());
                        println!("Service data has been updated.");
                    },
                    Err(_) => {
                        println!("{}", "Failed".red());
                    },
                }
            }
        }else if sub_matches.is_present("oui"){
            if let Some(v) = sub_matches.value_of("oui") {
                db::init_db();
                match db::update_oui(&v.to_string()) {
                    Ok(_) =>{
                        println!("{}", "Done".green());
                        println!("OUI data has been updated.");
                    },
                    Err(_) => {
                        println!("{}", "Failed".red());
                    },
                }
            }
        }else{
            println!();
            println!("Error: Update mode not specified. 'nscan update --help' for available options");
        }
        std::process::exit(0);
    }

    //Scan
    show_banner_with_starttime();
    if matches.is_present("port"){
        if !sys::check_root() {
            println!("{} This feature requires administrator privileges. ","error:".red());
            std::process::exit(0);
        }
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
            if let Some(s) = matches.value_of("save") {
                opt.set_save_path(s.to_string());
            }
            handle_port_scan(opt);
        }
    }else if matches.is_present("host") {
        if !sys::check_root() {
            println!("{} This feature requires administrator privileges. ","error:".red());
            std::process::exit(0);
        }
        if let Some(v) = matches.value_of("host") {
            let mut opt = option::HostOption::new();
            opt.set_option(v.to_string());
            if let Some(w) = matches.value_of("word") {
                opt.set_file_path(w.to_string());
            }
            if let Some(t) = matches.value_of("timeout") {
                opt.set_timeout(t.to_string());
            }
            if let Some(s) = matches.value_of("save") {
                opt.set_save_path(s.to_string());
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
            if let Some(s) = matches.value_of("save") {
                opt.set_save_path(s.to_string());
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
            if let Some(s) = matches.value_of("save") {
                opt.set_save_path(s.to_string());
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
            .validator(validator::validate_filepath)
        )
        .arg(Arg::with_name("save")
            .help("Save scan result to file - Ex: -s result.txt")
            .short("s")
            .long("save")
            .takes_value(true)
            .value_name("file_path")
        )
        .subcommand(SubCommand::with_name("update")
            .about("Update nscan database")
            .arg(Arg::with_name("database")
                .help("Update entire database")
                .short("d")
                .long("database")
            )
            .arg(Arg::with_name("service")
                .help("Update service data")
                .short("s")
                .long("service")
                .takes_value(true)
                .value_name("file_path")
                .validator(validator::validate_filepath)
            )
            .arg(Arg::with_name("oui")
                .help("Update oui data")
                .short("o")
                .long("oui")
                .takes_value(true)
                .value_name("file_path")
                .validator(validator::validate_filepath)
            )
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
    println!();
}

fn show_banner_with_starttime() {
    println!("{} {} {}", crate_name!(), crate_version!(), get_os_type());
    println!();
    let local_datetime: DateTime<Local> = Local::now();
    println!("Scan started at {}", local_datetime);
    println!();
}

// handler 
fn handle_port_scan(opt: option::PortOption) {
    let conn = match db::get_db_connection() {
        Ok(conn) => conn,
        Err(e) => {
            println!("{}: {}", "Error".red(), e);
            return;
        },
    };
    opt.show_options();
    println!();
    print!("Scanning... ");
    stdout().flush().unwrap();
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
    match result.scan_status {
        ScanStatus::Done => {println!("{}", "Done".green())},
        ScanStatus::Timeout => {println!("{}", "Timed out".yellow())},
        _ => {println!("{}", "Error".red())},
    }
    println!();
    sys::print_fix32("Scan Reports", sys::FillStr::Hyphen);
    for port in result.open_ports {
        match db::get_service(&conn, &port, "tcp"){
            Ok(service) => {
                print_service(service);
            },
            Err(_) => {
                println!("{}{}{}Unknown service", SPACE4, port.cyan(), SPACE4);
            }, 
        };
    }
    sys::print_fix32("", sys::FillStr::Hyphen);
    println!("Scan Time: {:?}", result.scan_time);
    if !opt.save_path.is_empty() {
        let s_result = port_scanner.get_result();
        save_port_result(&conn, &opt, s_result);
    }
}

fn handle_host_scan(opt: option::HostOption) {
    let conn = match db::get_db_connection() {
        Ok(conn) => conn,
        Err(e) => {
            println!("{}: {}", "Error".red(), e);
            return;
        },
    };
    opt.show_options();
    println!();
    print!("Scanning...");
    stdout().flush().unwrap();
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
        let data = read_to_string(opt.wordlist_path.to_string());
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
    match result.scan_status {
        ScanStatus::Done => {println!("{}", "Done".green())},
        ScanStatus::Timeout => {println!("{}", "Timed out".yellow())},
        _ => {println!("{}", "Error".red())},
    }
    println!();
    let def_if_index = interface::get_default_interface_index();
    let if_index = match def_if_index {
        Some(if_index) => if_index,
        None => 0,
    };
    let interface_ip = match nerve_base::ip::get_local_ipaddr(){
        Some(ip) => ip,
        None => String::new(),
    };
    let mut result_map: HashMap<String, Option<db::Oui>> = HashMap::new();
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces.into_iter().filter(|interface: &pnet::datalink::NetworkInterface| interface.index == if_index).next().expect("Failed to get Interface");
    sys::print_fix32("Scan Reports", sys::FillStr::Hyphen);
    for host in result.up_hosts {
        match host.parse::<Ipv4Addr>(){
            Ok(ipaddr) => {
                let mac_addr: pnet::datalink::MacAddr = arp::get_mac_through_arp(&interface, ipaddr);
                match db::get_vendor_info(&conn, &mac_addr.to_string()){
                    Ok(oui) => {
                        print_host_info(ipaddr.to_string(), mac_addr.to_string(), oui.clone());
                        result_map.insert(ipaddr.to_string(), Some(oui));
                    },
                    Err(_) => {
                        print!("{}{}{}", SPACE4, ipaddr.to_string().cyan(), " ".repeat(16 - ipaddr.to_string().len()));
                        print!("{}{}", SPACE4, mac_addr);
                        if ipaddr.to_string() == interface_ip {
                            println!(" Own device");
                        }else{
                            println!(" Unknown");
                        }
                        result_map.insert(ipaddr.to_string(), None);
                    },
                }
            },
            Err(_) => {
                println!("{}{}", SPACE4, host.cyan());
            },
        }
    }
    sys::print_fix32("", sys::FillStr::Hyphen);
    println!("Scan Time: {:?}", result.scan_time);
    if !opt.save_path.is_empty() {
        save_host_result(&opt, result_map);
    }
}

async fn handle_uri_scan(opt: option::UriOption) {
    opt.show_options();
    println!();
    print!("Scanning...");
    stdout().flush().unwrap();
    let mut uri_scanner = match UriScanner::new(){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    uri_scanner.set_base_uri(opt.base_uri.to_string());
    if opt.use_wordlist {
        let data = read_to_string(opt.wordlist_path.to_string());
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
    match result.scan_status {
        ScanStatus::Done => {println!("{}", "Done".green())},
        ScanStatus::Timeout => {println!("{}", "Timed out".yellow())},
        _ => {println!("{}", "Error".red())},
    }
    println!();
    sys::print_fix32("Scan Reports", sys::FillStr::Hyphen);
    for (uri, status) in result.responses {
        if status.starts_with("2") {
            println!("{}{} {}", SPACE4, uri, status.green());
        }else if status.starts_with("4") {
            println!("{}{} {}", SPACE4, uri, status.red());
        }else if status.starts_with("5") {
            println!("{}{} {}", SPACE4, uri, status.red());
        }else{
            println!("{}{} {}", SPACE4, uri, status);
        }
    }
    sys::print_fix32("", sys::FillStr::Hyphen);
    println!("Scan Time: {:?}", result.scan_time);
    if !opt.save_path.is_empty() {
        let s_result = uri_scanner.get_result();
        save_uri_result(&opt, s_result);
    }
}

async fn handle_domain_scan(opt: option::DomainOption) {
    opt.show_options();
    println!();
    print!("Scanning...");
    stdout().flush().unwrap();
    let mut domain_scanner = match DomainScanner::new(){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    domain_scanner.set_base_domain(opt.base_domain.to_string());
    if opt.use_wordlist {
        let data = read_to_string(opt.wordlist_path.to_string());
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
    match result.scan_status {
        ScanStatus::Done => {println!("{}", "Done".green())},
        ScanStatus::Timeout => {println!("{}", "Timed out".yellow())},
        _ => {println!("{}", "Error".red())},
    }
    println!();
    sys::print_fix32("Scan Reports", sys::FillStr::Hyphen);
    println!("{}", opt.base_domain.to_string());
    match lookup_host(&opt.base_domain){
        Ok(ips) => {
            for ip in ips{
                println!("{}{}",SPACE4, ip);
            }
        },
        Err(e) => {println!("{} {}", e, opt.base_domain);},
    }
    println!();
    for (domain, ips) in result.domain_map {
        println!("{}{}", SPACE4.repeat(2), domain);
        for ip in ips{
            println!("{}{}", SPACE4.repeat(3), ip);
        }
    }
    sys::print_fix32("", sys::FillStr::Hyphen);
    println!("Scan Time: {:?}", result.scan_time);
    if !opt.save_path.is_empty() {
        let s_result = domain_scanner.get_result();
        save_domain_result(&opt, s_result);
    }
}

fn print_service(service: db::Service){
    print!("{}{}", " ".repeat(8 - service.port_number.len()),service.port_number.cyan());
    println!("{}{}", SPACE4, service.service_name);
}

fn print_host_info(ip_addr: String, mac_addr: String, oui: db::Oui){
    print!("{}{}{}", SPACE4, ip_addr.to_string().cyan(), " ".repeat(16 - ip_addr.len()));
    print!("{}{}", SPACE4, mac_addr);
    if oui.mac_prefix == "00:00:00".to_string() {
        println!(" Unknown");
    }else{
        println!("{}", oui.vendor_name_detail);
    }
}

fn save_port_result(conn: &rusqlite::Connection, opt: &option::PortOption, result: nerve::PortScanResult) {
    let mut data = "[OPTIONS]".to_string();
    data = format!("{}\nIP_ADDR:{}",data, opt.ip_addr.to_string());
    data = format!("{}\nSTART_PORT:{}",data, opt.start_port.to_string());
    data = format!("{}\nEND_PORT:{}",data, opt.end_port.to_string());
    data = format!("{}\n[RESULTS]",data);
    for port in result.open_ports {
        match db::get_service(&conn, &port, "tcp"){
            Ok(service) => {
                data = format!("{}\n{},{},{},{}", data, service.port_number,service.protocol,service.service_name,service.description);
            },
            Err(_) => {
                data = format!("{}\n{},Unknown service", data, port);
            }, 
        };
    }
    data = format!("{}\n",data);
    sys::save_file(opt.save_path.to_string(), data);
}

fn save_host_result(opt: &option::HostOption, result_map: HashMap<String, Option<db::Oui>>){
    let mut data = "[OPTIONS]".to_string();
    data = format!("{}\nNETWORK: {}",data, opt.ip_addr.to_string());
    data = format!("{}\n[RESULTS]",data);
    for (ip, oui) in result_map{
        match oui {
            Some(oui) => {
                data = format!("{}\n{},{},{}",data, ip, oui.mac_addr,oui.vendor_name_detail);
            },
            None => {
                data = format!("{}\n{},Unknown",data, ip);
            },
        }
    }
    data = format!("{}\n",data);
    sys::save_file(opt.save_path.to_string(), data);
}

fn save_uri_result(opt: &option::UriOption, result: nerve::UriScanResult){
    let mut data = "[OPTIONS]".to_string();
    data = format!("{}\nBASE_URI: {}",data, opt.base_uri.to_string());
    data = format!("{}\nWORD_LIST: {}",data, opt.wordlist_path.to_string());
    data = format!("{}\n[RESULTS]",data);
    for (uri, status) in result.responses {
        data = format!("{}\n{},{}",data,uri,status);
    }
    data = format!("{}\n",data);
    sys::save_file(opt.save_path.to_string(), data);
}

fn save_domain_result(opt: &option::DomainOption, result: nerve::DomainScanResult){
    let mut data = "[OPTIONS]".to_string();
    data = format!("{}\nBASE_DOMAIN: {}",data, opt.base_domain.to_string());
    data = format!("{}\nWORD_LIST: {}",data, opt.wordlist_path.to_string());
    data = format!("{}\n[RESULTS]",data);
    match lookup_host(&opt.base_domain){
        Ok(ips) => {
            data = format!("{}\n{}", data, opt.base_domain.to_string());
            for ip in ips{
                data = format!("{},{}", data, ip);
            }
        },
        Err(_) => {},
    }
    for (domain, ips) in result.domain_map {
        data = format!("{}\n{}",data,domain);
        for ip in ips{
            data = format!("{},{}",data,ip);
        }
    }
    data = format!("{}\n",data);
    sys::save_file(opt.save_path.to_string(), data);
}
