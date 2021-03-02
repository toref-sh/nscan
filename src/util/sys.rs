use std::net::{IpAddr};
use std::str::FromStr;
use ipnet::{Ipv4Net, Ipv6Net};

pub const SPACE4: &str = "    ";

#[allow(dead_code)]
pub enum FillStr{
    Hyphen,
    Equal,
}

pub fn get_network_address(ip_str: String) -> Result<String, String>{
    let addr = IpAddr::from_str(&ip_str);
    match addr {
        Ok(ip_addr) => {
            match ip_addr {
                IpAddr::V4(ipv4_addr) => {
                    let net: Ipv4Net = Ipv4Net::new(ipv4_addr, 24).unwrap();
                    Ok(net.network().to_string())
                },
                IpAddr::V6(ipv6_addr) => {
                    let net: Ipv6Net = Ipv6Net::new(ipv6_addr, 24).unwrap();
                    Ok(net.network().to_string())
                },
            }
        },
        Err(_) => {
            Err(String::from("Invalid IP Address"))
        }
    }
}

pub fn print_fix32(msg: &str, fill_str: FillStr){
    if msg.len() >= 32 {
        println!("{}", msg);
        return;
    }
    match fill_str {
        FillStr::Hyphen => {
            println!("-{}{}",msg,"-".repeat(31 - msg.len()));
        },
        FillStr::Equal => {
            println!("={}{}",msg,"=".repeat(31 - msg.len()));
        },
    }
}

/*
fn read<T: std::str::FromStr>() -> T {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    s.trim().parse().ok().unwrap()
}
*/
