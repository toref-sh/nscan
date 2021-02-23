use regex::Regex;
use std::str::FromStr;
use std::net::IpAddr;
use std::path::Path;

pub fn validate_port_opt(v: String) -> Result<(), String> {
    let re = Regex::new(r"\S+:\d+-\d+$").unwrap();
    if !re.is_match(&v) {
        return Err(String::from("Please specify ip address and port number."));
    }
    let a_vec: Vec<&str> = v.split(":").collect();
    let addr = IpAddr::from_str(a_vec[0]);
    match addr {
        Ok(_) => {
            return Ok(())
        },
        Err(_) => {
            return Err(String::from("Please specify ip address"));
        }
    }
}

pub fn validate_host_opt(v: String) -> Result<(), String> {
    let addr = IpAddr::from_str(&v);
    match addr {
        Ok(_) => {
            return Ok(())
        },
        Err(_) => {
            return Err(String::from("Please specify ip address"));
        }
    }
}

pub fn validate_uri_opt(v: String) -> Result<(), String> {
    let re = Regex::new(r"https?://[\w!\?/\+\-_~=;\.,\*&@#\$%\(\)'\[\]]+").unwrap();
    if !re.is_match(&v) {
        return Err(String::from("Please specify uri"));
    }
    Ok(())
}

pub fn validate_domain_opt(v: String) -> Result<(), String> {
    let re = Regex::new(r"[\w\-._]+\.[A-Za-z]+").unwrap();
    if !re.is_match(&v) {
        return Err(String::from("Please specify domain name"));
    }
    Ok(())
}

pub fn validate_wordlist(v: String) -> Result<(), String> {
    if !Path::new(&v).exists() {
        return Err(format!("File {} does not exist", v));
    }
    Ok(())
}