use nerve::PortScanType;
use super::sys;

pub struct PortOption{
    pub ip_addr: String,
    pub start_port: u16,
    pub end_port: u16,
    pub app_port: u16,
    pub scan_type: PortScanType,
    pub use_wordlist: bool,
    pub wordlist_path: String,
}

pub struct HostOption{
    pub ip_addr: String,
    pub scan_host_addr: bool,
    pub use_wordlist: bool,
    pub wordlist_path: String,
}

pub struct UriOption{
    pub base_uri: String,
    pub use_wordlist: bool,
    pub wordlist_path: String,
}

pub struct DomainOption{
    pub base_domain: String,
    pub use_wordlist: bool,
    pub wordlist_path: String,
}

impl PortOption {
    pub fn new() -> PortOption {
        let port_option = PortOption {
            ip_addr: String::new(),
            start_port: 0,
            end_port: 0,
            app_port: 65432,
            scan_type: PortScanType::SynScan,
            use_wordlist: false,
            wordlist_path: String::new(),
        };
        return port_option;
    }
    pub fn set_option(&mut self, arg_value: String, file_path: String){
        let a_vec: Vec<&str> = arg_value.split(":").collect();
        let addr = a_vec[0].to_string();
        let port_range = a_vec[1].to_string();
        let range: Vec<&str> = port_range.split("-").collect();
        let s_port: u16 = range[0].parse().unwrap();
        let e_port: u16 = range[1].parse().unwrap();
        self.ip_addr = addr;
        self.start_port = s_port;
        self.end_port = e_port;
        if !file_path.is_empty() {
            self.use_wordlist = true;
            self.wordlist_path = file_path;   
        }
    }
    pub fn show_options(&self){
        println!("Port Scan Options:");
        println!("    IP Address: {}", self.ip_addr);
        println!("    Port Range: {}-{}", self.start_port, self.end_port);
        match self.scan_type {
            PortScanType::SynScan => {println!("    Scan Type: Syn Scan");},
            PortScanType::FinScan => {println!("    Scan Type: Fin Scan");},
            PortScanType::XmasScan => {println!("    Scan Type: Xmas Scan");},
            PortScanType::NullScan => {println!("    Scan Type: Null Scan");},
        }
    }
}

impl HostOption {
    pub fn new() -> HostOption {
        let host_option = HostOption {
            ip_addr: String::new(),
            scan_host_addr: false,
            use_wordlist: false,
            wordlist_path: String::new(),
        };
        return host_option;
    }
    pub fn set_option(&mut self, arg_value: String, file_path: String){
        match sys::get_network_address(arg_value){
            Ok(ip_str) =>{
                self.ip_addr = ip_str;
            },
            Err(e) => {
                error!("{}", e.to_string());
                std::process::exit(0);
            },
        }
        if file_path.is_empty() {
            self.scan_host_addr = true;
        }else{
            self.use_wordlist = true;
            self.wordlist_path = file_path;
        }
    }
    pub fn show_options(&self){
        println!("Host Scan Options:");
        if self.scan_host_addr {
            println!("    Target Network: {}", self.ip_addr);
        }else{
            println!("    Target: Specified in word list {}", self.wordlist_path);
        }
    }
}

impl UriOption {
    pub fn new() -> UriOption {
        let uri_option = UriOption {
            base_uri: String::new(),
            use_wordlist: false,
            wordlist_path: String::new(),
        };
        return uri_option;
    }
    pub fn set_option(&mut self, arg_value: String, file_path: String){
        if arg_value.ends_with("/") {
            self.base_uri = arg_value;
        }else{
            self.base_uri = format!("{}/", arg_value);
        }
        if !file_path.is_empty() {
            self.use_wordlist = true;
            self.wordlist_path = file_path;   
        }
    }
    pub fn show_options(&self){
        println!("URI Scan Options:");
        println!("    Base URI: {}", self.base_uri);
        if self.use_wordlist {
            println!("    Word list: {}", self.wordlist_path);
        }
    }
}

impl DomainOption {
    pub fn new() -> DomainOption {
        let domain_option = DomainOption {
            base_domain: String::new(),
            use_wordlist: false,
            wordlist_path: String::new(),
        };
        return domain_option;
    }
    pub fn set_option(&mut self, arg_value: String, file_path: String){
        self.base_domain = arg_value;
        if !file_path.is_empty() {
            self.use_wordlist = true;
            self.wordlist_path = file_path;   
        }
    }
    pub fn show_options(&self){
        println!("Domain Scan Options:");
        println!("    Base Domain Name: {}", self.base_domain);
        if self.use_wordlist {
            println!("    Word list: {}", self.wordlist_path);
        }
    }
}