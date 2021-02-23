#[derive(Debug)]
pub struct PortOption{
    pub ip_addr: String,
    pub start_port: u16,
    pub end_port: u16,
    pub app_port: u16,
    pub scan_type: String,
    pub use_wordlist: bool,
    pub wordlist_path: String,
}

#[derive(Debug)]
pub struct HostOption{
    pub ip_addr: String,
    pub scan_host_addr: bool,
    pub use_wordlist: bool,
    pub wordlist_path: String,
}

#[derive(Debug)]
pub struct UriOption{
    pub base_uri: String,
    pub use_wordlist: bool,
    pub wordlist_path: String,
}

#[derive(Debug)]
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
            scan_type: String::new(),
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
        self.ip_addr = arg_value;
        if file_path.is_empty() {
            self.scan_host_addr = true;
        }else{
            self.use_wordlist = true;
            self.wordlist_path = file_path;
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
}