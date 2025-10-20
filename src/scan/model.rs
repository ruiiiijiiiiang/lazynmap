use std::net::IpAddr;
use std::path::PathBuf;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumCount, EnumIter, EnumMessage, EnumString};

/// Represents a complete nmap scan configuration
#[derive(Debug, Clone, Default)]
pub struct NmapScan {
    // Target specification
    pub target_specification: TargetSpecification,

    // Host discovery
    pub host_discovery: HostDiscovery,

    // Scan techniques
    pub scan_technique: ScanTechnique,

    // Port specification
    pub port_specification: PortSpecification,

    // Service/Version detection
    pub service_detection: ServiceDetection,

    // OS detection
    pub os_detection: OsDetection,

    // Script scan
    pub script_scan: ScriptScan,

    // Timing and performance
    pub timing: TimingPerformance,

    // Firewall/IDS evasion and spoofing
    pub evasion: EvasionSpoofing,

    // Output
    pub output: OutputOptions,

    // Miscellaneous options
    pub misc: MiscOptions,
}

#[derive(Debug, Clone, Default)]
pub struct TargetSpecification {
    pub targets: Vec<String>,
    pub input_file: Option<PathBuf>,
    pub exclude: Vec<String>,
    pub exclude_file: Option<PathBuf>,
    pub random_targets: Option<u32>, // -iR
    pub no_resolve: bool,            // -n
    pub always_resolve: bool,        // -R
    pub resolve_all: bool,           // --resolve-all
    pub unique: bool,                // --unique
    pub system_dns: bool,            // --system-dns
    pub dns_servers: Vec<String>,    // --dns-servers
}

/// Host discovery options
#[derive(Debug, Clone, Default)]
pub struct HostDiscovery {
    pub list_scan: bool,            // -sL
    pub ping_scan: bool,            // -sn
    pub skip_port_scan: bool,       // -Pn
    pub syn_discovery: Vec<u32>,    // -PS
    pub ack_discovery: Vec<u32>,    // -PA
    pub udp_discovery: Vec<u32>,    // -PU
    pub sctp_discovery: Vec<u32>,   // -PY
    pub icmp_echo: bool,            // -PE
    pub icmp_timestamp: bool,       // -PP
    pub icmp_netmask: bool,         // -PM
    pub ip_protocol_ping: Vec<u32>, // -PO
    pub disable_arp_ping: bool,     // --disable-arp-ping
    pub discover_ignore_rst: bool,  // --discover-ignore-rst
    pub traceroute: bool,           // --traceroute
}

/// Scan technique options
#[derive(Debug, Clone)]
pub struct ScanTechnique {
    pub tcp: Option<TcpScanType>,
    pub udp: bool, // -sU
    pub sctp: Option<SctpScanType>,
}

#[derive(Debug, Clone, Eq, PartialEq, Display, EnumMessage, EnumCount, Default)]
pub enum TcpScanType {
    #[default]
    #[strum(to_string = "SYN (-sS)")]
    Syn, // -sS (default)
    #[strum(to_string = "Connect (-sT)")]
    Connect, // -sT
    #[strum(to_string = "ACK (-sA)")]
    Ack, // -sA
    #[strum(to_string = "Window (-sW)")]
    Window, // -sW
    #[strum(to_string = "Maimon (-sM)")]
    Maimon, // -sM
    #[strum(to_string = "Null (-sN)")]
    Null, // -sN
    #[strum(to_string = "FIN (-sF)")]
    Fin, // -sF
    #[strum(to_string = "Xmas (-sX)")]
    Xmas, // -sX
    #[strum(to_string = "IP protocol (-sO)")]
    IpProtocol, // -sO
    #[strum(to_string = "Idle (-sI)", message = "Zombie host")]
    Idle(String), // -sI (zombie host)
    #[strum(to_string = "FTP (-b)", message = "FTP relay host")]
    Ftp(String), // -b (FTP bounce)
    #[strum(to_string = "Flags (--scanflags)", message = "Custom TCP scan")]
    Scanflags(String), // --scanflags
}

impl TcpScanType {
    pub fn as_index(&self) -> usize {
        match self {
            TcpScanType::Syn => 0,
            TcpScanType::Connect => 1,
            TcpScanType::Ack => 2,
            TcpScanType::Window => 3,
            TcpScanType::Maimon => 4,
            TcpScanType::Null => 5,
            TcpScanType::Fin => 6,
            TcpScanType::Xmas => 7,
            TcpScanType::IpProtocol => 8,
            TcpScanType::Idle(_) => 9,
            TcpScanType::Ftp(_) => 10,
            TcpScanType::Scanflags(_) => 11,
        }
    }

    pub fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(TcpScanType::Syn),
            1 => Some(TcpScanType::Connect),
            2 => Some(TcpScanType::Ack),
            3 => Some(TcpScanType::Window),
            4 => Some(TcpScanType::Maimon),
            5 => Some(TcpScanType::Null),
            6 => Some(TcpScanType::Fin),
            7 => Some(TcpScanType::Xmas),
            8 => Some(TcpScanType::IpProtocol),
            _ => unreachable!(),
        }
    }

    pub fn with_value(self, value: String) -> Self {
        match self {
            TcpScanType::Idle(_) => TcpScanType::Idle(value),
            TcpScanType::Ftp(_) => TcpScanType::Ftp(value),
            TcpScanType::Scanflags(_) => TcpScanType::Scanflags(value),
            _ => unreachable!(),
        }
    }
}

impl Default for ScanTechnique {
    fn default() -> Self {
        ScanTechnique {
            tcp: Some(TcpScanType::Syn),
            udp: false,
            sctp: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SctpScanType {
    Init,   // -sY
    Cookie, // -sZ
}

/// Port specification
#[derive(Debug, Clone, Default)]
pub struct PortSpecification {
    pub ports: Option<String>,         // -p
    pub exclude_ports: Option<String>, // --exclude-ports
    pub fast_mode: bool,               // -F
    pub consecutive_ports: bool,       // -r
    pub top_ports: Option<u32>,        // --top-ports
    pub port_ratio: Option<f32>,       // --port-ratio
}

/// Service and version detection
#[derive(Debug, Clone, Default)]
pub struct ServiceDetection {
    pub enabled: bool,          // -sV
    pub allports: bool,         // --allports
    pub intensity: Option<u32>, // --version-intensity (0-9)
    pub light: bool,            // --version-light
    pub all: bool,              // --version-all
    pub trace: bool,            // --version-trace
}

/// OS detection options
#[derive(Debug, Clone, Default)]
pub struct OsDetection {
    pub enabled: bool,            // -O
    pub limit: bool,              // --osscan-limit
    pub guess: bool,              // --osscan-guess
    pub max_retries: Option<u32>, // --max-os-tries
}

/// Script scanning options
#[derive(Debug, Clone, Default)]
pub struct ScriptScan {
    pub default: bool,                     // -sC
    pub scripts: Vec<String>,              // --script
    pub script_args: Option<String>,       // --script-args
    pub script_args_file: Option<PathBuf>, // --script-args-file
    pub script_trace: bool,                // --script-trace
    pub script_updatedb: bool,             // --script-updatedb
    pub script_help: Option<String>,       // --script-help
}

/// Timing and performance options
#[derive(Debug, Clone)]
pub struct TimingPerformance {
    pub min_hostgroup: Option<u32>,          // --min-hostgroup
    pub max_hostgroup: Option<u32>,          // --max-hostgroup
    pub min_parallelism: Option<u32>,        // --min-parallelism
    pub max_parallelism: Option<u32>,        // --max-parallelism
    pub min_rtt_timeout: Option<String>,     // --min-rtt-timeout
    pub max_rtt_timeout: Option<String>,     // --max-rtt-timeout
    pub initial_rtt_timeout: Option<String>, // --initial-rtt-timeout
    pub max_retries: Option<u32>,            // --max-retries
    pub host_timeout: Option<String>,        // --host-timeout
    pub script_timeout: Option<String>,      // --script-timeout
    pub scan_delay: Option<String>,          // --scan-delay
    pub max_scan_delay: Option<String>,      // --max-scan-delay
    pub min_rate: Option<u32>,               // --min-rate
    pub max_rate: Option<u32>,               // --max-rate
    pub defeat_rst_ratelimit: bool,          // --defeat-rst-ratelimit
    pub defeat_icmp_ratelimit: bool,         // --defeat-icmp-ratelimit
    pub nsock_engine: Option<NsockEngine>,   // --nsock-engine
    pub template: Option<TimingTemplate>,    // -T<0-5>
}

impl Default for TimingPerformance {
    fn default() -> Self {
        TimingPerformance {
            min_hostgroup: None,
            max_hostgroup: None,
            min_parallelism: None,
            max_parallelism: None,
            min_rtt_timeout: None,
            max_rtt_timeout: None,
            initial_rtt_timeout: None,
            max_retries: None,
            host_timeout: None,
            script_timeout: None,
            scan_delay: None,
            max_scan_delay: None,
            min_rate: None,
            max_rate: None,
            defeat_rst_ratelimit: false,
            defeat_icmp_ratelimit: false,
            nsock_engine: None,
            template: Some(TimingTemplate::Normal),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Display, EnumIter, EnumCount, Default)]
pub enum TimingTemplate {
    #[strum(to_string = "Paranoid (-T0)")]
    Paranoid = 0,
    #[strum(to_string = "Sneaky (-T1)")]
    Sneaky = 1,
    #[strum(to_string = "Polite (-T2)")]
    Polite = 2,
    #[default]
    #[strum(to_string = "Normal (-T3)")]
    Normal = 3,
    #[strum(to_string = "Aggressive (-T4)")]
    Aggressive = 4,
    #[strum(to_string = "Insane (-T5)")]
    Insane = 5,
}

impl TimingTemplate {
    pub fn as_index(&self) -> usize {
        *self as usize
    }

    pub fn from_index(index: usize) -> Option<Self> {
        TimingTemplate::iter().nth(index)
    }

    pub fn all_labels() -> Vec<String> {
        Self::iter().map(|t| t.to_string()).collect()
    }
}

#[derive(Debug, Clone, Display, EnumString)]
pub enum NsockEngine {
    #[strum(to_string = "iocp")]
    Iocp,
    #[strum(to_string = "epoll")]
    Epoll,
    #[strum(to_string = "kqueue")]
    Kqueue,
    #[strum(to_string = "poll")]
    Poll,
    #[strum(to_string = "select")]
    Select,
}

/// Firewall/IDS evasion and spoofing
#[derive(Debug, Clone, Default)]
pub struct EvasionSpoofing {
    pub fragment_packets: bool,      // -f
    pub mtu: Option<u32>,            // --mtu
    pub decoys: Vec<String>,         // -D
    pub spoof_ip: Option<IpAddr>,    // -S
    pub interface: Option<String>,   // -e
    pub source_port: Option<u32>,    // -g/--source-port
    pub data: Option<String>,        // --data
    pub data_string: Option<String>, // --data-string
    pub data_length: Option<u32>,    // --data-length
    pub ip_options: Option<String>,  // --ip-options
    pub ttl: Option<u32>,            // --ttl
    pub randomize_hosts: bool,       // --randomize-hosts
    pub spoof_mac: Option<String>,   // --spoof-mac
    pub proxies: Vec<String>,        // --proxies
    pub badsum: bool,                // --badsum
    pub adler32: bool,               // --adler32
}

/// Output options
#[derive(Debug, Clone, Default)]
pub struct OutputOptions {
    pub normal: Option<PathBuf>,        // -oN
    pub xml: Option<PathBuf>,           // -oX
    pub script_kiddie: Option<PathBuf>, // -oS
    pub grepable: Option<PathBuf>,      // -oG
    pub all_formats: Option<String>,    // -oA (base filename)
    pub verbose: u32,                   // -v, -vv, etc. (0-10+)
    pub debug: u32,                     // -d, -dd, etc. (0-10+)
    pub reason: bool,                   // --reason
    pub stats_every: Option<String>,    // --stats-every
    pub packet_trace: bool,             // --packet-trace
    pub open_only: bool,                // --open
    pub iflist: bool,                   // --iflist
    pub append_output: bool,            // --append-output
    pub resume: Option<PathBuf>,        // --resume
    pub noninteractive: bool,           // --noninteractive
    pub stylesheet: Option<PathBuf>,    // --stylesheet
    pub webxml: bool,                   // --webxml
    pub no_stylesheet: bool,            // --no-stylesheet
}

/// Miscellaneous options
#[derive(Debug, Clone, Default)]
pub struct MiscOptions {
    pub ipv6: bool,                 // -6
    pub aggressive: bool,           // -A (OS, version, script, traceroute)
    pub datadir: Option<PathBuf>,   // --datadir
    pub servicedb: Option<PathBuf>, // --servicedb
    pub versiondb: Option<PathBuf>, // --versiondb
    pub send_eth: bool,             // --send-eth
    pub send_ip: bool,              // --send-ip
    pub privileged: bool,           // --privileged
    pub unprivileged: bool,         // --unprivileged
    pub release_memory: bool,       // --release-memory
    pub version: bool,              // -V
    pub help: bool,                 // -h
}

impl NmapScan {
    /// Creates a new NmapScan with default values
    pub fn new() -> Self {
        Self::default()
    }
}
