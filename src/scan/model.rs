use std::net::IpAddr;
use std::path::PathBuf;

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
    pub ports: PortSpecification,

    // Service/Version detection
    pub service_detection: ServiceDetection,

    // Script scan
    pub script_scan: ScriptScan,

    // OS detection
    pub os_detection: OsDetection,

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
    pub random_targets: Option<u32>,
    pub exclude: Vec<String>,
    pub exclude_file: Option<PathBuf>,
}

/// Host discovery options
#[derive(Debug, Clone, Default)]
pub struct HostDiscovery {
    pub list_scan: bool,           // -sL
    pub ping_scan: bool,           // -sn
    pub skip_port_scan: bool,      // -Pn
    pub syn_discovery: Vec<u16>,   // -PS
    pub ack_discovery: Vec<u16>,   // -PA
    pub udp_discovery: Vec<u16>,   // -PU
    pub sctp_discovery: Vec<u16>,  // -PY
    pub icmp_echo: bool,           // -PE
    pub icmp_timestamp: bool,      // -PP
    pub icmp_netmask: bool,        // -PM
    pub ip_protocol_ping: Vec<u8>, // -PO
    pub dns_servers: Vec<String>,  // --dns-servers
    pub system_dns: bool,          // --system-dns
    pub traceroute: bool,          // --traceroute
}

/// Scan technique options
#[derive(Debug, Clone, Default)]
pub enum ScanTechnique {
    #[default]
    Syn, // -sS (default)
    Connect,            // -sT
    Ack,                // -sA
    Window,             // -sW
    Maimon,             // -sM
    Udp,                // -sU
    TcpNull,            // -sN
    Fin,                // -sF
    Xmas,               // -sX
    Scanflags(String),  // --scanflags
    Idle(String),       // -sI (zombie host)
    Sctp(SctpScanType), // -sY, -sZ
    IpProtocol,         // -sO
    Ftp(String),        // -b (FTP bounce)
    Multiple(Vec<ScanTechnique>),
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
    pub enabled: bool,         // -sV
    pub intensity: Option<u8>, // --version-intensity (0-9)
    pub light: bool,           // --version-light
    pub all: bool,             // --version-all
    pub trace: bool,           // --version-trace
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

/// OS detection options
#[derive(Debug, Clone, Default)]
pub struct OsDetection {
    pub enabled: bool,            // -O
    pub limit: bool,              // --osscan-limit
    pub guess: bool,              // --osscan-guess
    pub max_retries: Option<u32>, // --max-os-tries
}

/// Timing and performance options
#[derive(Debug, Clone, Default)]
pub struct TimingPerformance {
    pub template: Option<TimingTemplate>,    // -T<0-5>
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
    pub nsock_engine: Option<String>,        // --nsock-engine
}

#[derive(Debug, Clone, Copy)]
pub enum TimingTemplate {
    Paranoid = 0,   // T0
    Sneaky = 1,     // T1
    Polite = 2,     // T2
    Normal = 3,     // T3
    Aggressive = 4, // T4
    Insane = 5,     // T5
}

/// Firewall/IDS evasion and spoofing
#[derive(Debug, Clone, Default)]
pub struct EvasionSpoofing {
    pub fragment_packets: bool,      // -f
    pub mtu: Option<u32>,            // --mtu
    pub decoys: Vec<String>,         // -D
    pub spoof_ip: Option<IpAddr>,    // -S
    pub interface: Option<String>,   // -e
    pub source_port: Option<u16>,    // -g/--source-port
    pub data: Option<String>,        // --data
    pub data_string: Option<String>, // --data-string
    pub data_length: Option<u32>,    // --data-length
    pub ip_options: Option<String>,  // --ip-options
    pub ttl: Option<u8>,             // --ttl
    pub randomize_hosts: bool,       // --randomize-hosts
    pub spoof_mac: Option<String>,   // --spoof-mac
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
    pub verbose: u8,                    // -v, -vv, etc. (0-10+)
    pub debug: u8,                      // -d, -dd, etc. (0-10+)
    pub reason: bool,                   // --reason
    pub stats_every: Option<String>,    // --stats-every
    pub packet_trace: bool,             // --packet-trace
    pub open_only: bool,                // --open
    pub iflist: bool,                   // --iflist
    pub append_output: bool,            // --append-output
    pub resume: Option<PathBuf>,        // --resume
    pub stylesheet: Option<PathBuf>,    // --stylesheet
    pub webxml: bool,                   // --webxml
    pub no_stylesheet: bool,            // --no-stylesheet
}

/// Miscellaneous options
#[derive(Debug, Clone, Default)]
pub struct MiscOptions {
    pub ipv6: bool,               // -6
    pub aggressive: bool,         // -A (OS, version, script, traceroute)
    pub datadir: Option<PathBuf>, // --datadir
    pub send_eth: bool,           // --send-eth
    pub send_ip: bool,            // --send-ip
    pub privileged: bool,         // --privileged
    pub unprivileged: bool,       // --unprivileged
    pub release_memory: bool,     // --release-memory
    pub version: bool,            // -V
    pub help: bool,               // -h
    pub resolve_all: bool,        // -R
    pub no_resolve: bool,         // -n
    pub unique: bool,             // --unique
    pub log_errors: bool,         // --log-errors
}

impl NmapScan {
    /// Creates a new NmapScan with default values
    pub fn new() -> Self {
        Self::default()
    }
}
