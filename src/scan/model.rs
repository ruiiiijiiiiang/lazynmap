use std::path::PathBuf;
use strum_macros::{Display, EnumCount, EnumIter, EnumMessage, EnumString};

/// Represents a complete nmap scan configuration
#[derive(Clone, Debug, Default)]
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

    // NSE script
    pub nse_script: NseScript,

    // Timing and performance
    pub timing: TimingPerformance,

    // Firewall/IDS evasion and spoofing
    pub evasion: EvasionSpoofing,

    // Output
    pub output: OutputOptions,

    // Miscellaneous options
    pub misc: MiscOptions,
}

#[derive(Clone, Debug, Default)]
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
#[derive(Clone, Debug, Default)]
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
#[derive(Clone, Debug)]
pub struct ScanTechnique {
    pub tcp: Option<TcpScanType>,
    pub udp: bool, // -sU
    pub sctp: Option<SctpScanType>,
}

#[derive(Clone, Debug, Default, Display, EnumCount, EnumIter, EnumMessage, Eq, PartialEq)]
pub enum TcpScanType {
    #[default]
    #[strum(
        to_string = "SYN",
        detailed_message = "-sS: Stealthy half-open scan that doesn't complete handshake. Default scan requiring root. Fast and relatively undetectable."
    )]
    Syn, // -sS
    #[strum(
        to_string = "Connect",
        detailed_message = "-sT: Completes full TCP connection. Used when no root privileges available. More detectable but works without special access."
    )]
    Connect, // -sT (default)
    #[strum(
        to_string = "ACK",
        detailed_message = "-sA: Maps firewall rules by sending ACK packets. Determines filtering but doesn't identify open ports. Useful for firewall analysis."
    )]
    Ack, // -sA
    #[strum(
        to_string = "Window",
        detailed_message = "-sW: Examines TCP window field in responses. Can distinguish open from closed ports on certain systems. More informative than ACK scan."
    )]
    Window, // -sW
    #[strum(
        to_string = "Maimon",
        detailed_message = "-sM: Sends FIN/ACK packets to exploit BSD TCP stacks. Named after discoverer Uriel Maimon. Rarely effective on modern systems."
    )]
    Maimon, // -sM
    #[strum(
        to_string = "Null",
        detailed_message = "-sN: Sends packets with no flags set. Stealthy technique bypassing non-stateful firewalls. Works on RFC-compliant Unix/Linux systems."
    )]
    Null, // -sN
    #[strum(
        to_string = "FIN",
        detailed_message = "-sF: Sends only FIN flag. Stealthy method to evade basic firewalls and detection systems. Effective against older security devices."
    )]
    Fin, // -sF
    #[strum(
        to_string = "Xmas",
        detailed_message = "-sX: Sets FIN, PSH, URG flags (lit like Christmas tree). Bypasses simple packet filters. Works on Unix but not Windows systems."
    )]
    Xmas, // -sX
    #[strum(
        to_string = "IP protocol",
        detailed_message = "-sO: Determines which IP protocols host supports (TCP, UDP, ICMP, etc). Sends raw packets to identify protocol implementations."
    )]
    IpProtocol, // -sO
    #[strum(
        to_string = "Idle",
        message = "string",
        detailed_message = "-sI: Ultra-stealthy technique using zombie host as proxy. Completely masks your IP address. Complex setup but maximum anonymity."
    )]
    Idle(String), // -sI (zombie host)
    #[strum(
        to_string = "FTP",
        message = "string",
        detailed_message = "-b: Relays scan through FTP server. Exploits legacy FTP proxy feature. Rarely works on modern servers but masks source IP."
    )]
    Ftp(String), // -b (FTP bounce)
    #[strum(
        to_string = "Scanflags",
        message = "string",
        detailed_message = "--scanflags: Sets custom TCP flags for scan packets. Accepts numeric value or symbolic names (URG, ACK, PSH, RST, SYN, FIN). Advanced technique for custom probes and evasion."
    )]
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
            9 => Some(TcpScanType::Idle(String::new())),
            10 => Some(TcpScanType::Ftp(String::new())),
            11 => Some(TcpScanType::Scanflags(String::new())),
            _ => unreachable!(),
        }
    }

    pub fn with_value(&self, value: String) -> Self {
        match self {
            TcpScanType::Idle(_) => TcpScanType::Idle(value),
            TcpScanType::Ftp(_) => TcpScanType::Ftp(value),
            TcpScanType::Scanflags(_) => TcpScanType::Scanflags(value),
            _ => unreachable!(),
        }
    }

    pub fn requires_admin(&self) -> bool {
        !matches!(self, TcpScanType::Connect)
    }
}

impl Default for ScanTechnique {
    fn default() -> Self {
        ScanTechnique {
            tcp: Some(TcpScanType::Connect),
            udp: false,
            sctp: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Display, EnumCount, EnumIter, EnumMessage, Eq, PartialEq)]
pub enum SctpScanType {
    #[strum(
        to_string = "SCTP init",
        detailed_message = "-sY: Checks SCTP associations. Similar speed and stealth to TCP SYN. Useful for telecommunications and signaling protocols."
    )]
    Init, // -sY
    #[strum(
        to_string = "SCTP cookie",
        detailed_message = "-sZ: Stealthier SCTP technique. Can bypass firewalls blocking INIT. Less reliable but harder to detect than INIT scan."
    )]
    Cookie, // -sZ
}

/// Port specification
#[derive(Clone, Debug, Default)]
pub struct PortSpecification {
    pub ports: Option<String>,         // -p
    pub exclude_ports: Option<String>, // --exclude-ports
    pub fast_mode: bool,               // -F
    pub consecutive_ports: bool,       // -r
    pub top_ports: Option<u32>,        // --top-ports
    pub port_ratio: Option<f32>,       // --port-ratio
}

/// Service and version detection
#[derive(Clone, Debug, Default)]
pub struct ServiceDetection {
    pub enabled: bool,          // -sV
    pub allports: bool,         // --allports
    pub intensity: Option<u32>, // --version-intensity (0-9)
    pub light: bool,            // --version-light
    pub all: bool,              // --version-all
    pub trace: bool,            // --version-trace
}

/// OS detection options
#[derive(Clone, Debug, Default)]
pub struct OsDetection {
    pub enabled: bool,            // -O
    pub limit: bool,              // --osscan-limit
    pub guess: bool,              // --osscan-guess
    pub max_retries: Option<u32>, // --max-os-tries
}

/// NSE script options
#[derive(Clone, Debug, Default)]
pub struct NseScript {
    pub default: bool,                     // -sC
    pub script: Vec<String>,               // --script
    pub script_args: Option<String>,       // --script-args
    pub script_args_file: Option<PathBuf>, // --script-args-file
    pub script_help: Option<String>,       // --script-help
    pub script_trace: bool,                // --script-trace
    pub script_updatedb: bool,             // --script-updatedb
}

/// Timing and performance options
#[derive(Clone, Debug)]
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
    pub min_rate: Option<f32>,               // --min-rate
    pub max_rate: Option<f32>,               // --max-rate
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

#[derive(Clone, Copy, Debug, Default, Display, EnumCount, EnumIter, EnumMessage, Eq, PartialEq)]
pub enum TimingTemplate {
    #[strum(
        to_string = "Paranoid",
        detailed_message = "-T0: Extremely slow, one port at a time. IDS evasion mode. Waits 5 minutes between probes. Use for maximum stealth."
    )]
    Paranoid = 0,
    #[strum(
        to_string = "Sneaky",
        detailed_message = "-T1: Very slow scan for IDS evasion. Waits 15 seconds between probes. Slightly faster than paranoid but still stealthy."
    )]
    Sneaky = 1,
    #[strum(
        to_string = "Polite",
        detailed_message = "-T2: Slows scan to use less bandwidth. Less intrusive to target systems. Good for production environments during business hours."
    )]
    Polite = 2,
    #[default]
    #[strum(
        to_string = "Normal",
        detailed_message = "-T3: Default balanced mode. Good compromise between speed and reliability. Suitable for most scanning situations and networks."
    )]
    Normal = 3,
    #[strum(
        to_string = "Aggressive",
        detailed_message = "-T4: Faster scan assuming reliable network. Reduces timeouts. Good for local networks or fast connections with low latency."
    )]
    Aggressive = 4,
    #[strum(
        to_string = "Insane",
        detailed_message = "-T5: Maximum speed, may sacrifice accuracy. Very short timeouts. Only for very fast networks or when speed critical over accuracy."
    )]
    Insane = 5,
}

#[derive(
    Clone, Copy, Debug, Display, EnumCount, EnumIter, EnumMessage, EnumString, Eq, PartialEq,
)]
pub enum NsockEngine {
    #[strum(
        to_string = "iocp",
        detailed_message = "Windows-specific high-performance asynchronous I/O mechanism. Most efficient for Windows systems. Provides scalability for large connection counts. Not available on Unix/Linux."
    )]
    Iocp,
    #[strum(
        to_string = "epoll",
        detailed_message = "Linux-specific scalable I/O event notification. More efficient than poll/select for many connections. Default on Linux with epoll support. Best Linux performance."
    )]
    Epoll,
    #[strum(
        to_string = "kqueue",
        detailed_message = "BSD-based systems' scalable event notification (FreeBSD, OpenBSD, NetBSD, macOS). High performance on BSD platforms. Superior to select for concurrent connections."
    )]
    Kqueue,
    #[strum(
        to_string = "poll",
        detailed_message = "Portable alternative to select without file descriptor limits. Works on most systems including Windows. Similar efficiency to select but more scalable."
    )]
    Poll,
    #[strum(
        to_string = "select",
        detailed_message = "Fallback I/O multiplexing available everywhere. Guaranteed compatibility but limited scalability. Has hardcoded maximum file descriptor limits. Least efficient engine."
    )]
    Select,
}

/// Firewall/IDS evasion and spoofing
#[derive(Clone, Debug, Default)]
pub struct EvasionSpoofing {
    pub fragment_packets: bool,      // -f
    pub mtu: Option<u32>,            // --mtu
    pub decoys: Vec<String>,         // -D
    pub spoof_ip: Option<String>,    // -S
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
#[derive(Clone, Debug, Default)]
pub struct OutputOptions {
    pub normal: Option<PathBuf>,        // -oN
    pub xml: Option<PathBuf>,           // -oX
    pub script_kiddie: Option<PathBuf>, // -oS
    pub grepable: Option<PathBuf>,      // -oG
    pub all_formats: Option<PathBuf>,   // -oA (base filename)
    pub verbosity: Option<u32>,         // -v, -vv, etc. (0-9)
    pub debugging: Option<u32>,         // -d, -dd, etc. (0-9)
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
#[derive(Clone, Debug, Default)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_scan_type_as_index() {
        assert_eq!(TcpScanType::Syn.as_index(), 0);
        assert_eq!(TcpScanType::Connect.as_index(), 1);
        assert_eq!(TcpScanType::Ack.as_index(), 2);
        assert_eq!(TcpScanType::Window.as_index(), 3);
        assert_eq!(TcpScanType::Maimon.as_index(), 4);
        assert_eq!(TcpScanType::Null.as_index(), 5);
        assert_eq!(TcpScanType::Fin.as_index(), 6);
        assert_eq!(TcpScanType::Xmas.as_index(), 7);
        assert_eq!(TcpScanType::IpProtocol.as_index(), 8);
        assert_eq!(TcpScanType::Idle("zombie".to_string()).as_index(), 9);
        assert_eq!(TcpScanType::Ftp("relay".to_string()).as_index(), 10);
        assert_eq!(TcpScanType::Scanflags("SYN".to_string()).as_index(), 11);
    }

    #[test]
    fn test_tcp_scan_type_from_index() {
        assert_eq!(TcpScanType::from_index(0), Some(TcpScanType::Syn));
        assert_eq!(TcpScanType::from_index(1), Some(TcpScanType::Connect));
        assert_eq!(TcpScanType::from_index(2), Some(TcpScanType::Ack));
        assert_eq!(
            TcpScanType::from_index(9),
            Some(TcpScanType::Idle(String::new()))
        );
        assert_eq!(
            TcpScanType::from_index(10),
            Some(TcpScanType::Ftp(String::new()))
        );
        assert_eq!(
            TcpScanType::from_index(11),
            Some(TcpScanType::Scanflags(String::new()))
        );
    }

    #[test]
    fn test_tcp_scan_type_with_value() {
        let idle = TcpScanType::Idle(String::new());
        let idle_with_value = idle.with_value("192.168.1.100".to_string());
        assert_eq!(
            idle_with_value,
            TcpScanType::Idle("192.168.1.100".to_string())
        );

        let ftp = TcpScanType::Ftp(String::new());
        let ftp_with_value = ftp.with_value("ftp.example.com".to_string());
        assert_eq!(
            ftp_with_value,
            TcpScanType::Ftp("ftp.example.com".to_string())
        );

        let scanflags = TcpScanType::Scanflags(String::new());
        let scanflags_with_value = scanflags.with_value("SYNFIN".to_string());
        assert_eq!(
            scanflags_with_value,
            TcpScanType::Scanflags("SYNFIN".to_string())
        );
    }

    #[test]
    fn test_tcp_scan_type_requires_admin() {
        // Only Connect scan doesn't require admin
        assert!(!TcpScanType::Connect.requires_admin());

        // All other scan types require admin
        assert!(TcpScanType::Syn.requires_admin());
        assert!(TcpScanType::Ack.requires_admin());
        assert!(TcpScanType::Window.requires_admin());
        assert!(TcpScanType::Maimon.requires_admin());
        assert!(TcpScanType::Null.requires_admin());
        assert!(TcpScanType::Fin.requires_admin());
        assert!(TcpScanType::Xmas.requires_admin());
        assert!(TcpScanType::IpProtocol.requires_admin());
        assert!(TcpScanType::Idle("zombie".to_string()).requires_admin());
        assert!(TcpScanType::Ftp("relay".to_string()).requires_admin());
        assert!(TcpScanType::Scanflags("SYN".to_string()).requires_admin());
    }

    #[test]
    fn test_nmap_scan_default() {
        let scan = NmapScan::new();

        // Verify default TCP scan type is Connect
        assert!(matches!(
            scan.scan_technique.tcp,
            Some(TcpScanType::Connect)
        ));

        // Verify default timing template is Normal
        assert!(matches!(
            scan.timing.template,
            Some(TimingTemplate::Normal)
        ));

        // Verify UDP is disabled by default
        assert!(!scan.scan_technique.udp);

        // Verify targets are empty by default
        assert!(scan.target_specification.targets.is_empty());
    }

    #[test]
    fn test_sctp_scan_type_enum() {
        // Test that SCTP scan types are properly defined
        let init = SctpScanType::Init;
        let cookie = SctpScanType::Cookie;

        assert_ne!(init, cookie);
    }

    #[test]
    fn test_timing_template_ordering() {
        // Verify timing templates are correctly ordered by speed
        assert_eq!(TimingTemplate::Paranoid as u8, 0);
        assert_eq!(TimingTemplate::Sneaky as u8, 1);
        assert_eq!(TimingTemplate::Polite as u8, 2);
        assert_eq!(TimingTemplate::Normal as u8, 3);
        assert_eq!(TimingTemplate::Aggressive as u8, 4);
        assert_eq!(TimingTemplate::Insane as u8, 5);
    }

    #[test]
    fn test_port_specification_defaults() {
        let port_spec = PortSpecification::default();
        assert!(port_spec.ports.is_none());
        assert!(port_spec.exclude_ports.is_none());
        assert!(!port_spec.fast_mode);
        assert!(!port_spec.consecutive_ports);
        assert!(port_spec.top_ports.is_none());
        assert!(port_spec.port_ratio.is_none());
    }

    #[test]
    fn test_service_detection_defaults() {
        let service_detection = ServiceDetection::default();
        assert!(!service_detection.enabled);
        assert!(!service_detection.allports);
        assert!(service_detection.intensity.is_none());
        assert!(!service_detection.light);
        assert!(!service_detection.all);
        assert!(!service_detection.trace);
    }

    #[test]
    fn test_os_detection_defaults() {
        let os_detection = OsDetection::default();
        assert!(!os_detection.enabled);
        assert!(!os_detection.limit);
        assert!(!os_detection.guess);
        assert!(os_detection.max_retries.is_none());
    }
}
