use std::path::PathBuf;
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{Display, EnumIter, EnumMessage};

use crate::scan::model::{NmapScan, SctpScanType, TcpScanType, TimingTemplate};

#[derive(Clone, Copy, Debug, Display, EnumIter, EnumMessage, Eq, Hash, PartialEq)]
pub enum NmapFlag {
    // Target specification
    #[strum(
        to_string = "Targets",
        message = "Hostnames, IP addresses, networks, etc"
    )]
    Targets,
    #[strum(
        to_string = "Input file (-iL)",
        message = "Input from list of hosts/networks"
    )]
    InputFile,
    #[strum(to_string = "Exclude (--exclude)", message = "Exclude hosts/networks")]
    Exclude,
    #[strum(
        to_string = "Exclude file (--exclude-file)",
        message = "Exclude list from file"
    )]
    ExcludeFile,
    #[strum(
        to_string = "Random targets (-iR)",
        message = "Number of random targets"
    )]
    RandomTargets,
    #[strum(to_string = "Unique (--unique)")]
    Unique,
    #[strum(to_string = "No resolve (-n)")]
    NoResolve,
    #[strum(to_string = "Always resolve (-R)")]
    AlwaysResolve,
    #[strum(to_string = "Resolve all (--resolve-all)")]
    ResolveAll,
    #[strum(to_string = "System DNS (--system-dns)")]
    SystemDns,
    #[strum(to_string = "DNS servers (--dns-servers)", message = "Server list")]
    DnsServers,

    // Host discovery
    #[strum(to_string = "List scan (-sL)")]
    ListScan,
    #[strum(to_string = "Ping scan (-sn)")]
    PingScan,
    #[strum(to_string = "Skip port scan (-Pn)")]
    SkipPortScan,
    #[strum(to_string = "SYN (-PS)", message = "Port list")]
    SynDiscovery,
    #[strum(to_string = "ACK (-PA)", message = "Port list")]
    AckDiscovery,
    #[strum(to_string = "UDP (-PU)", message = "Port list")]
    UdpDiscovery,
    #[strum(to_string = "SCTP (-PY)", message = "Port list")]
    SctpDiscovery,
    #[strum(to_string = "ICMP echo (-PE)")]
    IcmpEcho,
    #[strum(to_string = "ICMP timestamp (-PP)")]
    IcmpTimestamp,
    #[strum(to_string = "ICMP netmask (-PM)")]
    IcmpNetmask,
    #[strum(to_string = "IP protocol ping (-PO)", message = "Protocol list")]
    IpProtocolPing,
    #[strum(to_string = "Disable ARP ping (--disable-arp-ping)")]
    DisableArpPing,
    #[strum(to_string = "Discover ignore RST (--discover-ignore-rst)")]
    DiscoverIgnoreRst,
    #[strum(to_string = "Traceroute (--traceroute)")]
    Traceroute,

    // Scan technique
    #[strum(to_string = "TCP scan")]
    TcpScan,
    #[strum(to_string = "UDP scan")]
    UdpScan,
    #[strum(to_string = "SCTP scan")]
    SctpScan,

    // Port specification
    #[strum(to_string = "Ports (-p)", message = "Port ranges")]
    Ports,
    #[strum(to_string = "Exclude ports (--exclude-ports)", message = "Port ranges")]
    ExcludePorts,
    #[strum(to_string = "Fast mode (-F)")]
    FastMode,
    #[strum(to_string = "Consecutive ports (-r)")]
    ConsecutivePorts,
    #[strum(to_string = "Top ports (--top-ports)", message = "Number of ports")]
    TopPorts,
    #[strum(to_string = "Port ratio (--port-ratio)", message = "Ratio")]
    PortRatio,

    // Service detection
    #[strum(to_string = "Version detection (-sV)")]
    VersionDetection,
    #[strum(to_string = "All ports (--allports)")]
    AllPorts,
    #[strum(
        to_string = "Version intensity (--version-intensity)",
        message = "Intensity"
    )]
    VersionIntensity,
    #[strum(to_string = "Version light (--version-light)")]
    VersionLight,
    #[strum(to_string = "Version all (--version-all)")]
    VersionAll,
    #[strum(to_string = "Version trace (--version-trace)")]
    VersionTrace,

    // Timing
    #[strum(to_string = "Timing template (-T)")]
    TimingTemplate,
}

pub enum FlagValue<'a> {
    // Base types
    Bool(&'a mut bool),
    Int(&'a mut Option<u32>),
    Float(&'a mut Option<f32>),
    String(&'a mut Option<String>),
    VecInt(&'a mut Vec<u32>),
    VecString(&'a mut Vec<String>),
    Path(&'a mut Option<PathBuf>),

    // Enum types
    TcpScanType(&'a mut Option<TcpScanType>),
    SctpScanType(&'a mut Option<SctpScanType>),
    TimingTemplate(&'a mut Option<TimingTemplate>),

    // Used for handling special cases of mutually exclusive TCP scan types
    RequiredString(&'a mut String),
}

impl NmapFlag {
    pub fn get_flag_value<'a>(self, scan: &'a mut NmapScan) -> FlagValue<'a> {
        match self {
            // Target specification
            NmapFlag::Targets => FlagValue::VecString(&mut scan.target_specification.targets),
            NmapFlag::InputFile => FlagValue::Path(&mut scan.target_specification.input_file),
            NmapFlag::Exclude => FlagValue::VecString(&mut scan.target_specification.exclude),
            NmapFlag::ExcludeFile => FlagValue::Path(&mut scan.target_specification.exclude_file),
            NmapFlag::RandomTargets => {
                FlagValue::Int(&mut scan.target_specification.random_targets)
            }
            NmapFlag::Unique => FlagValue::Bool(&mut scan.target_specification.unique),
            NmapFlag::NoResolve => FlagValue::Bool(&mut scan.target_specification.no_resolve),
            NmapFlag::AlwaysResolve => {
                FlagValue::Bool(&mut scan.target_specification.always_resolve)
            }
            NmapFlag::ResolveAll => FlagValue::Bool(&mut scan.target_specification.resolve_all),
            NmapFlag::SystemDns => FlagValue::Bool(&mut scan.target_specification.system_dns),
            NmapFlag::DnsServers => {
                FlagValue::VecString(&mut scan.target_specification.dns_servers)
            }

            // Host discovery
            NmapFlag::ListScan => FlagValue::Bool(&mut scan.host_discovery.list_scan),
            NmapFlag::PingScan => FlagValue::Bool(&mut scan.host_discovery.ping_scan),
            NmapFlag::SkipPortScan => FlagValue::Bool(&mut scan.host_discovery.skip_port_scan),
            NmapFlag::SynDiscovery => FlagValue::VecInt(&mut scan.host_discovery.syn_discovery),
            NmapFlag::AckDiscovery => FlagValue::VecInt(&mut scan.host_discovery.ack_discovery),
            NmapFlag::UdpDiscovery => FlagValue::VecInt(&mut scan.host_discovery.udp_discovery),
            NmapFlag::SctpDiscovery => FlagValue::VecInt(&mut scan.host_discovery.sctp_discovery),
            NmapFlag::IcmpEcho => FlagValue::Bool(&mut scan.host_discovery.icmp_echo),
            NmapFlag::IcmpTimestamp => FlagValue::Bool(&mut scan.host_discovery.icmp_timestamp),
            NmapFlag::IcmpNetmask => FlagValue::Bool(&mut scan.host_discovery.icmp_netmask),
            NmapFlag::IpProtocolPing => {
                FlagValue::VecInt(&mut scan.host_discovery.ip_protocol_ping)
            }
            NmapFlag::DisableArpPing => FlagValue::Bool(&mut scan.host_discovery.disable_arp_ping),
            NmapFlag::DiscoverIgnoreRst => {
                FlagValue::Bool(&mut scan.host_discovery.discover_ignore_rst)
            }
            NmapFlag::Traceroute => FlagValue::Bool(&mut scan.host_discovery.traceroute),

            // Scan technique
            NmapFlag::TcpScan => FlagValue::TcpScanType(&mut scan.scan_technique.tcp),
            NmapFlag::UdpScan => FlagValue::Bool(&mut scan.scan_technique.udp),
            NmapFlag::SctpScan => FlagValue::SctpScanType(&mut scan.scan_technique.sctp),

            // Service detection
            NmapFlag::VersionDetection => FlagValue::Bool(&mut scan.service_detection.enabled),
            NmapFlag::AllPorts => FlagValue::Bool(&mut scan.service_detection.allports),
            NmapFlag::VersionIntensity => FlagValue::Int(&mut scan.service_detection.intensity),
            NmapFlag::VersionLight => FlagValue::Bool(&mut scan.service_detection.light),
            NmapFlag::VersionAll => FlagValue::Bool(&mut scan.service_detection.all),
            NmapFlag::VersionTrace => FlagValue::Bool(&mut scan.service_detection.trace),

            // Port specification
            NmapFlag::Ports => FlagValue::String(&mut scan.port_specification.ports),
            NmapFlag::ExcludePorts => FlagValue::String(&mut scan.port_specification.exclude_ports),
            NmapFlag::FastMode => FlagValue::Bool(&mut scan.port_specification.fast_mode),
            NmapFlag::ConsecutivePorts => {
                FlagValue::Bool(&mut scan.port_specification.consecutive_ports)
            }
            NmapFlag::TopPorts => FlagValue::Int(&mut scan.port_specification.top_ports),
            NmapFlag::PortRatio => FlagValue::Float(&mut scan.port_specification.port_ratio),

            // Timing
            NmapFlag::TimingTemplate => FlagValue::TimingTemplate(&mut scan.timing.template),
        }
    }

    pub fn next(&self) -> Self {
        let all_flags = NmapFlag::iter().collect::<Vec<_>>();
        let index = all_flags.iter().position(|f| f == self).unwrap();
        let next_index = (index + 1) % all_flags.len();
        all_flags[next_index]
    }

    pub fn prev(&self) -> Self {
        let all_flags = NmapFlag::iter().collect::<Vec<_>>();
        let index = all_flags.iter().position(|f| f == self).unwrap();
        let prev_index = (index + all_flags.len() - 1) % all_flags.len();
        all_flags[prev_index]
    }

    pub fn first() -> Self {
        NmapFlag::iter().next().unwrap()
    }

    pub fn get_variant_count(self) -> Option<usize> {
        match self {
            NmapFlag::TimingTemplate => Some(TimingTemplate::COUNT),
            NmapFlag::TcpScan => Some(TcpScanType::COUNT),
            NmapFlag::SctpScan => Some(SctpScanType::COUNT),
            _ => None,
        }
    }
}
