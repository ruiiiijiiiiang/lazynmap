use std::path::PathBuf;
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{Display, EnumIter, EnumMessage};

use crate::scan::model::{NmapScan, TcpScanType, TimingTemplate};

#[derive(Debug, Display, Clone, Copy, Eq, Hash, PartialEq, EnumIter, EnumMessage)]
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
    // #[strum(to_string = "Idle (-sI)", message = "Zombie host")]
    // Idle,
    // #[strum(to_string = "FTP (-b)", message = "FTP relay host")]
    // Ftp,
    // #[strum(to_string = "Flags (--scanflags)", message = "Custom TCP scan")]
    // Scanflags,

    // Timing
    #[strum(to_string = "Timing template (-T)")]
    TimingTemplate,

    #[strum(to_string = "Top ports (--top-ports)", message = "Number of ports")]
    TopPorts,
}

pub enum FlagValue<'a> {
    // Base types
    Bool(&'a mut bool),
    Int(&'a mut Option<u32>),
    String(&'a mut Option<String>),
    VecInt(&'a mut Vec<u32>),
    VecString(&'a mut Vec<String>),
    Path(&'a mut Option<PathBuf>),

    // Enum types
    TcpScanType(&'a mut Option<TcpScanType>),
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
            // NmapFlag::Scanflags => {
            //     Self::ensure_tcp_variant(
            //         &mut scan.scan_technique.tcp,
            //         TcpScanType::Scanflags(String::new()),
            //     );
            //     match scan.scan_technique.tcp.as_mut().unwrap() {
            //         TcpScanType::Scanflags(s) => FlagValue::RequiredString(s),
            //         _ => unreachable!(),
            //     }
            // }
            // NmapFlag::Idle => {
            //     Self::ensure_tcp_variant(
            //         &mut scan.scan_technique.tcp,
            //         TcpScanType::Idle(String::new()),
            //     );
            //     match scan.scan_technique.tcp.as_mut().unwrap() {
            //         TcpScanType::Idle(s) => FlagValue::RequiredString(s),
            //         _ => unreachable!(),
            //     }
            // }
            // NmapFlag::Ftp => {
            //     Self::ensure_tcp_variant(
            //         &mut scan.scan_technique.tcp,
            //         TcpScanType::Ftp(String::new()),
            //     );
            //     match scan.scan_technique.tcp.as_mut().unwrap() {
            //         TcpScanType::Ftp(s) => FlagValue::RequiredString(s),
            //         _ => unreachable!(),
            //     }
            // }

            // Timing
            NmapFlag::TimingTemplate => FlagValue::TimingTemplate(&mut scan.timing.template),
            NmapFlag::TopPorts => FlagValue::Int(&mut scan.port_specification.top_ports),
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
            _ => None,
        }
    }

    // fn ensure_tcp_variant(tcp: &mut Option<TcpScanType>, variant: TcpScanType) {
    //     let needs_set = match tcp {
    //         None => true,
    //         Some(TcpScanType::Scanflags(_)) if matches!(variant, TcpScanType::Scanflags(_)) => {
    //             false
    //         }
    //         Some(TcpScanType::Idle(_)) if matches!(variant, TcpScanType::Idle(_)) => false,
    //         Some(TcpScanType::Ftp(_)) if matches!(variant, TcpScanType::Ftp(_)) => false,
    //         Some(_) => true,
    //     };
    //
    //     if needs_set {
    //         *tcp = Some(variant);
    //     }
    // }
}
