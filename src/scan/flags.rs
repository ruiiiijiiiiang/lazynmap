use std::path::PathBuf;
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{Display, EnumIter, EnumMessage};

use crate::scan::model::{NmapScan, TimingTemplate};

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

    // Host discovery
    #[strum(to_string = "List scan (-sL)")]
    ListScan,
    #[strum(to_string = "Ping scan (-sn)")]
    PingScan,
    #[strum(to_string = "Skip port scan (-Pn)")]
    SkipPortScan,
    #[strum(to_string = "Traceroute (--traceroute)")]
    Traceroute,
    #[strum(to_string = "SYN disccovery (-PS)", message = "Port list")]
    SynDiscovery,
    #[strum(to_string = "ACK disccovery (-PA)", message = "Port list")]
    AckDiscovery,
    #[strum(to_string = "UDP disccovery (-PU)", message = "Port list")]
    UdpDiscovery,
    #[strum(to_string = "SCTP disccovery (-PY)", message = "Port list")]
    SctpDiscovery,
    #[strum(to_string = "ICMP echo (-PE)")]
    IcmpEcho,
    #[strum(to_string = "ICMP timestamp (-PP)")]
    IcmpTimestamp,
    #[strum(to_string = "ICMP netmask (-PM)")]
    IcmpNetmask,
    #[strum(to_string = "IP protocol ping (-PO)", message = "Protocol list")]
    IpProtocolPing,
    #[strum(to_string = "System DNS (--system-dns)")]
    SystemDns,
    #[strum(to_string = "No resolve (-n)")]
    NoResolve,
    #[strum(to_string = "Always Resolve (-R)")]
    AlwaysResolve,
    #[strum(to_string = "DNS servers (--dns-servers)", message = "Server list")]
    DnsServers,

    #[strum(to_string = "Timing template")]
    TimingTemplate,
}

pub enum FlagValue<'a> {
    Bool(&'a mut bool),
    Int(&'a mut Option<u32>),
    VecInt(&'a mut Vec<u32>),
    VecString(&'a mut Vec<String>),
    Path(&'a mut Option<PathBuf>),
    TimingTemplate(&'a mut Option<TimingTemplate>),
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

            // Host discovery
            NmapFlag::ListScan => FlagValue::Bool(&mut scan.host_discovery.list_scan),
            NmapFlag::PingScan => FlagValue::Bool(&mut scan.host_discovery.ping_scan),
            NmapFlag::SkipPortScan => FlagValue::Bool(&mut scan.host_discovery.skip_port_scan),
            NmapFlag::Traceroute => FlagValue::Bool(&mut scan.host_discovery.traceroute),
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
            NmapFlag::SystemDns => FlagValue::Bool(&mut scan.host_discovery.system_dns),
            NmapFlag::NoResolve => FlagValue::Bool(&mut scan.host_discovery.no_resolve),
            NmapFlag::AlwaysResolve => FlagValue::Bool(&mut scan.host_discovery.always_resolve),
            NmapFlag::DnsServers => FlagValue::VecString(&mut scan.host_discovery.dns_servers),

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
            _ => None,
        }
    }
}
