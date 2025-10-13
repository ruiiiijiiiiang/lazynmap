use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter};

use crate::scan::model::NmapScan;

#[derive(Debug, Display, Clone, Copy, Eq, Hash, PartialEq, EnumIter)]
pub enum NmapFlag {
    ListScan,
    PingScan,
    SkipPortScan,
    IcmpEcho,
    IcmpTimestamp,
    IcmpNetmask,
    SystemDns,
    Traceroute,
}

pub enum FlagValue<'a> {
    Bool(&'a mut bool),
}

impl NmapFlag {
    pub fn to_label(&self) -> &'static str {
        match self {
            NmapFlag::ListScan => "List scan (-sL)",
            NmapFlag::PingScan => "Ping scan (-sn)",
            NmapFlag::SkipPortScan => "Skip port scan (-Pn)",
            NmapFlag::IcmpEcho => "ICMP echo (-PE)",
            NmapFlag::IcmpTimestamp => "ICMP timestamp (-PP)",
            NmapFlag::IcmpNetmask => "ICMP netmask (-PM)",
            NmapFlag::SystemDns => "System DNS (--system-dns)",
            NmapFlag::Traceroute => "Traceroute (--traceroute)",
        }
    }

    pub fn get_flag_value<'a>(&self, scan: &'a mut NmapScan) -> FlagValue<'a> {
        match self {
            NmapFlag::ListScan => FlagValue::Bool(&mut scan.host_discovery.list_scan),
            NmapFlag::PingScan => FlagValue::Bool(&mut scan.host_discovery.ping_scan),
            NmapFlag::SkipPortScan => FlagValue::Bool(&mut scan.host_discovery.skip_port_scan),
            NmapFlag::IcmpEcho => FlagValue::Bool(&mut scan.host_discovery.icmp_echo),
            NmapFlag::IcmpTimestamp => FlagValue::Bool(&mut scan.host_discovery.icmp_timestamp),
            NmapFlag::IcmpNetmask => FlagValue::Bool(&mut scan.host_discovery.icmp_netmask),
            NmapFlag::SystemDns => FlagValue::Bool(&mut scan.host_discovery.system_dns),
            NmapFlag::Traceroute => FlagValue::Bool(&mut scan.host_discovery.traceroute),
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
}
