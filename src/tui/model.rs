use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumMessage};

use crate::scan::model::NmapScan;

#[derive(Debug, Display, Clone, Copy, Eq, Hash, PartialEq, EnumIter, EnumMessage)]
pub enum FocusPath {
    TargetSpecification(TargetSpecificationFocus),
    HostDiscovery(HostDiscoveryFocus),
}

#[derive(Debug, Display, Clone, Copy, Eq, Hash, PartialEq, EnumIter, EnumMessage)]
pub enum HostDiscoveryFocus {
    ListScan,
    PingScan,
    SkipPortScan,
    IcmpEcho,
    IcmpTimestamp,
    IcmpNetmask,
    SystemDns,
    Traceroute,
}

#[derive(Debug, Display, Clone, Copy, Eq, Hash, PartialEq, EnumIter, EnumMessage)]
pub enum TargetSpecificationFocus {
    Targets,
    // Port,
}

pub enum FlagValue<'a> {
    Bool(&'a mut bool),
    VecString(&'a mut Vec<String>),
}

impl FocusPath {
    pub fn get_path_value<'a>(&self, scan: &'a mut NmapScan) -> FlagValue<'a> {
        match self {
            FocusPath::HostDiscovery(HostDiscoveryFocus::ListScan) => {
                FlagValue::Bool(&mut scan.host_discovery.list_scan)
            }
            FocusPath::HostDiscovery(HostDiscoveryFocus::PingScan) => {
                FlagValue::Bool(&mut scan.host_discovery.ping_scan)
            }
            FocusPath::HostDiscovery(HostDiscoveryFocus::SkipPortScan) => {
                FlagValue::Bool(&mut scan.host_discovery.skip_port_scan)
            }
            FocusPath::HostDiscovery(HostDiscoveryFocus::IcmpEcho) => {
                FlagValue::Bool(&mut scan.host_discovery.icmp_echo)
            }
            FocusPath::HostDiscovery(HostDiscoveryFocus::IcmpTimestamp) => {
                FlagValue::Bool(&mut scan.host_discovery.icmp_timestamp)
            }
            FocusPath::HostDiscovery(HostDiscoveryFocus::IcmpNetmask) => {
                FlagValue::Bool(&mut scan.host_discovery.icmp_netmask)
            }
            FocusPath::HostDiscovery(HostDiscoveryFocus::SystemDns) => {
                FlagValue::Bool(&mut scan.host_discovery.system_dns)
            }
            FocusPath::HostDiscovery(HostDiscoveryFocus::Traceroute) => {
                FlagValue::Bool(&mut scan.host_discovery.traceroute)
            }
            FocusPath::TargetSpecification(TargetSpecificationFocus::Targets) => {
                FlagValue::VecString(&mut scan.target_specification.targets)
            }
        }
    }

    fn get_paths_linear() -> Vec<FocusPath> {
        let mut paths = Vec::new();
        for path in FocusPath::iter() {
            for subpath in path.iter() {
                paths.push(subpath);
            }
        }
        paths
    }
}
