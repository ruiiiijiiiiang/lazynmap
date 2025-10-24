use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{app::App, utils::render_flags_in_clamped_grid},
};

pub fn render_host_discovery(app: &mut App, frame: &mut Frame, area: Rect) {
    let flags_grid = vec![
        vec![
            NmapFlag::ListScan,
            NmapFlag::PingScan,
            NmapFlag::SkipPortScan,
        ],
        vec![
            NmapFlag::SynDiscovery,
            NmapFlag::AckDiscovery,
            NmapFlag::UdpDiscovery,
            NmapFlag::SctpDiscovery,
        ],
        vec![
            NmapFlag::IcmpEcho,
            NmapFlag::IcmpTimestamp,
            NmapFlag::IcmpNetmask,
            NmapFlag::IpProtocolPing,
        ],
        vec![
            NmapFlag::DisableArpPing,
            NmapFlag::DiscoverIgnoreRst,
            NmapFlag::Traceroute,
        ],
    ];

    render_flags_in_clamped_grid(app, frame, area, flags_grid);
}
