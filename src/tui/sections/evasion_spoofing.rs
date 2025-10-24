use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{app::App, utils::render_flags_in_clamped_grid},
};

pub fn render_evasion_spoofing(app: &mut App, frame: &mut Frame, area: Rect) {
    let flags_grid = vec![
        vec![
            NmapFlag::FragmentPackets,
            NmapFlag::Mtu,
            NmapFlag::Decoys,
            NmapFlag::Proxies,
        ],
        vec![
            NmapFlag::SpoofIp,
            NmapFlag::SpoofMac,
            NmapFlag::Interface,
            NmapFlag::SourcePort,
        ],
        vec![
            NmapFlag::Data,
            NmapFlag::DataString,
            NmapFlag::DataLength,
            NmapFlag::IpOptions,
        ],
        vec![
            NmapFlag::Ttl,
            NmapFlag::RandomizeHosts,
            NmapFlag::Badsum,
            NmapFlag::Adler32,
        ],
    ];

    render_flags_in_clamped_grid(app, frame, area, flags_grid);
}
