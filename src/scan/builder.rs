use std::fmt::Write;

use crate::scan::model::{
    EvasionSpoofing, HostDiscovery, MiscOptions, NmapScan, OsDetection, OutputOptions,
    PortSpecification, ScanTechnique, ScriptScan, SctpScanType, ServiceDetection,
    TimingPerformance,
};

/// Builder for converting NmapScan structs into command strings
pub struct NmapCommandBuilder;

impl NmapCommandBuilder {
    /// Build a complete nmap command string from an NmapScan struct
    pub fn build(scan: &NmapScan) -> String {
        let mut cmd = String::from("nmap");

        // Host discovery
        Self::build_host_discovery(&mut cmd, &scan.host_discovery);

        // Scan technique
        Self::build_scan_technique(&mut cmd, &scan.scan_technique);

        // Port specification
        Self::build_port_specification(&mut cmd, &scan.ports);

        // Service/Version detection
        Self::build_service_detection(&mut cmd, &scan.service_detection);

        // Script scan
        Self::build_script_scan(&mut cmd, &scan.script_scan);

        // OS detection
        Self::build_os_detection(&mut cmd, &scan.os_detection);

        // Timing and performance
        Self::build_timing_performance(&mut cmd, &scan.timing);

        // Firewall/IDS evasion
        Self::build_evasion_spoofing(&mut cmd, &scan.evasion);

        // Output
        Self::build_output(&mut cmd, &scan.output);

        // Miscellaneous
        Self::build_misc(&mut cmd, &scan.misc);

        // Target specification (at the end)
        Self::build_target_specification(&mut cmd, scan);

        cmd
    }

    fn build_host_discovery(cmd: &mut String, hd: &HostDiscovery) {
        if hd.list_scan {
            cmd.push_str(" -sL");
        }
        if hd.ping_scan {
            cmd.push_str(" -sn");
        }
        if hd.skip_port_scan {
            cmd.push_str(" -Pn");
        }
        if !hd.syn_discovery.is_empty() {
            write!(cmd, " -PS{}", Self::format_port_list(&hd.syn_discovery)).ok();
        }
        if !hd.ack_discovery.is_empty() {
            write!(cmd, " -PA{}", Self::format_port_list(&hd.ack_discovery)).ok();
        }
        if !hd.udp_discovery.is_empty() {
            write!(cmd, " -PU{}", Self::format_port_list(&hd.udp_discovery)).ok();
        }
        if !hd.sctp_discovery.is_empty() {
            write!(cmd, " -PY{}", Self::format_port_list(&hd.sctp_discovery)).ok();
        }
        if hd.icmp_echo {
            cmd.push_str(" -PE");
        }
        if hd.icmp_timestamp {
            cmd.push_str(" -PP");
        }
        if hd.icmp_netmask {
            cmd.push_str(" -PM");
        }
        if !hd.ip_protocol_ping.is_empty() {
            write!(
                cmd,
                " -PO{}",
                Self::format_protocol_list(&hd.ip_protocol_ping)
            )
            .ok();
        }
        if hd.traceroute {
            cmd.push_str(" --traceroute");
        }
        if !hd.dns_servers.is_empty() {
            write!(cmd, " --dns-servers {}", hd.dns_servers.join(",")).ok();
        }
        if hd.system_dns {
            cmd.push_str(" --system-dns");
        }
    }

    fn build_scan_technique(cmd: &mut String, st: &ScanTechnique) {
        match st {
            ScanTechnique::Syn => cmd.push_str(" -sS"),
            ScanTechnique::Connect => cmd.push_str(" -sT"),
            ScanTechnique::Ack => cmd.push_str(" -sA"),
            ScanTechnique::Window => cmd.push_str(" -sW"),
            ScanTechnique::Maimon => cmd.push_str(" -sM"),
            ScanTechnique::Udp => cmd.push_str(" -sU"),
            ScanTechnique::TcpNull => cmd.push_str(" -sN"),
            ScanTechnique::Fin => cmd.push_str(" -sF"),
            ScanTechnique::Xmas => cmd.push_str(" -sX"),
            ScanTechnique::Scanflags(flags) => {
                write!(cmd, " --scanflags {}", Self::quote_if_needed(flags)).ok();
            }
            ScanTechnique::Idle(zombie) => {
                write!(cmd, " -sI {}", Self::quote_if_needed(zombie)).ok();
            }
            ScanTechnique::Sctp(sctp_type) => match sctp_type {
                SctpScanType::Init => cmd.push_str(" -sY"),
                SctpScanType::Cookie => cmd.push_str(" -sZ"),
            },
            ScanTechnique::IpProtocol => cmd.push_str(" -sO"),
            ScanTechnique::Ftp(relay) => {
                write!(cmd, " -b {}", Self::quote_if_needed(relay)).ok();
            }
            ScanTechnique::Multiple(techniques) => {
                for technique in techniques {
                    Self::build_scan_technique(cmd, technique);
                }
            }
        }
    }

    fn build_port_specification(cmd: &mut String, ps: &PortSpecification) {
        if let Some(ref ports) = ps.ports {
            write!(cmd, " -p {}", Self::quote_if_needed(ports)).ok();
        }
        if let Some(ref exclude_ports) = ps.exclude_ports {
            write!(
                cmd,
                " --exclude-ports {}",
                Self::quote_if_needed(exclude_ports)
            )
            .ok();
        }
        if ps.fast_mode {
            cmd.push_str(" -F");
        }
        if ps.consecutive_ports {
            cmd.push_str(" -r");
        }
        if let Some(top_ports) = ps.top_ports {
            write!(cmd, " --top-ports {}", top_ports).ok();
        }
        if let Some(port_ratio) = ps.port_ratio {
            write!(cmd, " --port-ratio {}", port_ratio).ok();
        }
    }

    fn build_service_detection(cmd: &mut String, sd: &ServiceDetection) {
        if sd.enabled {
            cmd.push_str(" -sV");
        }
        if let Some(intensity) = sd.intensity {
            write!(cmd, " --version-intensity {}", intensity).ok();
        }
        if sd.light {
            cmd.push_str(" --version-light");
        }
        if sd.all {
            cmd.push_str(" --version-all");
        }
        if sd.trace {
            cmd.push_str(" --version-trace");
        }
    }

    fn build_script_scan(cmd: &mut String, ss: &ScriptScan) {
        if ss.default {
            cmd.push_str(" -sC");
        }
        if !ss.scripts.is_empty() {
            write!(cmd, " --script {}", ss.scripts.join(",")).ok();
        }
        if let Some(ref args) = ss.script_args {
            write!(cmd, " --script-args {}", Self::quote_if_needed(args)).ok();
        }
        if let Some(ref args_file) = ss.script_args_file {
            write!(cmd, " --script-args-file {}", Self::quote_path(args_file)).ok();
        }
        if ss.script_trace {
            cmd.push_str(" --script-trace");
        }
        if ss.script_updatedb {
            cmd.push_str(" --script-updatedb");
        }
        if let Some(ref help) = ss.script_help {
            write!(cmd, " --script-help {}", Self::quote_if_needed(help)).ok();
        }
    }

    fn build_os_detection(cmd: &mut String, od: &OsDetection) {
        if od.enabled {
            cmd.push_str(" -O");
        }
        if od.limit {
            cmd.push_str(" --osscan-limit");
        }
        if od.guess {
            cmd.push_str(" --osscan-guess");
        }
        if let Some(max_retries) = od.max_retries {
            write!(cmd, " --max-os-tries {}", max_retries).ok();
        }
    }

    fn build_timing_performance(cmd: &mut String, tp: &TimingPerformance) {
        if let Some(ref template) = tp.template {
            write!(cmd, " -T{}", *template as u8).ok();
        }
        if let Some(min_hostgroup) = tp.min_hostgroup {
            write!(cmd, " --min-hostgroup {}", min_hostgroup).ok();
        }
        if let Some(max_hostgroup) = tp.max_hostgroup {
            write!(cmd, " --max-hostgroup {}", max_hostgroup).ok();
        }
        if let Some(min_parallelism) = tp.min_parallelism {
            write!(cmd, " --min-parallelism {}", min_parallelism).ok();
        }
        if let Some(max_parallelism) = tp.max_parallelism {
            write!(cmd, " --max-parallelism {}", max_parallelism).ok();
        }
        if let Some(ref min_rtt) = tp.min_rtt_timeout {
            write!(cmd, " --min-rtt-timeout {}", Self::quote_if_needed(min_rtt)).ok();
        }
        if let Some(ref max_rtt) = tp.max_rtt_timeout {
            write!(cmd, " --max-rtt-timeout {}", Self::quote_if_needed(max_rtt)).ok();
        }
        if let Some(ref initial_rtt) = tp.initial_rtt_timeout {
            write!(
                cmd,
                " --initial-rtt-timeout {}",
                Self::quote_if_needed(initial_rtt)
            )
            .ok();
        }
        if let Some(max_retries) = tp.max_retries {
            write!(cmd, " --max-retries {}", max_retries).ok();
        }
        if let Some(ref host_timeout) = tp.host_timeout {
            write!(
                cmd,
                " --host-timeout {}",
                Self::quote_if_needed(host_timeout)
            )
            .ok();
        }
        if let Some(ref script_timeout) = tp.script_timeout {
            write!(
                cmd,
                " --script-timeout {}",
                Self::quote_if_needed(script_timeout)
            )
            .ok();
        }
        if let Some(ref scan_delay) = tp.scan_delay {
            write!(cmd, " --scan-delay {}", Self::quote_if_needed(scan_delay)).ok();
        }
        if let Some(ref max_scan_delay) = tp.max_scan_delay {
            write!(
                cmd,
                " --max-scan-delay {}",
                Self::quote_if_needed(max_scan_delay)
            )
            .ok();
        }
        if let Some(min_rate) = tp.min_rate {
            write!(cmd, " --min-rate {}", min_rate).ok();
        }
        if let Some(max_rate) = tp.max_rate {
            write!(cmd, " --max-rate {}", max_rate).ok();
        }
        if tp.defeat_rst_ratelimit {
            cmd.push_str(" --defeat-rst-ratelimit");
        }
        if tp.defeat_icmp_ratelimit {
            cmd.push_str(" --defeat-icmp-ratelimit");
        }
        if let Some(ref engine) = tp.nsock_engine {
            write!(cmd, " --nsock-engine {}", Self::quote_if_needed(engine)).ok();
        }
    }

    fn build_evasion_spoofing(cmd: &mut String, es: &EvasionSpoofing) {
        if es.fragment_packets {
            cmd.push_str(" -f");
        }
        if let Some(mtu) = es.mtu {
            write!(cmd, " --mtu {}", mtu).ok();
        }
        if !es.decoys.is_empty() {
            write!(cmd, " -D {}", es.decoys.join(",")).ok();
        }
        if let Some(ref spoof_ip) = es.spoof_ip {
            write!(cmd, " -S {}", spoof_ip).ok();
        }
        if let Some(ref interface) = es.interface {
            write!(cmd, " -e {}", Self::quote_if_needed(interface)).ok();
        }
        if let Some(source_port) = es.source_port {
            write!(cmd, " -g {}", source_port).ok();
        }
        if let Some(ref data) = es.data {
            write!(cmd, " --data {}", Self::quote_if_needed(data)).ok();
        }
        if let Some(ref data_string) = es.data_string {
            write!(cmd, " --data-string {}", Self::quote_if_needed(data_string)).ok();
        }
        if let Some(data_length) = es.data_length {
            write!(cmd, " --data-length {}", data_length).ok();
        }
        if let Some(ref ip_options) = es.ip_options {
            write!(cmd, " --ip-options {}", Self::quote_if_needed(ip_options)).ok();
        }
        if let Some(ttl) = es.ttl {
            write!(cmd, " --ttl {}", ttl).ok();
        }
        if es.randomize_hosts {
            cmd.push_str(" --randomize-hosts");
        }
        if let Some(ref spoof_mac) = es.spoof_mac {
            write!(cmd, " --spoof-mac {}", Self::quote_if_needed(spoof_mac)).ok();
        }
        if es.badsum {
            cmd.push_str(" --badsum");
        }
        if es.adler32 {
            cmd.push_str(" --adler32");
        }
    }

    fn build_output(cmd: &mut String, out: &OutputOptions) {
        if let Some(ref normal) = out.normal {
            write!(cmd, " -oN {}", Self::quote_path(normal)).ok();
        }
        if let Some(ref xml) = out.xml {
            write!(cmd, " -oX {}", Self::quote_path(xml)).ok();
        }
        if let Some(ref script_kiddie) = out.script_kiddie {
            write!(cmd, " -oS {}", Self::quote_path(script_kiddie)).ok();
        }
        if let Some(ref grepable) = out.grepable {
            write!(cmd, " -oG {}", Self::quote_path(grepable)).ok();
        }
        if let Some(ref all_formats) = out.all_formats {
            write!(cmd, " -oA {}", Self::quote_if_needed(all_formats)).ok();
        }

        // Handle verbose flag
        match out.verbose {
            0 => {}
            1 => cmd.push_str(" -v"),
            2 => cmd.push_str(" -vv"),
            n => {
                for _ in 0..n {
                    cmd.push_str(" -v");
                }
            }
        }

        // Handle debug flag
        match out.debug {
            0 => {}
            1 => cmd.push_str(" -d"),
            2 => cmd.push_str(" -dd"),
            n => {
                for _ in 0..n {
                    cmd.push_str(" -d");
                }
            }
        }

        if out.reason {
            cmd.push_str(" --reason");
        }
        if let Some(ref stats_every) = out.stats_every {
            write!(cmd, " --stats-every {}", Self::quote_if_needed(stats_every)).ok();
        }
        if out.packet_trace {
            cmd.push_str(" --packet-trace");
        }
        if out.open_only {
            cmd.push_str(" --open");
        }
        if out.iflist {
            cmd.push_str(" --iflist");
        }
        if out.append_output {
            cmd.push_str(" --append-output");
        }
        if let Some(ref resume) = out.resume {
            write!(cmd, " --resume {}", Self::quote_path(resume)).ok();
        }
        if let Some(ref stylesheet) = out.stylesheet {
            write!(cmd, " --stylesheet {}", Self::quote_path(stylesheet)).ok();
        }
        if out.webxml {
            cmd.push_str(" --webxml");
        }
        if out.no_stylesheet {
            cmd.push_str(" --no-stylesheet");
        }
    }

    fn build_misc(cmd: &mut String, misc: &MiscOptions) {
        if misc.ipv6 {
            cmd.push_str(" -6");
        }
        if misc.aggressive {
            cmd.push_str(" -A");
        }
        if let Some(ref datadir) = misc.datadir {
            write!(cmd, " --datadir {}", Self::quote_path(datadir)).ok();
        }
        if misc.send_eth {
            cmd.push_str(" --send-eth");
        }
        if misc.send_ip {
            cmd.push_str(" --send-ip");
        }
        if misc.privileged {
            cmd.push_str(" --privileged");
        }
        if misc.unprivileged {
            cmd.push_str(" --unprivileged");
        }
        if misc.release_memory {
            cmd.push_str(" --release-memory");
        }
        if misc.version {
            cmd.push_str(" -V");
        }
        if misc.help {
            cmd.push_str(" -h");
        }
        if misc.resolve_all {
            cmd.push_str(" -R");
        }
        if misc.no_resolve {
            cmd.push_str(" -n");
        }
        if misc.unique {
            cmd.push_str(" --unique");
        }
        if misc.log_errors {
            cmd.push_str(" --log-errors");
        }
    }

    fn build_target_specification(cmd: &mut String, scan: &NmapScan) {
        if let Some(ref input_file) = scan.input_file {
            write!(cmd, " -iL {}", Self::quote_path(input_file)).ok();
        }
        if let Some(random_targets) = scan.random_targets {
            write!(cmd, " -iR {}", random_targets).ok();
        }
        if !scan.exclude.is_empty() {
            write!(cmd, " --exclude {}", scan.exclude.join(",")).ok();
        }
        if let Some(ref exclude_file) = scan.exclude_file {
            write!(cmd, " --exclude-file {}", Self::quote_path(exclude_file)).ok();
        }

        // Add targets at the end
        for target in &scan.targets {
            write!(cmd, " {}", Self::quote_if_needed(target)).ok();
        }
    }

    // Helper functions
    fn format_port_list(ports: &[u16]) -> String {
        ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn format_protocol_list(protocols: &[u8]) -> String {
        protocols
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn quote_if_needed(s: &str) -> String {
        if s.contains(' ') || s.contains('\t') || s.contains('"') {
            format!("\"{}\"", s.replace('\"', "\\\""))
        } else {
            s.to_string()
        }
    }

    fn quote_path(path: &std::path::Path) -> String {
        let s = path.to_string_lossy();
        Self::quote_if_needed(&s)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::scan::model::TimingTemplate;

    use super::*;

    #[test]
    fn test_basic_scan() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["192.168.1.1".to_string()];
        scan.scan_technique = ScanTechnique::Syn;
        scan.ports.ports = Some("80,443".to_string());

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains("-sS"));
        assert!(cmd.contains("-p 80,443"));
        assert!(cmd.contains("192.168.1.1"));
    }

    #[test]
    fn test_timing_template() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["scanme.nmap.org".to_string()];
        scan.timing.template = Some(TimingTemplate::Aggressive);

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains("-T4"));
        assert!(cmd.contains("scanme.nmap.org"));
    }

    #[test]
    fn test_os_detection() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["192.168.1.1".to_string()];
        scan.os_detection.enabled = true;
        scan.os_detection.guess = true;

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains("-O"));
        assert!(cmd.contains("--osscan-guess"));
    }

    #[test]
    fn test_service_detection() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["example.com".to_string()];
        scan.service_detection.enabled = true;
        scan.service_detection.intensity = Some(9);

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains("-sV"));
        assert!(cmd.contains("--version-intensity 9"));
    }

    #[test]
    fn test_script_scan() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["192.168.1.1".to_string()];
        scan.script_scan.scripts = vec!["vuln".to_string(), "exploit".to_string()];

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains("--script vuln,exploit"));
    }

    #[test]
    fn test_verbose_and_debug() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["192.168.1.1".to_string()];
        scan.output.verbose = 2;
        scan.output.debug = 3;

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains("-vv"));
        assert!(cmd.matches("-d").count() == 3);
    }

    #[test]
    fn test_complex_scan() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["192.168.1.0/24".to_string()];
        scan.scan_technique = ScanTechnique::Syn;
        scan.host_discovery.skip_port_scan = true;
        scan.ports.ports = Some("-".to_string());
        scan.timing.template = Some(TimingTemplate::Aggressive);
        scan.script_scan.scripts = vec!["vuln".to_string()];
        scan.output.xml = Some(PathBuf::from("output.xml"));

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains("-Pn"));
        assert!(cmd.contains("-sS"));
        assert!(cmd.contains("-p -"));
        assert!(cmd.contains("-T4"));
        assert!(cmd.contains("--script vuln"));
        assert!(cmd.contains("-oX output.xml"));
        assert!(cmd.contains("192.168.1.0/24"));
    }

    #[test]
    fn test_quoting() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["192.168.1.1".to_string()];
        scan.evasion.data_string = Some("test data with spaces".to_string());

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains("--data-string \"test data with spaces\""));
    }

    #[test]
    fn test_host_discovery_flags() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["192.168.1.0/24".to_string()];
        scan.host_discovery.list_scan = true;
        scan.host_discovery.ping_scan = true;
        scan.host_discovery.syn_discovery = vec![80, 443];
        scan.host_discovery.ack_discovery = vec![22];
        scan.host_discovery.udp_discovery = vec![53];
        scan.host_discovery.icmp_echo = true;
        scan.host_discovery.dns_servers = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains(" -sL"));
        assert!(cmd.contains(" -sn"));
        assert!(cmd.contains(" -PS80,443"));
        assert!(cmd.contains(" -PA22"));
        assert!(cmd.contains(" -PU53"));
        assert!(cmd.contains(" -PE"));
        assert!(cmd.contains(" 192.168.1.0/24"));
        assert!(cmd.contains(" --dns-servers 8.8.8.8,1.1.1.1"));
    }

    #[test]
    fn test_port_specification_flags() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["localhost".to_string()];
        scan.ports.fast_mode = true;
        scan.ports.consecutive_ports = true;
        scan.ports.top_ports = Some(100);
        scan.ports.exclude_ports = Some("22,80".to_string());

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains(" -F"));
        assert!(cmd.contains(" -r"));
        assert!(cmd.contains(" --top-ports 100"));
        assert!(cmd.contains(" --exclude-ports 22,80"));
        assert!(cmd.contains(" localhost"));
    }

    #[test]
    fn test_evasion_flags() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["10.0.0.1".to_string()];
        scan.evasion.fragment_packets = true;
        scan.evasion.mtu = Some(16);
        scan.evasion.decoys = vec!["decoy1".to_string(), "ME".to_string(), "decoy2".to_string()];
        scan.evasion.spoof_ip = Some("10.0.0.99".parse().unwrap());
        scan.evasion.randomize_hosts = true;
        scan.evasion.badsum = true;

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains(" -f"));
        assert!(cmd.contains(" --mtu 16"));
        assert!(cmd.contains(" -D decoy1,ME,decoy2"));
        assert!(cmd.contains(" -S 10.0.0.99"));
        assert!(cmd.contains(" --randomize-hosts"));
        assert!(cmd.contains(" --badsum"));
        assert!(cmd.contains(" 10.0.0.1"));
    }

    #[test]
    fn test_output_flags() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["scanme.nmap.org".to_string()];
        scan.output.normal = Some(PathBuf::from("output.nmap"));
        scan.output.grepable = Some(PathBuf::from("output.gnmap"));
        scan.output.all_formats = Some("all_output".to_string());
        scan.output.open_only = true;
        scan.output.reason = true;

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains(" -oN output.nmap"));
        assert!(cmd.contains(" -oG output.gnmap"));
        assert!(cmd.contains(" -oA all_output"));
        assert!(cmd.contains(" --open"));
        assert!(cmd.contains(" --reason"));
        assert!(cmd.contains(" scanme.nmap.org"));
    }

    #[test]
    fn test_misc_flags() {
        let mut scan = NmapScan::new();
        scan.targets = vec!["example.com".to_string()];
        scan.misc.ipv6 = true;
        scan.misc.aggressive = true;
        scan.misc.no_resolve = true;

        let cmd = NmapCommandBuilder::build(&scan);
        assert!(cmd.contains(" -6"));
        assert!(cmd.contains(" -A"));
        assert!(cmd.contains(" -n"));
        assert!(cmd.contains(" example.com"));
    }
}
