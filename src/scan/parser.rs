use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use crate::scan::model::{NmapScan, ScanTechnique, TimingTemplate};

/// Error type for parsing failures
#[derive(Debug, Clone)]
pub enum ParseError {
    InvalidFlag(String),
    InvalidValue(String, String),
    MissingValue(String),
    ConflictingFlags(String, String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParseError::InvalidFlag(flag) => write!(f, "Invalid flag: {}", flag),
            ParseError::InvalidValue(flag, val) => {
                write!(f, "Invalid value '{}' for flag {}", val, flag)
            }
            ParseError::MissingValue(flag) => write!(f, "Missing value for flag {}", flag),
            ParseError::ConflictingFlags(f1, f2) => {
                write!(f, "Conflicting flags: {} and {}", f1, f2)
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Parser for nmap command strings
pub struct NmapParser;

impl NmapParser {
    /// Parse an nmap command string into an NmapScan struct
    pub fn parse(command: &str) -> Result<NmapScan, ParseError> {
        let mut scan = NmapScan::new();
        let tokens = Self::tokenize(command);
        let mut iter = tokens.iter().enumerate().peekable();

        while let Some((idx, token)) = iter.next() {
            if token == "nmap" && idx == 0 {
                continue;
            }

            if token.starts_with('-') {
                Self::parse_flag(&mut scan, token, &mut iter)?;
            } else {
                // Target specification
                scan.target_specification.targets.push(token.to_string());
            }
        }

        Ok(scan)
    }

    fn tokenize(command: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut chars = command.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                '"' => in_quotes = !in_quotes,
                ' ' | '\t' | '\n' if !in_quotes => {
                    if !current.is_empty() {
                        tokens.push(current.clone());
                        current.clear();
                    }
                }
                '\\' if in_quotes => {
                    if let Some(&next) = chars.peek() {
                        chars.next();
                        current.push(next);
                    }
                }
                _ => current.push(c),
            }
        }

        if !current.is_empty() {
            tokens.push(current);
        }

        tokens
    }

    fn parse_flag<'a>(
        scan: &mut NmapScan,
        flag: &str,
        iter: &mut std::iter::Peekable<impl Iterator<Item = (usize, &'a String)>>,
    ) -> Result<(), ParseError> {
        match flag {
            // Target specification
            "-iL" => {
                scan.target_specification.input_file =
                    Some(PathBuf::from(Self::get_next_value(iter, flag)?))
            }
            "-iR" => {
                scan.target_specification.random_targets =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--exclude" => {
                scan.target_specification.exclude = Self::get_next_value(iter, flag)?
                    .split(',')
                    .map(String::from)
                    .collect()
            }
            "--exclude-file" => {
                scan.target_specification.exclude_file =
                    Some(PathBuf::from(Self::get_next_value(iter, flag)?))
            }

            // Host discovery
            "-sL" => scan.host_discovery.list_scan = true,
            "-sn" => scan.host_discovery.ping_scan = true,
            "-Pn" => scan.host_discovery.skip_port_scan = true,
            "-PS" => {
                if let Some(val) = Self::peek_next_value(iter) {
                    scan.host_discovery.syn_discovery = Self::parse_port_list(Some(val));
                }
            }
            "-PA" => {
                if let Some(val) = Self::peek_next_value(iter) {
                    scan.host_discovery.ack_discovery = Self::parse_port_list(Some(val));
                }
            }
            "-PU" => {
                if let Some(val) = Self::peek_next_value(iter) {
                    scan.host_discovery.udp_discovery = Self::parse_port_list(Some(val));
                }
            }
            "-PY" => {
                if let Some(val) = Self::peek_next_value(iter) {
                    scan.host_discovery.sctp_discovery = Self::parse_port_list(Some(val));
                }
            }
            "-PE" => scan.host_discovery.icmp_echo = true,
            "-PP" => scan.host_discovery.icmp_timestamp = true,
            "-PM" => scan.host_discovery.icmp_netmask = true,
            "-PO" => {
                if let Some(val) = Self::peek_next_value(iter) {
                    scan.host_discovery.ip_protocol_ping = Self::parse_protocol_list(Some(val));
                }
            }
            "--traceroute" => scan.host_discovery.traceroute = true,
            "--dns-servers" => {
                scan.host_discovery.dns_servers = Self::get_next_value(iter, flag)?
                    .split(',')
                    .map(String::from)
                    .collect()
            }
            "--system-dns" => scan.host_discovery.system_dns = true,

            // Scan techniques
            "-sS" => scan.scan_technique = ScanTechnique::Syn,
            "-sT" => scan.scan_technique = ScanTechnique::Connect,
            "-sA" => scan.scan_technique = ScanTechnique::Ack,
            "-sW" => scan.scan_technique = ScanTechnique::Window,
            "-sM" => scan.scan_technique = ScanTechnique::Maimon,
            "-sU" => scan.scan_technique = ScanTechnique::Udp,
            "-sN" => scan.scan_technique = ScanTechnique::TcpNull,
            "-sF" => scan.scan_technique = ScanTechnique::Fin,
            "-sX" => scan.scan_technique = ScanTechnique::Xmas,
            "-sY" => scan.scan_technique = ScanTechnique::SctpInit,
            "-sZ" => scan.scan_technique = ScanTechnique::SctpCookie,
            "-sO" => scan.scan_technique = ScanTechnique::IpProtocol,
            "--scanflags" => {
                scan.scan_technique =
                    ScanTechnique::Scanflags(Self::get_next_value(iter, flag)?.clone())
            }
            "-sI" => {
                scan.scan_technique = ScanTechnique::Idle(Self::get_next_value(iter, flag)?.clone())
            }
            "-b" => {
                scan.scan_technique = ScanTechnique::Ftp(Self::get_next_value(iter, flag)?.clone())
            }

            // Port specification
            f if f.starts_with("-p") && f.len() > 2 => {
                let rest = &flag[2..];
                scan.ports.ports = Some(rest.to_string());
            }
            "-p" => scan.ports.ports = Some(Self::get_next_value(iter, flag)?.clone()),
            "--exclude-ports" => {
                scan.ports.exclude_ports = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "-F" => scan.ports.fast_mode = true,
            "-r" => scan.ports.consecutive_ports = true,
            "--top-ports" => {
                scan.ports.top_ports =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--port-ratio" => {
                scan.ports.port_ratio =
                    Some(Self::parse_float(Self::get_next_value(iter, flag)?, flag)?)
            }

            // Service/Version detection
            "-sV" => scan.service_detection.enabled = true,
            "--version-intensity" => {
                scan.service_detection.intensity =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--version-light" => scan.service_detection.light = true,
            "--version-all" => scan.service_detection.all = true,
            "--version-trace" => scan.service_detection.trace = true,

            // Script scan
            "-sC" => scan.script_scan.default = true,
            "--script" => {
                scan.script_scan.scripts = Self::get_next_value(iter, flag)?
                    .split(',')
                    .map(String::from)
                    .collect()
            }
            "--script-args" => {
                scan.script_scan.script_args = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "--script-args-file" => {
                scan.script_scan.script_args_file =
                    Some(PathBuf::from(Self::get_next_value(iter, flag)?))
            }
            "--script-trace" => scan.script_scan.script_trace = true,
            "--script-updatedb" => scan.script_scan.script_updatedb = true,
            "--script-help" => {
                scan.script_scan.script_help = Some(Self::get_next_value(iter, flag)?.clone())
            }

            // OS detection
            "-O" => scan.os_detection.enabled = true,
            "--osscan-limit" => scan.os_detection.limit = true,
            "--osscan-guess" => scan.os_detection.guess = true,
            "--max-os-tries" => {
                scan.os_detection.max_retries =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }

            // Timing and performance
            "-T0" => scan.timing.template = Some(TimingTemplate::Paranoid),
            "-T1" => scan.timing.template = Some(TimingTemplate::Sneaky),
            "-T2" => scan.timing.template = Some(TimingTemplate::Polite),
            "-T3" => scan.timing.template = Some(TimingTemplate::Normal),
            "-T4" => scan.timing.template = Some(TimingTemplate::Aggressive),
            "-T5" => scan.timing.template = Some(TimingTemplate::Insane),
            "--min-hostgroup" => {
                scan.timing.min_hostgroup =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--max-hostgroup" => {
                scan.timing.max_hostgroup =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--min-parallelism" => {
                scan.timing.min_parallelism =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--max-parallelism" => {
                scan.timing.max_parallelism =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--min-rtt-timeout" => {
                scan.timing.min_rtt_timeout = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "--max-rtt-timeout" => {
                scan.timing.max_rtt_timeout = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "--initial-rtt-timeout" => {
                scan.timing.initial_rtt_timeout = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "--max-retries" => {
                scan.timing.max_retries =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--host-timeout" => {
                scan.timing.host_timeout = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "--script-timeout" => {
                scan.timing.script_timeout = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "--scan-delay" => {
                scan.timing.scan_delay = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "--max-scan-delay" => {
                scan.timing.max_scan_delay = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "--min-rate" => {
                scan.timing.min_rate =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--max-rate" => {
                scan.timing.max_rate =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--defeat-rst-ratelimit" => scan.timing.defeat_rst_ratelimit = true,
            "--defeat-icmp-ratelimit" => scan.timing.defeat_icmp_ratelimit = true,
            "--nsock-engine" => {
                scan.timing.nsock_engine = Some(Self::get_next_value(iter, flag)?.clone())
            }

            // Firewall/IDS evasion
            "-f" => scan.evasion.fragment_packets = true,
            "--mtu" => {
                scan.evasion.mtu =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "-D" => {
                scan.evasion.decoys = Self::get_next_value(iter, flag)?
                    .split(',')
                    .map(String::from)
                    .collect()
            }
            "-S" => {
                let val = Self::get_next_value(iter, flag)?;
                scan.evasion.spoof_ip = Some(
                    IpAddr::from_str(val)
                        .map_err(|_| ParseError::InvalidValue(flag.to_string(), val.clone()))?,
                );
            }
            "-e" => scan.evasion.interface = Some(Self::get_next_value(iter, flag)?.clone()),
            "-g" | "--source-port" => {
                scan.evasion.source_port =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--data" => scan.evasion.data = Some(Self::get_next_value(iter, flag)?.clone()),
            "--data-string" => {
                scan.evasion.data_string = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "--data-length" => {
                scan.evasion.data_length =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--ip-options" => {
                scan.evasion.ip_options = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "--ttl" => {
                scan.evasion.ttl =
                    Some(Self::parse_number(Self::get_next_value(iter, flag)?, flag)?)
            }
            "--randomize-hosts" => scan.evasion.randomize_hosts = true,
            "--spoof-mac" => {
                scan.evasion.spoof_mac = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "--badsum" => scan.evasion.badsum = true,
            "--adler32" => scan.evasion.adler32 = true,

            // Output
            "-oN" => scan.output.normal = Some(PathBuf::from(Self::get_next_value(iter, flag)?)),
            "-oX" => scan.output.xml = Some(PathBuf::from(Self::get_next_value(iter, flag)?)),
            "-oS" => {
                scan.output.script_kiddie = Some(PathBuf::from(Self::get_next_value(iter, flag)?))
            }
            "-oG" => scan.output.grepable = Some(PathBuf::from(Self::get_next_value(iter, flag)?)),
            "-oA" => scan.output.all_formats = Some(Self::get_next_value(iter, flag)?.clone()),
            "-v" => scan.output.verbose = scan.output.verbose.saturating_add(1),
            "-vv" => scan.output.verbose = scan.output.verbose.saturating_add(2),
            "-d" => scan.output.debug = scan.output.debug.saturating_add(1),
            "-dd" => scan.output.debug = scan.output.debug.saturating_add(2),
            "--reason" => scan.output.reason = true,
            "--stats-every" => {
                scan.output.stats_every = Some(Self::get_next_value(iter, flag)?.clone())
            }
            "--packet-trace" => scan.output.packet_trace = true,
            "--open" => scan.output.open_only = true,
            "--iflist" => scan.output.iflist = true,
            "--append-output" => scan.output.append_output = true,
            "--resume" => {
                scan.output.resume = Some(PathBuf::from(Self::get_next_value(iter, flag)?))
            }
            "--stylesheet" => {
                scan.output.stylesheet = Some(PathBuf::from(Self::get_next_value(iter, flag)?))
            }
            "--webxml" => scan.output.webxml = true,
            "--no-stylesheet" => scan.output.no_stylesheet = true,

            // Miscellaneous
            "-6" => scan.misc.ipv6 = true,
            "-A" => scan.misc.aggressive = true,
            "--datadir" => {
                scan.misc.datadir = Some(PathBuf::from(Self::get_next_value(iter, flag)?))
            }
            "--send-eth" => scan.misc.send_eth = true,
            "--send-ip" => scan.misc.send_ip = true,
            "--privileged" => scan.misc.privileged = true,
            "--unprivileged" => scan.misc.unprivileged = true,
            "--release-memory" => scan.misc.release_memory = true,
            "-V" | "--version" => scan.misc.version = true,
            "-h" | "--help" => scan.misc.help = true,
            "-R" => scan.misc.resolve_all = true,
            "-n" => scan.misc.no_resolve = true,
            "--unique" => scan.misc.unique = true,
            "--log-errors" => scan.misc.log_errors = true,

            _ => return Err(ParseError::InvalidFlag(flag.to_string())),
        }

        Ok(())
    }

    fn get_next_value<'a>(
        iter: &mut impl Iterator<Item = (usize, &'a String)>,
        flag: &str,
    ) -> Result<&'a String, ParseError> {
        iter.next()
            .map(|(_, v)| v)
            .ok_or_else(|| ParseError::MissingValue(flag.to_string()))
    }

    fn peek_next_value<'a>(
        iter: &mut std::iter::Peekable<impl Iterator<Item = (usize, &'a String)>>,
    ) -> Option<&'a str> {
        iter.peek().and_then(|(_, v)| {
            if v.starts_with('-') {
                None
            } else {
                Some(v.as_str())
            }
        })
    }

    fn parse_number<T: FromStr>(s: &str, flag: &str) -> Result<T, ParseError> {
        s.parse()
            .map_err(|_| ParseError::InvalidValue(flag.to_string(), s.to_string()))
    }

    fn parse_float(s: &str, flag: &str) -> Result<f32, ParseError> {
        s.parse()
            .map_err(|_| ParseError::InvalidValue(flag.to_string(), s.to_string()))
    }

    fn parse_port_list(s: Option<&str>) -> Vec<u16> {
        s.map(|s| s.split(',').filter_map(|p| p.parse().ok()).collect())
            .unwrap_or_default()
    }

    fn parse_protocol_list(s: Option<&str>) -> Vec<u8> {
        s.map(|s| s.split(',').filter_map(|p| p.parse().ok()).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::scan::model::ScanTechnique;

    #[test]
    fn test_basic_scan() {
        let result = NmapParser::parse("nmap -sS -p 80,443 192.168.1.1");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.target_specification.targets, vec!["192.168.1.1"]);
        assert!(matches!(scan.scan_technique, ScanTechnique::Syn));
        assert_eq!(scan.ports.ports, Some("80,443".to_string()));
    }

    #[test]
    fn test_timing_template() {
        let result = NmapParser::parse("nmap -T4 scanme.nmap.org");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert!(matches!(
            scan.timing.template,
            Some(TimingTemplate::Aggressive)
        ));
    }

    #[test]
    fn test_os_detection() {
        let result = NmapParser::parse("nmap -O --osscan-guess 192.168.1.1");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert!(scan.os_detection.enabled);
        assert!(scan.os_detection.guess);
    }

    #[test]
    fn test_service_detection() {
        let result = NmapParser::parse("nmap -sV --version-intensity 9 example.com");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert!(scan.service_detection.enabled);
        assert_eq!(scan.service_detection.intensity, Some(9));
    }

    #[test]
    fn test_script_scan() {
        let result = NmapParser::parse("nmap --script vuln,exploit 192.168.1.1");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.script_scan.scripts, vec!["vuln", "exploit"]);
    }

    #[test]
    fn test_host_discovery() {
        let result = NmapParser::parse("nmap -sL -sn -Pn 192.168.1.0/24");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert!(scan.host_discovery.list_scan);
        assert!(scan.host_discovery.ping_scan);
        assert!(scan.host_discovery.skip_port_scan);
        assert_eq!(scan.target_specification.targets, vec!["192.168.1.0/24"]);
    }

    #[test]
    fn test_port_specification() {
        let result = NmapParser::parse("nmap -F -r --top-ports 10 127.0.0.1");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert!(scan.ports.fast_mode);
        assert!(scan.ports.consecutive_ports);
        assert_eq!(scan.ports.top_ports, Some(10));
    }

    #[test]
    fn test_evasion_techniques() {
        let result = NmapParser::parse("nmap -f --mtu 8 -D RND:10 10.0.0.1");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert!(scan.evasion.fragment_packets);
        assert_eq!(scan.evasion.mtu, Some(8));
        assert_eq!(scan.evasion.decoys, vec!["RND:10"]);
    }

    #[test]
    fn test_output_options() {
        let result = NmapParser::parse("nmap -oN normal.txt -v --open scanme.nmap.org");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.output.normal, Some(PathBuf::from("normal.txt")));
        assert_eq!(scan.output.verbose, 1);
        assert!(scan.output.open_only);
    }

    #[test]
    fn test_misc_flags() {
        let result = NmapParser::parse("nmap -6 -A -n example.com");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert!(scan.misc.ipv6);
        assert!(scan.misc.aggressive);
        assert!(scan.misc.no_resolve);
    }

    #[test]
    fn test_invalid_value() {
        let result = NmapParser::parse("nmap -iR not-a-number scanme.nmap.org");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidValue(flag, val) if flag == "-iR" && val == "not-a-number"
        ));
    }

    #[test]
    fn test_combined_scan() {
        let command = "nmap -sS -sV -O -p- -T4 --min-rate 1000 -oA full_scan 192.168.1.1";
        let result = NmapParser::parse(command);
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert!(matches!(scan.scan_technique, ScanTechnique::Syn));
        assert!(scan.service_detection.enabled);
        assert!(scan.os_detection.enabled);
        assert_eq!(scan.ports.ports, Some("-".to_string()));
        assert!(matches!(
            scan.timing.template,
            Some(TimingTemplate::Aggressive)
        ));
        assert_eq!(scan.timing.min_rate, Some(1000));
        assert_eq!(scan.output.all_formats, Some("full_scan".to_string()));
        assert_eq!(scan.target_specification.targets, vec!["192.168.1.1"]);
    }
}
