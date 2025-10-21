use std::path::PathBuf;
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{Display, EnumIter, EnumMessage};

use crate::scan::model::{NmapScan, NsockEngine, SctpScanType, TcpScanType, TimingTemplate};

#[derive(Clone, Copy, Debug, Display, EnumIter, EnumMessage, Eq, Hash, PartialEq)]
pub enum NmapFlag {
    // Target specification
    #[strum(
        to_string = "Targets",
        message = "list of strings",
        detailed_message = "Hostnames, IP addresses, networks, etc"
    )]
    Targets,
    #[strum(
        to_string = "Input file",
        message = "file path",
        detailed_message = "-iL"
    )]
    InputFile,
    #[strum(
        to_string = "Exclude",
        message = "list of strings",
        detailed_message = "--exclude"
    )]
    Exclude,
    #[strum(
        to_string = "Exclude file",
        message = "file path",
        detailed_message = "--exclude-file"
    )]
    ExcludeFile,
    #[strum(
        to_string = "Random targets",
        message = "number",
        detailed_message = "-iR"
    )]
    RandomTargets,
    #[strum(to_string = "Unique", detailed_message = "--unique")]
    Unique,
    #[strum(to_string = "No resolve", detailed_message = "-n")]
    NoResolve,
    #[strum(to_string = "Always resolve", detailed_message = "-R")]
    AlwaysResolve,
    #[strum(to_string = "Resolve all", detailed_message = "--resolve-all")]
    ResolveAll,
    #[strum(to_string = "System DNS", detailed_message = "--system-dns")]
    SystemDns,
    #[strum(
        to_string = "DNS servers",
        message = "list of strings",
        detailed_message = "--dns-servers"
    )]
    DnsServers,

    // Host discovery
    #[strum(to_string = "List scan", detailed_message = "-sL")]
    ListScan,
    #[strum(to_string = "Ping scan", detailed_message = "-sn")]
    PingScan,
    #[strum(to_string = "Skip port scan", detailed_message = "-Pn")]
    SkipPortScan,
    #[strum(
        to_string = "SYN",
        message = "list of numbers",
        detailed_message = "-PS"
    )]
    SynDiscovery,
    #[strum(
        to_string = "ACK",
        message = "list of numbers",
        detailed_message = "-PA"
    )]
    AckDiscovery,
    #[strum(
        to_string = "UDP",
        message = "list of numbers",
        detailed_message = "-PU"
    )]
    UdpDiscovery,
    #[strum(
        to_string = "SCTP",
        message = "list of numbers",
        detailed_message = "-PY"
    )]
    SctpDiscovery,
    #[strum(to_string = "ICMP echo", detailed_message = "-PE")]
    IcmpEcho,
    #[strum(to_string = "ICMP timestamp", detailed_message = "-PP")]
    IcmpTimestamp,
    #[strum(to_string = "ICMP netmask", detailed_message = "-PM")]
    IcmpNetmask,
    #[strum(
        to_string = "IP protocol ping",
        message = "list of numbers",
        detailed_message = "-PO"
    )]
    IpProtocolPing,
    #[strum(
        to_string = "Disable ARP ping",
        detailed_message = "--disable-arp-ping"
    )]
    DisableArpPing,
    #[strum(
        to_string = "Discover ignore RST",
        detailed_message = "--discover-ignore-rst"
    )]
    DiscoverIgnoreRst,
    #[strum(to_string = "Traceroute", detailed_message = "--traceroute")]
    Traceroute,

    // Scan technique
    #[strum(to_string = "TCP scan")]
    TcpScan,
    #[strum(to_string = "UDP scan", detailed_message = "-sU")]
    UdpScan,
    #[strum(to_string = "SCTP scan")]
    SctpScan,

    // Port specification
    #[strum(to_string = "Ports", message = "string", detailed_message = "-p")]
    Ports,
    #[strum(
        to_string = "Exclude ports",
        message = "string",
        detailed_message = "--exclude-ports"
    )]
    ExcludePorts,
    #[strum(to_string = "Fast mode", detailed_message = "-F")]
    FastMode,
    #[strum(to_string = "Consecutive ports", detailed_message = "-r")]
    ConsecutivePorts,
    #[strum(
        to_string = "Top ports",
        message = "number",
        detailed_message = "--top-ports"
    )]
    TopPorts,
    #[strum(
        to_string = "Port ratio",
        message = "decimal number (0-1)",
        detailed_message = "--port-ratio"
    )]
    PortRatio,

    // Service detection
    #[strum(to_string = "Version detection", detailed_message = "-sV")]
    VersionDetection,
    #[strum(to_string = "All ports", detailed_message = "--allports")]
    AllPorts,
    #[strum(
        to_string = "Version intensity",
        message = "number (0-9)",
        detailed_message = "--version-intensity"
    )]
    VersionIntensity,
    #[strum(to_string = "Light", detailed_message = "--version-light")]
    VersionLight,
    #[strum(to_string = "All", detailed_message = "--version-all")]
    VersionAll,
    #[strum(to_string = "Trace", detailed_message = "--version-trace")]
    VersionTrace,

    // OS detection
    #[strum(to_string = "OS detection", detailed_message = "-O")]
    OsDetection,
    #[strum(to_string = "Limit", detailed_message = "--osscan-limit")]
    OsLimit,
    #[strum(to_string = "Guess", detailed_message = "--osscan-guess")]
    OsGuess,
    #[strum(
        to_string = "Max retries",
        message = "number",
        detailed_message = "--max-os-retries"
    )]
    MaxOsRetries,

    // NSE script
    #[strum(to_string = "Default", detailed_message = "-sC")]
    DefaultScript,
    #[strum(
        to_string = "Script",
        message = "list of strings",
        detailed_message = "--script"
    )]
    Script,
    #[strum(
        to_string = "Args",
        message = "string (key/value pairs)",
        detailed_message = "--script-args"
    )]
    ScriptArgs,
    #[strum(
        to_string = "Args file",
        message = "file path",
        detailed_message = "--script-args-file"
    )]
    ScriptArgsFile,
    #[strum(
        to_string = "Help",
        message = "string",
        detailed_message = "--script-help"
    )]
    ScriptHelp,
    #[strum(to_string = "Trace", detailed_message = "--script-trace")]
    ScriptTrace,
    #[strum(to_string = "Update DB", detailed_message = "--script-updatedb")]
    ScriptUpdateDb,

    // Timing
    #[strum(
        to_string = "Min hostgroup",
        message = "number",
        detailed_message = "--min-hostgroup"
    )]
    MinHostgroup,
    #[strum(
        to_string = "Max hostgroup",
        message = "number",
        detailed_message = "--max-hostgroup"
    )]
    MaxHostgroup,
    #[strum(
        to_string = "Min parallelism",
        message = "number",
        detailed_message = "--min-parallelism"
    )]
    MinParallelism,
    #[strum(
        to_string = "Max parallelism",
        message = "number",
        detailed_message = "--max-parallelism"
    )]
    MaxParallelism,
    #[strum(
        to_string = "Min RTT timeoue",
        message = "time",
        detailed_message = "--min-rtt-timeout"
    )]
    MinRttTimeout,
    #[strum(
        to_string = "Max RTT timeout",
        message = "time",
        detailed_message = "--max-rtt-timeout"
    )]
    MaxRttTimeout,
    #[strum(
        to_string = "Initial RTT timeout",
        message = "time",
        detailed_message = "--initial-rtt-timeout"
    )]
    InitialRttTimeout,
    #[strum(
        to_string = "Max retries",
        message = "number",
        detailed_message = "--max-retries"
    )]
    MaxRetries,
    #[strum(
        to_string = "Host timeout",
        message = "time",
        detailed_message = "--host-timeout"
    )]
    HostTimeout,
    #[strum(
        to_string = "Script timeout",
        message = "time",
        detailed_message = "--script-timeout"
    )]
    ScriptTimeout,
    #[strum(
        to_string = "Scan delay",
        message = "time",
        detailed_message = "--scan-delay"
    )]
    ScanDelay,
    #[strum(
        to_string = "Max scan delay",
        message = "time",
        detailed_message = "--max-scan-delay"
    )]
    MaxScanDelay,
    #[strum(
        to_string = "Min rate",
        message = "decimal number",
        detailed_message = "--min-rate"
    )]
    MinRate,
    #[strum(
        to_string = "Max rate",
        message = "decimal number",
        detailed_message = "--max-rate"
    )]
    MaxRate,
    #[strum(
        to_string = "Defeat RST ratelimit",
        detailed_message = "--defeat-rst-ratelimit"
    )]
    DefeatRstRatelimit,
    #[strum(
        to_string = "Defeat ICMP ratelimit",
        detailed_message = "--defeat-icmp-ratelimit"
    )]
    DefeatIcmpRatelimit,
    #[strum(to_string = "Nsock engine", detailed_message = "--nsock-engine")]
    NsockEngine,
    #[strum(to_string = "Timing template", detailed_message = "-T")]
    TimingTemplate,

    // Evasion and spoofing
    #[strum(to_string = "Fragment packets", detailed_message = "-f")]
    FragmentPackets,
    #[strum(to_string = "MTU", message = "number", detailed_message = "--mtu")]
    Mtu,
    #[strum(
        to_string = "Decoys",
        message = "list of strings",
        detailed_message = "--decoys"
    )]
    Decoys,
    #[strum(
        to_string = "Proxies",
        message = "list of strings",
        detailed_message = "--proxies"
    )]
    Proxies,
    #[strum(
        to_string = "Spoof IP",
        message = "string (IP address)",
        detailed_message = "--spoof"
    )]
    SpoofIp,
    #[strum(
        to_string = "Spoof MAC",
        message = "string (MAC address)",
        detailed_message = "--spoof-mac"
    )]
    SpoofMac,
    #[strum(to_string = "Interface", message = "string", detailed_message = "-e")]
    Interface,
    #[strum(
        to_string = "Source port",
        message = "number",
        detailed_message = "--source-port"
    )]
    SourcePort,
    #[strum(
        to_string = "Data",
        message = "hex string",
        detailed_message = "--data"
    )]
    Data,
    #[strum(
        to_string = "Data string",
        message = "string",
        detailed_message = "--data-string"
    )]
    DataString,
    #[strum(
        to_string = "Data length",
        message = "number",
        detailed_message = "--data-length"
    )]
    DataLength,
    #[strum(
        to_string = "IP options",
        message = "string",
        detailed_message = "--ip-options"
    )]
    IpOptions,
    #[strum(
        to_string = "TTL",
        message = "number (0-255)",
        detailed_message = "--ttl"
    )]
    Ttl,
    #[strum(to_string = "Randomize hosts", detailed_message = "--randomize-hosts")]
    RandomizeHosts,
    #[strum(to_string = "Badsum", detailed_message = "--badsum")]
    Badsum,
    #[strum(to_string = "Adler32", detailed_message = "--adler32")]
    Adler32,

    // Output
    #[strum(
        to_string = "Normal output",
        message = "file path",
        detailed_message = "-oN"
    )]
    Normal,
    #[strum(
        to_string = "XML output",
        message = "file path",
        detailed_message = "-oX"
    )]
    Xml,
    #[strum(
        to_string = "Grepable output",
        message = "file path",
        detailed_message = "-oG"
    )]
    Grepable,
    #[strum(
        to_string = "All formats",
        message = "file path",
        detailed_message = "-oA"
    )]
    AllFormats,
    #[strum(
        to_string = "Resume",
        message = "file path",
        detailed_message = "--resume"
    )]
    Resume,
    #[strum(to_string = "Append output", detailed_message = "--append-output")]
    AppendOutput,
    #[strum(
        to_string = "Verbosity",
        message = "number (0-9)",
        detailed_message = "-v"
    )]
    Verbosity,
    #[strum(
        to_string = "Debugging",
        message = "number (0-9)",
        detailed_message = "-d"
    )]
    Debugging,
    #[strum(
        to_string = "Stats every",
        message = "time",
        detailed_message = "--stats-every"
    )]
    StatsEvery,
    #[strum(to_string = "Reason", detailed_message = "--reason")]
    Reason,
    #[strum(to_string = "Packet trace", detailed_message = "--packet-trace")]
    PacketTrace,
    #[strum(to_string = "Open only", detailed_message = "--open")]
    OpenOnly,
    #[strum(to_string = "List interfaces", detailed_message = "--iflist")]
    IfList,
    #[strum(to_string = "Noninteractive", detailed_message = "--noninteractive")]
    Noninteractive,
    #[strum(
        to_string = "Stylesheet",
        message = "file path",
        detailed_message = "--stylesheet"
    )]
    Stylesheet,
    #[strum(to_string = "Web XML", detailed_message = "--webxml")]
    WebXml,
    #[strum(to_string = "No stylesheet", detailed_message = "--no-stylesheet")]
    NoStylesheet,
    #[strum(
        to_string = "ScRipT KIdd|3 oUTpuT",
        message = "file path",
        detailed_message = "-oS"
    )]
    ScriptKiddie,

    // Miscellaneous
    #[strum(to_string = "IPv6", detailed_message = "-6")]
    IpV6,
    #[strum(to_string = "Aggressive", detailed_message = "-A")]
    Aggressive,
    #[strum(to_string = "Release memory", detailed_message = "--release-memory")]
    ReleaseMemory,
    #[strum(
        to_string = "Data directory",
        message = "directory path",
        detailed_message = "--datadir"
    )]
    DataDir,
    #[strum(
        to_string = "Service DB",
        message = "file path",
        detailed_message = "--service-db"
    )]
    ServiceDb,
    #[strum(
        to_string = "Version DB",
        message = "file path",
        detailed_message = "--version-db"
    )]
    VersionDb,
    #[strum(to_string = "Send eth", detailed_message = "--send-eth")]
    SendEth,
    #[strum(to_string = "Send IP", detailed_message = "--send-ip")]
    SendIp,
    #[strum(to_string = "Privileged", detailed_message = "--privileged")]
    Privileged,
    #[strum(to_string = "Unprivileged", detailed_message = "--unprivileged")]
    Unprivileged,
    #[strum(to_string = "Version", detailed_message = "--version")]
    Version,
    #[strum(to_string = "Help", detailed_message = "--help")]
    Help,
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
    NsockEngine(&'a mut Option<NsockEngine>),
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

            // OS detection
            NmapFlag::OsDetection => FlagValue::Bool(&mut scan.os_detection.enabled),
            NmapFlag::OsLimit => FlagValue::Bool(&mut scan.os_detection.limit),
            NmapFlag::OsGuess => FlagValue::Bool(&mut scan.os_detection.guess),
            NmapFlag::MaxOsRetries => FlagValue::Int(&mut scan.os_detection.max_retries),

            // NSE script
            NmapFlag::DefaultScript => FlagValue::Bool(&mut scan.nse_script.default),
            NmapFlag::Script => FlagValue::VecString(&mut scan.nse_script.script),
            NmapFlag::ScriptArgs => FlagValue::String(&mut scan.nse_script.script_args),
            NmapFlag::ScriptArgsFile => FlagValue::Path(&mut scan.nse_script.script_args_file),
            NmapFlag::ScriptHelp => FlagValue::String(&mut scan.nse_script.script_help),
            NmapFlag::ScriptTrace => FlagValue::Bool(&mut scan.nse_script.script_trace),
            NmapFlag::ScriptUpdateDb => FlagValue::Bool(&mut scan.nse_script.script_updatedb),

            // Timing
            NmapFlag::MinHostgroup => FlagValue::Int(&mut scan.timing.min_hostgroup),
            NmapFlag::MaxHostgroup => FlagValue::Int(&mut scan.timing.max_hostgroup),
            NmapFlag::MinParallelism => FlagValue::Int(&mut scan.timing.min_parallelism),
            NmapFlag::MaxParallelism => FlagValue::Int(&mut scan.timing.max_parallelism),
            NmapFlag::MinRttTimeout => FlagValue::String(&mut scan.timing.min_rtt_timeout),
            NmapFlag::MaxRttTimeout => FlagValue::String(&mut scan.timing.max_rtt_timeout),
            NmapFlag::InitialRttTimeout => FlagValue::String(&mut scan.timing.initial_rtt_timeout),
            NmapFlag::MaxRetries => FlagValue::Int(&mut scan.timing.max_retries),
            NmapFlag::HostTimeout => FlagValue::String(&mut scan.timing.host_timeout),
            NmapFlag::ScriptTimeout => FlagValue::String(&mut scan.timing.script_timeout),
            NmapFlag::ScanDelay => FlagValue::String(&mut scan.timing.scan_delay),
            NmapFlag::MaxScanDelay => FlagValue::String(&mut scan.timing.max_scan_delay),
            NmapFlag::MinRate => FlagValue::Float(&mut scan.timing.min_rate),
            NmapFlag::MaxRate => FlagValue::Float(&mut scan.timing.max_rate),
            NmapFlag::DefeatRstRatelimit => FlagValue::Bool(&mut scan.timing.defeat_rst_ratelimit),
            NmapFlag::DefeatIcmpRatelimit => {
                FlagValue::Bool(&mut scan.timing.defeat_icmp_ratelimit)
            }
            NmapFlag::NsockEngine => FlagValue::NsockEngine(&mut scan.timing.nsock_engine),
            NmapFlag::TimingTemplate => FlagValue::TimingTemplate(&mut scan.timing.template),

            // Evasion and spoof
            NmapFlag::FragmentPackets => FlagValue::Bool(&mut scan.evasion.fragment_packets),
            NmapFlag::Mtu => FlagValue::Int(&mut scan.evasion.mtu),
            NmapFlag::Decoys => FlagValue::VecString(&mut scan.evasion.decoys),
            NmapFlag::Proxies => FlagValue::VecString(&mut scan.evasion.proxies),
            NmapFlag::SpoofIp => FlagValue::String(&mut scan.evasion.spoof_ip),
            NmapFlag::SpoofMac => FlagValue::String(&mut scan.evasion.spoof_mac),
            NmapFlag::Interface => FlagValue::String(&mut scan.evasion.interface),
            NmapFlag::SourcePort => FlagValue::Int(&mut scan.evasion.source_port),
            NmapFlag::Data => FlagValue::String(&mut scan.evasion.data),
            NmapFlag::DataString => FlagValue::String(&mut scan.evasion.data_string),
            NmapFlag::DataLength => FlagValue::Int(&mut scan.evasion.data_length),
            NmapFlag::IpOptions => FlagValue::String(&mut scan.evasion.ip_options),
            NmapFlag::Ttl => FlagValue::Int(&mut scan.evasion.ttl),
            NmapFlag::RandomizeHosts => FlagValue::Bool(&mut scan.evasion.randomize_hosts),
            NmapFlag::Badsum => FlagValue::Bool(&mut scan.evasion.badsum),
            NmapFlag::Adler32 => FlagValue::Bool(&mut scan.evasion.adler32),

            // Output
            NmapFlag::Normal => FlagValue::Path(&mut scan.output.normal),
            NmapFlag::Xml => FlagValue::Path(&mut scan.output.xml),
            NmapFlag::Grepable => FlagValue::Path(&mut scan.output.grepable),
            NmapFlag::AllFormats => FlagValue::Path(&mut scan.output.all_formats),
            NmapFlag::Resume => FlagValue::Path(&mut scan.output.resume),
            NmapFlag::AppendOutput => FlagValue::Bool(&mut scan.output.append_output),
            NmapFlag::Verbosity => FlagValue::Int(&mut scan.output.verbosity),
            NmapFlag::Debugging => FlagValue::Int(&mut scan.output.debugging),
            NmapFlag::StatsEvery => FlagValue::String(&mut scan.output.stats_every),
            NmapFlag::Reason => FlagValue::Bool(&mut scan.output.reason),
            NmapFlag::PacketTrace => FlagValue::Bool(&mut scan.output.packet_trace),
            NmapFlag::OpenOnly => FlagValue::Bool(&mut scan.output.open_only),
            NmapFlag::IfList => FlagValue::Bool(&mut scan.output.iflist),
            NmapFlag::Noninteractive => FlagValue::Bool(&mut scan.output.noninteractive),
            NmapFlag::Stylesheet => FlagValue::Path(&mut scan.output.stylesheet),
            NmapFlag::WebXml => FlagValue::Bool(&mut scan.output.webxml),
            NmapFlag::NoStylesheet => FlagValue::Bool(&mut scan.output.no_stylesheet),
            NmapFlag::ScriptKiddie => FlagValue::Path(&mut scan.output.script_kiddie),

            // Miscellaneous
            NmapFlag::IpV6 => FlagValue::Bool(&mut scan.misc.ipv6),
            NmapFlag::Aggressive => FlagValue::Bool(&mut scan.misc.aggressive),
            NmapFlag::ReleaseMemory => FlagValue::Bool(&mut scan.misc.release_memory),
            NmapFlag::DataDir => FlagValue::Path(&mut scan.misc.datadir),
            NmapFlag::ServiceDb => FlagValue::Path(&mut scan.misc.servicedb),
            NmapFlag::VersionDb => FlagValue::Path(&mut scan.misc.versiondb),
            NmapFlag::SendEth => FlagValue::Bool(&mut scan.misc.send_eth),
            NmapFlag::SendIp => FlagValue::Bool(&mut scan.misc.send_ip),
            NmapFlag::Privileged => FlagValue::Bool(&mut scan.misc.privileged),
            NmapFlag::Unprivileged => FlagValue::Bool(&mut scan.misc.unprivileged),
            NmapFlag::Version => FlagValue::Bool(&mut scan.misc.version),
            NmapFlag::Help => FlagValue::Bool(&mut scan.misc.help),
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
            NmapFlag::TcpScan => Some(TcpScanType::COUNT),
            NmapFlag::SctpScan => Some(SctpScanType::COUNT),
            NmapFlag::NsockEngine => Some(NsockEngine::COUNT),
            NmapFlag::TimingTemplate => Some(TimingTemplate::COUNT),
            _ => None,
        }
    }
}
