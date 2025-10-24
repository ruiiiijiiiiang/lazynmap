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
        detailed_message = "Lists hostnames, IP addresses, networks, etc as targets"
    )]
    Targets,
    #[strum(
        to_string = "Input file",
        message = "file path",
        detailed_message = "-iL: Reads target specifications from file. Each entry separated by spaces, tabs, or newlines. Supports comments with #. Useful for large scans."
    )]
    InputFile,
    #[strum(
        to_string = "Exclude",
        message = "list of strings",
        detailed_message = "--exclude: Comma-separated list of targets to skip. Uses normal nmap syntax. Prevents scanning critical servers or unauthorized systems."
    )]
    Exclude,
    #[strum(
        to_string = "Exclude file",
        message = "file path",
        detailed_message = "--exclude-file: Like --exclude but reads from newline/space/tab delimited file. Supports comments. Useful for large exclusion lists."
    )]
    ExcludeFile,
    #[strum(
        to_string = "Random targets",
        message = "number",
        detailed_message = "-iR: Generates specified number of random IPs to scan. Use 0 for never-ending scan. Automatically skips private/multicast ranges. For research surveys."
    )]
    RandomTargets,
    #[strum(
        to_string = "Unique",
        detailed_message = "--unique: Scans all resolved IP addresses for a hostname. Default only scans first address. Useful when hosts have multiple IPs."
    )]
    Unique,
    #[strum(
        to_string = "No resolve",
        detailed_message = "-n: Skips reverse DNS lookups. Significantly speeds up scans. Uses IP addresses only in output and processing."
    )]
    NoResolve,
    #[strum(
        to_string = "Always resolve",
        detailed_message = "-R: Performs reverse DNS even for offline hosts. Slower but provides hostnames for all targets in scan range."
    )]
    AlwaysResolve,
    #[strum(
        to_string = "Resolve all",
        detailed_message = "--resolve-all: If a hostname target resolves to more than one address, scan all of them"
    )]
    ResolveAll,
    #[strum(
        to_string = "System DNS",
        detailed_message = "--system-dns: Uses operating system's DNS configuration instead of nmap's parallel resolver. Slower but respects local settings."
    )]
    SystemDns,
    #[strum(
        to_string = "DNS servers",
        message = "list of strings",
        detailed_message = "--dns-servers: Specify alternative DNS resolvers for lookups. Useful when default DNS unavailable or for stealth purposes."
    )]
    DnsServers,

    // Host discovery
    #[strum(
        to_string = "List scan",
        detailed_message = "-sL: Simply lists target IPs and performs reverse DNS. No actual scanning or packets sent. Useful for verifying target ranges."
    )]
    ListScan,
    #[strum(
        to_string = "Ping scan",
        detailed_message = "-sn: Host discovery only without port scanning. Determines which hosts are online. Formerly called -sP in older nmap versions."
    )]
    PingScan,
    #[strum(
        to_string = "Skip port scan",
        detailed_message = "-Pn: Treats all hosts as online. Useful when firewalls block ping probes. Slower but ensures no hosts missed due to filtering."
    )]
    SkipPortScan,
    #[strum(
        to_string = "SYN",
        message = "list of numbers",
        detailed_message = "-PS: Discovers hosts using SYN packets to specified ports. More effective than ICMP when firewalls block traditional pings."
    )]
    SynDiscovery,
    #[strum(
        to_string = "ACK",
        message = "list of numbers",
        detailed_message = "-PA: Uses ACK packets for host discovery. Can bypass firewalls that filter SYN packets. Effective alternative discovery method."
    )]
    AckDiscovery,
    #[strum(
        to_string = "UDP",
        message = "list of numbers",
        detailed_message = "-PU: Sends UDP packets for host discovery. Useful when TCP and ICMP are filtered. Targets high-numbered or specified UDP ports."
    )]
    UdpDiscovery,
    #[strum(
        to_string = "SCTP",
        message = "list of numbers",
        detailed_message = "-PY: Uses SCTP INIT packets for discovery. Alternative when TCP/UDP filtered. Effective for telecommunications infrastructure."
    )]
    SctpDiscovery,
    #[strum(
        to_string = "ICMP echo",
        detailed_message = "-PE: Standard ping request (echo). Often blocked by firewalls but universally understood. Traditional host discovery method."
    )]
    IcmpEcho,
    #[strum(
        to_string = "ICMP timestamp",
        detailed_message = "-PP: Uses ICMP timestamp request. Alternative when echo blocked. Some systems respond to timestamps but not echo."
    )]
    IcmpTimestamp,
    #[strum(
        to_string = "ICMP netmask",
        detailed_message = "-PM: Sends ICMP address mask request. Less common discovery method. Occasionally works when other ICMP types filtered."
    )]
    IcmpNetmask,
    #[strum(
        to_string = "IP ping",
        message = "list of numbers",
        detailed_message = "-PO: Tests multiple IP protocols for discovery. Sends packets with different protocol numbers. Comprehensive discovery technique."
    )]
    IpProtocolPing,
    #[strum(
        to_string = "Disable ARP ping",
        detailed_message = "--disable-arp-ping: Prevents automatic ARP (IPv4) or Neighbor Discovery (IPv6) on local networks. Useful on proxy ARP networks. Default is faster."
    )]
    DisableArpPing,
    #[strum(
        to_string = "Discover ignore RST",
        detailed_message = "--discover-ignore-rst: Prevents treating RST packets as proof host is up. Useful when firewalls spoof RST responses. May need extra discovery options."
    )]
    DiscoverIgnoreRst,
    #[strum(
        to_string = "Traceroute",
        detailed_message = "--traceroute: Performs traceroute post-scan using scan results to determine best port/protocol. Shows network path with hop RTTs and addresses."
    )]
    Traceroute,

    // Scan technique
    #[strum(to_string = "TCP scan", detailed_message = "")]
    TcpScanType,
    #[strum(
        to_string = "UDP scan",
        detailed_message = "-sU: Checks UDP ports for services like DNS, SNMP, DHCP. Slower than TCP but essential for complete network mapping. Requires root."
    )]
    UdpScan,
    #[strum(to_string = "SCTP scan", detailed_message = "")]
    SctpScanType,

    // Port specification
    #[strum(
        to_string = "Ports",
        message = "string",
        detailed_message = "-p: Specifies which ports to scan (e.g., -p 22,80,443 or -p 1-1000). Can target specific services or comprehensive ranges."
    )]
    Ports,
    #[strum(
        to_string = "Exclude ports",
        message = "string",
        detailed_message = "--exclude-ports: Specifies ports to skip in all scan types including discovery. Uses same syntax as -p. Prevents scanning known safe ports."
    )]
    ExcludePorts,
    #[strum(
        to_string = "Fast mode",
        detailed_message = "-F: Scans only top 100 most common ports. Much faster than default 1000. Good for quick network overview or time-limited scans."
    )]
    FastMode,
    #[strum(
        to_string = "Consecutive ports",
        detailed_message = "-r: Scans ports in numerical order instead of random. Easier to follow progress but potentially more detectable by IDS systems."
    )]
    ConsecutivePorts,
    #[strum(
        to_string = "Top ports",
        message = "number",
        detailed_message = "--top-ports: Scans specified number of most popular ports (e.g., --top-ports 500). Based on nmap's frequency database."
    )]
    TopPorts,
    #[strum(
        to_string = "Port ratio",
        message = "decimal number (0-1)",
        detailed_message = "--port-ratio: Scans ports with ratio frequency or higher (0.0 to 1.0). More flexible than --top-ports for custom coverage."
    )]
    PortRatio,

    // Service detection
    #[strum(
        to_string = "Version detection",
        detailed_message = "-sV: Probes open ports to determine service and version info. Essential for vulnerability assessment. Increases scan time significantly."
    )]
    VersionDetection,
    #[strum(
        to_string = "All ports",
        detailed_message = "--allports: Includes TCP port 9100 in version scanning. By default skipped because printers print probe packets. Overrides nmap-service-probes Exclude."
    )]
    AllPorts,
    #[strum(
        to_string = "Version intensity",
        message = "number (0-9)",
        detailed_message = "--version-intensity: Sets thoroughness level (0-9). Higher numbers try more probes. Default is 7. Trade-off between speed and accuracy."
    )]
    VersionIntensity,
    #[strum(
        to_string = "Light",
        detailed_message = "--version-light: Sets intensity to 2. Faster but less comprehensive version detection. Misses less common services and versions."
    )]
    VersionLight,
    #[strum(
        to_string = "All",
        detailed_message = "--version-all: Sets intensity to 9. Most thorough version detection possible. Very slow but maximum accuracy for all services."
    )]
    VersionAll,
    #[strum(
        to_string = "Trace",
        detailed_message = "--version-trace: Shows detailed probe activity. Useful for troubleshooting detection issues or understanding service responses."
    )]
    VersionTrace,

    // OS detection
    #[strum(
        to_string = "OS detection",
        detailed_message = "-O: Fingerprints operating system based on TCP/IP stack behavior. Requires root and at least one open and closed port on target."
    )]
    OsDetection,
    #[strum(
        to_string = "Limit",
        detailed_message = "--osscan-limit: Only attempts OS detection on promising targets with open and closed ports. Speeds up scans of multiple hosts."
    )]
    OsLimit,
    #[strum(
        to_string = "Guess",
        detailed_message = "--osscan-guess: Forces OS match guesses even when detection not ideal. Provides best-guess results for difficult fingerprints."
    )]
    OsGuess,
    #[strum(
        to_string = "Max retries",
        message = "number",
        detailed_message = "--max-os-retries: Limits number of detection attempts per host. Default is 5. Lower values speed up scans of uncooperative hosts."
    )]
    MaxOsRetries,

    // NSE script
    #[strum(
        to_string = "Default",
        detailed_message = "-sC: Runs safe, useful NSE scripts. Equivalent to --script=default. Good balance of information and safety for most scans."
    )]
    DefaultScript,
    #[strum(
        to_string = "Script",
        message = "list of strings",
        detailed_message = "--script: Specifies which NSE scripts to run. Can use names, categories, or wildcards. Powerful for targeted information gathering."
    )]
    Script,
    #[strum(
        to_string = "Args",
        message = "string",
        detailed_message = "--script-args: Passes parameters to NSE scripts. Format: scriptname.arg=value. Customizes script behavior and targeting options."
    )]
    ScriptArgs,
    #[strum(
        to_string = "Args file",
        message = "file path",
        detailed_message = "--script-args-file: Loads script arguments from file. One argument per line. Useful for complex or lengthy argument lists."
    )]
    ScriptArgsFile,
    #[strum(
        to_string = "Help",
        message = "string",
        detailed_message = "--script-help: Displays documentation for scripts. Shows usage, arguments, and output. Essential for understanding available script options."
    )]
    ScriptHelp,
    #[strum(
        to_string = "Trace",
        detailed_message = "--script-trace: Shows detailed script execution and output. Useful for debugging script behavior. Displays all network activity from scripts."
    )]
    ScriptTrace,
    #[strum(
        to_string = "Update DB",
        detailed_message = "--script-updatedb: Refreshes NSE script database. Run after adding new scripts. Updates categories and dependencies information."
    )]
    ScriptUpdateDb,

    // Timing
    #[strum(
        to_string = "Min hostgroup",
        message = "number",
        detailed_message = "--min-hostgroup: Sets minimum hosts scanned in parallel. Higher values increase speed but use more resources and bandwidth."
    )]
    MinHostgroup,
    #[strum(
        to_string = "Max hostgroup",
        message = "number",
        detailed_message = "--max-hostgroup: Limits simultaneous host scanning. Lower values reduce network impact. Controls memory and bandwidth usage."
    )]
    MaxHostgroup,
    #[strum(
        to_string = "Min parallelism",
        message = "number",
        detailed_message = "--min-parallelism: Sets minimum simultaneous probes. Ensures minimum concurrency level. Speeds up scans of slow networks."
    )]
    MinParallelism,
    #[strum(
        to_string = "Max parallelism",
        message = "number",
        detailed_message = "--max-parallelism: Limits concurrent probes per host. Prevents overwhelming target or network. Controls resource consumption."
    )]
    MaxParallelism,
    #[strum(
        to_string = "Min RTT timeoue",
        message = "time",
        detailed_message = "--min-rtt-timeout: Sets minimum round-trip time to wait. Lower values speed up scans but may miss responses on slow networks."
    )]
    MinRttTimeout,
    #[strum(
        to_string = "Max RTT timeout",
        message = "time",
        detailed_message = "--max-rtt-timeout: Sets maximum round-trip wait time. Higher values accommodate slow networks but increase total scan duration."
    )]
    MaxRttTimeout,
    #[strum(
        to_string = "Initial RTT timeout",
        message = "time",
        detailed_message = "--initial-rtt-timeout: Starting timeout before adjustment. Nmap adapts based on responses. Affects early scan performance."
    )]
    InitialRttTimeout,
    #[strum(
        to_string = "Max retries",
        message = "number",
        detailed_message = "--max-retries: Maximum probe retry attempts. Lower values speed scans but may miss ports. Higher ensures thoroughness."
    )]
    MaxRetries,
    #[strum(
        to_string = "Host timeout",
        message = "time",
        detailed_message = "--host-timeout: Abandons slow hosts after specified time. Prevents single hosts from delaying entire scan. Useful for large ranges."
    )]
    HostTimeout,
    #[strum(
        to_string = "Script timeout",
        message = "time",
        detailed_message = "--script-timeout: Sets maximum execution time for script instances. Scripts exceeding limit are terminated without output."
    )]
    ScriptTimeout,
    #[strum(
        to_string = "Scan delay",
        message = "time",
        detailed_message = "--scan-delay: Minimum wait between probes. Useful for rate-limiting or evading detection. Slows scan but reduces network impact."
    )]
    ScanDelay,
    #[strum(
        to_string = "Max scan delay",
        message = "time",
        detailed_message = "--max-scan-delay: Caps automatic delay adjustments. Prevents scan from becoming too slow. Balances stealth with reasonable speed."
    )]
    MaxScanDelay,
    #[strum(
        to_string = "Min rate",
        message = "decimal number",
        detailed_message = "--min-rate: Guarantees minimum packets per second. Ensures scan doesn't slow too much. Overrides conservative timing estimates."
    )]
    MinRate,
    #[strum(
        to_string = "Max rate",
        message = "decimal number",
        detailed_message = "--max-rate: Limits packets per second sent. Prevents network flooding. Useful for bandwidth control or stealth requirements."
    )]
    MaxRate,
    #[strum(
        to_string = "Defeat RST ratelimit",
        detailed_message = "--defeat-rst-ratelimit: Speeds scans by not waiting for rate-limited RST packets. Trades accuracy for speed. Ports may show filtered instead of closed."
    )]
    DefeatRstRatelimit,
    #[strum(
        to_string = "Defeat ICMP ratelimit",
        detailed_message = "--defeat-icmp-ratelimit: Speeds UDP scans by not waiting for rate-limited ICMP errors. Labels non-responsive UDP ports as closed|filtered. Greater inaccuracy risk."
    )]
    DefeatIcmpRatelimit,
    #[strum(to_string = "Nsock engine", detailed_message = "--nsock-engine")]
    NsockEngine,
    #[strum(to_string = "Timing template", detailed_message = "-T")]
    TimingTemplate,

    // Evasion and spoofing
    #[strum(
        to_string = "Fragment packets",
        detailed_message = "-f: Splits TCP header across multiple packets. Evades packet filters inspecting headers. Makes detection and filtering harder."
    )]
    FragmentPackets,
    #[strum(
        to_string = "MTU",
        message = "number",
        detailed_message = "--mtu: Sets maximum transmission unit for fragmentation. Must be multiple of 8. Gives control over fragment sizes for evasion."
    )]
    Mtu,
    #[strum(
        to_string = "Decoys",
        message = "list of strings",
        detailed_message = "--decoys: Mixes real scans with spoofed sources. Makes identifying actual scanner difficult. Generates many false positives for defenders."
    )]
    Decoys,
    #[strum(
        to_string = "Proxies",
        message = "list of strings",
        detailed_message = "--proxies: Routes connections through HTTP/SOCKS4 proxy chains (comma-separated URLs). Only affects NSE and version scan. No SSL or proxy-side DNS yet."
    )]
    Proxies,
    #[strum(
        to_string = "Spoof IP",
        message = "string (IP address)",
        detailed_message = "-S: Uses fake source IP address. Hides true origin but responses go to spoofed address. Requires raw packet access and root."
    )]
    SpoofIp,
    #[strum(
        to_string = "Spoof MAC",
        message = "string (MAC address)",
        detailed_message = "--spoof-mac: Fakes hardware address. Useful on local networks. Can specify vendor or complete address. Evades MAC filtering."
    )]
    SpoofMac,
    #[strum(
        to_string = "Interface",
        message = "string",
        detailed_message = "-e: Chooses specific network interface. Useful for multi-homed systems. Controls which adapter sends packets for routing."
    )]
    Interface,
    #[strum(
        to_string = "Source port",
        message = "number",
        detailed_message = "--source-port: Specifies source port number. Some firewalls trust certain ports (53, 20). Can bypass poorly configured packet filters."
    )]
    SourcePort,
    #[strum(
        to_string = "Data",
        message = "hex string",
        detailed_message = "--data: Adds custom hexadecimal data to packets. Can trigger specific firewall rules or evade detection based on packet content."
    )]
    Data,
    #[strum(
        to_string = "Data string",
        message = "string",
        detailed_message = "--data-string: Adds ASCII string to packets. Easier than hex for text payloads. Useful for testing content-based filtering."
    )]
    DataString,
    #[strum(
        to_string = "Data length",
        message = "number",
        detailed_message = "--data-length: Pads packets to specified length with random data. Evades detection based on packet size signatures."
    )]
    DataLength,
    #[strum(
        to_string = "IP options",
        message = "string",
        detailed_message = "--ip-options: Adds custom IP header options. Can specify loose/strict source routing or record route. Advanced evasion technique."
    )]
    IpOptions,
    #[strum(
        to_string = "TTL",
        message = "number (0-255)",
        detailed_message = "--ttl: Customizes time-to-live field. Can help evade detection or test firewall TTL filtering. Normal values range 1-255."
    )]
    Ttl,
    #[strum(
        to_string = "Randomize hosts",
        detailed_message = "--randomize-hosts: Shuffles target order in 16384 IP blocks. Makes scans less conspicuous. Harder to detect pattern. Useful against IDS that track sequential scans."
    )]
    RandomizeHosts,
    #[strum(
        to_string = "Badsum",
        detailed_message = "--badsum: Sends packets with wrong checksums. Tests firewall/IDS packet validation. Legitimate stacks drop these packets immediately."
    )]
    Badsum,
    #[strum(
        to_string = "Adler32",
        detailed_message = "--adler32: Uses old Adler32 algorithm instead of CRC-32C for SCTP checksums. For eliciting responses from legacy SCTP implementations."
    )]
    Adler32,

    // Output
    #[strum(
        to_string = "Normal output",
        message = "file path",
        detailed_message = "-oN: Saves human-readable output to file. Interactive format suitable for reading. Includes all standard scan information and results."
    )]
    Normal,
    #[strum(
        to_string = "Grepable output",
        message = "file path",
        detailed_message = "-oG: Line-based format easy to grep and parse. Each host on one line. Useful for quick command-line processing and scripts."
    )]
    Grepable,
    #[strum(
        to_string = "All formats",
        message = "file path",
        detailed_message = "-oA: Saves output in all three main formats (Normal, XML, Grepable). Uses base filename with different extensions for each."
    )]
    AllFormats,
    #[strum(
        to_string = "Resume",
        message = "file path",
        detailed_message = "--resume: Continues interrupted scan from saved file. Recovers progress after crash or cancellation. Saves time on large scans."
    )]
    Resume,
    #[strum(
        to_string = "Append output",
        detailed_message = "--append-output: Adds to existing files instead of overwriting. Useful for incremental scans. Preserves previous scan results in same file."
    )]
    AppendOutput,
    #[strum(
        to_string = "ScRipT KIdd|3",
        message = "file path",
        detailed_message = "-oS: Saves in l33t speak format. Humorous output replacing letters with numbers. Not commonly used for serious work."
    )]
    ScriptKiddie,
    #[strum(
        to_string = "Verbosity",
        message = "number (0-9)",
        detailed_message = "-v: Increases output detail during scan. Shows real-time progress and discoveries."
    )]
    Verbosity,
    #[strum(
        to_string = "Debugging",
        message = "number (0-9)",
        detailed_message = "-d: Shows detailed internal operations. Useful for troubleshooting scan issues or understanding behavior."
    )]
    Debugging,
    #[strum(
        to_string = "Stats every",
        message = "time",
        detailed_message = "--stats-every: Prints scan statistics at specified intervals. Takes time value (e.g., 10s, 5m). Useful for monitoring progress of long scans."
    )]
    StatsEvery,
    #[strum(
        to_string = "Noninteractive",
        detailed_message = "--noninteractive: Prevents interactive keypresses from affecting scan. Useful for automated/scripted scans. Blocks status updates via keyboard."
    )]
    Noninteractive,
    #[strum(
        to_string = "Reason",
        detailed_message = "--reason: Explains why port is in particular state. Shows what response caused determination. Helpful for understanding scan results."
    )]
    Reason,
    #[strum(
        to_string = "Packet trace",
        detailed_message = "--packet-trace: Shows every packet sent and received. Extremely verbose. Essential for debugging network issues or understanding behavior."
    )]
    PacketTrace,
    #[strum(
        to_string = "Open only",
        detailed_message = "--open: Displays only open ports in output. Hides closed and filtered. Makes results cleaner when scanning many ports."
    )]
    OpenOnly,
    #[strum(
        to_string = "List interfaces",
        detailed_message = "--iflist: Shows available network interfaces and routes. Useful for multi-homed systems. Helps choose correct interface for scanning."
    )]
    IfList,
    #[strum(
        to_string = "XML output",
        message = "file path",
        detailed_message = "-oX: Saves results in XML format. Machine-parseable for automated processing. Essential for integration with other security tools."
    )]
    Xml,
    #[strum(
        to_string = "Stylesheet",
        message = "file path",
        detailed_message = "--stylesheet: Specifies custom XSL for XML output transformation. Controls HTML rendering of results. Enables custom report formatting."
    )]
    Stylesheet,
    #[strum(
        to_string = "Web XML",
        detailed_message = "--webxml: Uses official stylesheet from nmap.org. Requires internet access. Creates standard HTML reports from XML output."
    )]
    WebXml,
    #[strum(
        to_string = "No stylesheet",
        detailed_message = "--no-stylesheet: Outputs plain XML without stylesheet reference. Useful for custom processing. Reduces file size and external dependencies."
    )]
    NoStylesheet,

    // Miscellaneous
    #[strum(
        to_string = "IPv6",
        detailed_message = "-6: Enables IPv6 scanning mode. Requires IPv6 connectivity. Address format: [IPv6]:port or IPv6 only. Currently less mature than IPv4."
    )]
    IpV6,
    #[strum(
        to_string = "Aggressive",
        detailed_message = "-A: Enables OS detection, version detection, script scanning, and traceroute. Comprehensive but noisy. Equivalent to -O -sV -sC --traceroute."
    )]
    Aggressive,
    #[strum(
        to_string = "Release memory",
        detailed_message = "--release-memory: Frees memory before exit. Useful for debugging memory leaks. Slows down exit but cleans up resources completely."
    )]
    ReleaseMemory,
    #[strum(
        to_string = "Data directory",
        message = "directory path",
        detailed_message = "--datadir: Specifies custom location for nmap data files (scripts, fingerprints). Useful for portable or custom installations."
    )]
    DataDir,
    #[strum(
        to_string = "Service DB",
        message = "file path",
        detailed_message = "--service-db: Specifies alternative nmap-services file location. Changes port-to-service mappings. Useful for custom environments or testing."
    )]
    ServiceDb,
    #[strum(
        to_string = "Version DB",
        message = "file path",
        detailed_message = "--version-db: Specifies alternative nmap-service-probes file location. Changes version detection probes and matches. For custom service detection needs."
    )]
    VersionDb,
    #[strum(
        to_string = "Send eth",
        detailed_message = "--send-eth: : Sends packets at raw ethernet layer. Bypasses IP layer. Gives more control but requires more privileges and expertise."
    )]
    SendEth,
    #[strum(
        to_string = "Send IP",
        detailed_message = "--send-ip: Uses raw IP sockets instead of ethernet. Default on most systems. Less control than ethernet but more portable."
    )]
    SendIp,
    #[strum(
        to_string = "Privileged",
        detailed_message = "--privileged: Assumes user has raw socket privileges. Skips permission checks. Useful in special environments where checks fail incorrectly."
    )]
    Privileged,
    #[strum(
        to_string = "Unprivileged",
        detailed_message = "--unprivileged: Forces connect() scan even if raw sockets available. Useful for testing or when stealth not required from privileged account."
    )]
    Unprivileged,
    #[strum(
        to_string = "Version",
        detailed_message = "--version: Shows nmap version number, platform, compilation details, and available features. Same as -V flag. Useful for bug reports."
    )]
    Version,
    #[strum(
        to_string = "Help",
        detailed_message = "--help: Shows condensed usage information and common options. Same as -h flag. Quick reference for command syntax. See man page for full details."
    )]
    Help,
}

impl NmapFlag {
    pub fn get_flag_value<'a>(&self, scan: &'a mut NmapScan) -> FlagValue<'a> {
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
            NmapFlag::TcpScanType => FlagValue::TcpScanType(&mut scan.scan_technique.tcp),
            NmapFlag::UdpScan => FlagValue::Bool(&mut scan.scan_technique.udp),
            NmapFlag::SctpScanType => FlagValue::SctpScanType(&mut scan.scan_technique.sctp),

            // Port specification
            NmapFlag::Ports => FlagValue::String(&mut scan.port_specification.ports),
            NmapFlag::ExcludePorts => FlagValue::String(&mut scan.port_specification.exclude_ports),
            NmapFlag::FastMode => FlagValue::Bool(&mut scan.port_specification.fast_mode),
            NmapFlag::ConsecutivePorts => {
                FlagValue::Bool(&mut scan.port_specification.consecutive_ports)
            }
            NmapFlag::TopPorts => FlagValue::Int(&mut scan.port_specification.top_ports),
            NmapFlag::PortRatio => FlagValue::Float(&mut scan.port_specification.port_ratio),

            // Service detection
            NmapFlag::VersionDetection => FlagValue::Bool(&mut scan.service_detection.enabled),
            NmapFlag::AllPorts => FlagValue::Bool(&mut scan.service_detection.allports),
            NmapFlag::VersionIntensity => FlagValue::Int(&mut scan.service_detection.intensity),
            NmapFlag::VersionLight => FlagValue::Bool(&mut scan.service_detection.light),
            NmapFlag::VersionAll => FlagValue::Bool(&mut scan.service_detection.all),
            NmapFlag::VersionTrace => FlagValue::Bool(&mut scan.service_detection.trace),

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
            NmapFlag::Grepable => FlagValue::Path(&mut scan.output.grepable),
            NmapFlag::AllFormats => FlagValue::Path(&mut scan.output.all_formats),
            NmapFlag::Resume => FlagValue::Path(&mut scan.output.resume),
            NmapFlag::AppendOutput => FlagValue::Bool(&mut scan.output.append_output),
            NmapFlag::ScriptKiddie => FlagValue::Path(&mut scan.output.script_kiddie),
            NmapFlag::Verbosity => FlagValue::Int(&mut scan.output.verbosity),
            NmapFlag::Debugging => FlagValue::Int(&mut scan.output.debugging),
            NmapFlag::StatsEvery => FlagValue::String(&mut scan.output.stats_every),
            NmapFlag::Noninteractive => FlagValue::Bool(&mut scan.output.noninteractive),
            NmapFlag::Reason => FlagValue::Bool(&mut scan.output.reason),
            NmapFlag::PacketTrace => FlagValue::Bool(&mut scan.output.packet_trace),
            NmapFlag::OpenOnly => FlagValue::Bool(&mut scan.output.open_only),
            NmapFlag::IfList => FlagValue::Bool(&mut scan.output.iflist),
            NmapFlag::Xml => FlagValue::Path(&mut scan.output.xml),
            NmapFlag::Stylesheet => FlagValue::Path(&mut scan.output.stylesheet),
            NmapFlag::WebXml => FlagValue::Bool(&mut scan.output.webxml),
            NmapFlag::NoStylesheet => FlagValue::Bool(&mut scan.output.no_stylesheet),

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
        all_flags.get(index + 1).copied().unwrap_or(*self)
    }

    pub fn prev(&self) -> Self {
        let all_flags = NmapFlag::iter().collect::<Vec<_>>();
        let index = all_flags.iter().position(|f| f == self).unwrap();
        if index > 0 {
            all_flags[index - 1]
        } else {
            *self
        }
    }

    pub fn first() -> Self {
        NmapFlag::iter().next().unwrap()
    }

    pub fn get_variant_count(&self) -> Option<usize> {
        match self {
            NmapFlag::TcpScanType => Some(TcpScanType::COUNT),
            NmapFlag::SctpScanType => Some(SctpScanType::COUNT),
            NmapFlag::NsockEngine => Some(NsockEngine::COUNT),
            NmapFlag::TimingTemplate => Some(TimingTemplate::COUNT),
            _ => None,
        }
    }

    pub fn requires_admin(&self) -> bool {
        ADMIN_FLAGS.contains(self)
    }
}

#[derive(Debug)]
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

pub const ADMIN_FLAGS: [NmapFlag; 14] = [
    NmapFlag::SynDiscovery,
    NmapFlag::AckDiscovery,
    NmapFlag::UdpDiscovery,
    NmapFlag::SctpDiscovery,
    NmapFlag::IcmpEcho,
    NmapFlag::IcmpTimestamp,
    NmapFlag::IpProtocolPing,
    NmapFlag::TcpScanType,
    NmapFlag::UdpScan,
    NmapFlag::SctpScanType,
    NmapFlag::OsDetection,
    NmapFlag::SpoofIp,
    NmapFlag::SpoofMac,
    NmapFlag::SendEth,
];
