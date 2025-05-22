# StratUmm - IPv4/6 NTP Amplifier

## Overview

StratUmm is a powerful and user-friendly NTP amplification attack tool, built with Rust and featuring a graphical user interface (GUI). It allows you to perform NTP reflection attacks against a target IP address by leveraging vulnerable NTP servers. A key feature is the ability to **spoof the source IP address** of the attack packets, enhancing anonymity and making the attack untraceable to the origin.

This tool is designed for educational purposes and network security research. **Misuse of this tool for illegal activities is strictly prohibited and the author is not responsible for any such misuse.**

## Features

* **IPv4/IPv6 Support:** Capable of operating on both IPv4 and IPv6 networks.

* **NTP Amplification:** Leverages NTP's MON_GETLIST_1 request for high amplification factors.

* **Source IP Spoofing:** Spoof the source IP address of outgoing packets for enhanced anonymity.

* **GUI Interface:** An intuitive graphical interface built with `eframe` for easy interaction.

* **NTP Server Scanning:** Automatically scans for active NTP servers using `ntpq`.

* **Configurable NTP Pools:** Manages NTP pools via a `config.json` file.

* **Attack Statistics:** Real-time display of packets sent, attack duration, and effective throughput.

* **Server List Management:** Load NTP server lists from a file.

* **Individual Server Benchmarking:** Test the amplification factor of specific NTP servers.

* **Logging:** Detailed logging of operations and attack status.

## Requirements

* **Rust Toolchain:** Ensure you have Rust installed. You can install it via `rustup`:

    ```
    curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
    ```

* **Root/Administrator Privileges:** This tool requires root (Linux) or Administrator (Windows) privileges to create raw sockets for packet manipulation.

* **Npcap (for Windows):** If you are on Windows, you **must** install [Npcap](https://nmap.org/npcap/) and ensure the "Install Npcap SDK" option is checked during installation.

* **NTP Daemon:** An NTP daemon (like `ntp` or `ntpd`) should be installed and running on your system for server scanning functionality.

## Installation

1.  **Clone the Repository:**

    ```
    git clone [https://github.com/dotslashCosmic/StratUmm.git](https://github.com/dotslashCosmic/StratUmm.git)
    cd StratUmm
    ```
    
    * **Windows Users:** Ensure Npcap SDK is installed. If `cargo build` fails to find Npcap libraries, you might need to manually set the `LIB` environment variable before building:

        ```
        set LIB=%LIB%;C:\Path\Npcap\Lib\x64
        ```

        (Replace `C:\Path\Npcap\Lib\x64` with the actual path to your Npcap SDK `Lib` directory, typically `C:\Program Files\Npcap\SDK\Lib\x64` or `C:\Program Files (x86)\Npcap\SDK\Lib\x86` for 32-bit systems).

2.  **Build the Project:**

    ```
    cargo build --release
    ```

## Usage

After building, the executable will be located in `target/release/stratumm`.

**Run with necessary privileges:**

* **Linux:**

    ```
    sudo ./target/release/stratumm
    ```

* **Windows (Run as Administrator):**
    Navigate to `target/release/` in File Explorer, right-click `stratumm.exe`, and select "Run as administrator".

### GUI Overview

The GUI provides several sections:

1.  **Target and Configuration:**

    * **Target IP (Victim & Spoofed Source):** This field serves a dual purpose. It is the IP address of the **ultimate victim** you intend to flood with amplified traffic. Simultaneously, this IP address will be used as the **spoofed source IP** in the initial NTP requests sent to the amplifier servers. This means the amplified responses from the NTP servers will be directed back to this "Target IP," causing the flood.

    * **Server List File:** Path to a text file containing a list of NTP server IPs/hostnames (one per line). A default `servers.txt` will be created if missing.

    * **NTP Config File:** Path to your system's NTP configuration file (e.g., `/etc/ntp.conf` or `/etc/ntpsec/ntp.conf`). A default `config.json` will be created if missing.

    * **Scan Servers Button:** Initiates a scan for active NTP servers using `ntpq`. The discovered servers will be used for attacks.

2.  **Attack Control:**

    * **START ATTACK / STOP ATTACK Button:** Toggles the amplification attack. Ensure you have a valid **Target IP** and scanned/loaded NTP servers before starting. The amplified traffic will be directed to the **Target IP** you provided.

3.  **NTP Server Benchmark:**

    * **Server IP to Benchmark:** Enter the IP or hostname of an NTP server you want to test for its amplification factor.

    * **Test Target IP (Spoofed Source):** Enter a **local IP address on your machine that you can listen on**. This IP will be used as the **spoofed source IP** for the benchmark request sent to the NTP server. The tool will then attempt to listen for the NTP response on this local IP/port to measure the amplification.

    * **Benchmark Server Button:** Initiates a benchmark to calculate the amplification factor of the specified server.

    * **Last Benchmark Result:** Displays the results of the most recent benchmark.

4.  **Attack Statistics:**

    * Provides real-time metrics like attack duration, packets sent, effective throughput (packets per second), and the number of active servers being used.

5.  **Logs:**

    * A scrollable area displaying all operations, warnings, and errors.

### Configuration Files

* **`config.json`:**
    A JSON file used to manage the NTP pools that your local NTP daemon will synchronize with. If this file does not exist, a default will be created:

    ```
    {
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
    }
    ```

    * `ntp_config_path`: The path to your system's NTP configuration file.

    * `pools`: A list of NTP pool domains. The scanner will attempt to resolve and use servers from these pools.

* **`servers.txt`:**
    A plain text file where each line is an NTP server IP address or hostname. This file is used if you prefer to provide a static list of servers rather than relying solely on the scanner. If this file does not exist, a default will be created:

    ```
    time.google.com
    time1.google.com
    time2.google.com
    time3.google.com
    time4.google.com
    ```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License and the Apache-2.0 License. See the [LICENSE](LICENSE) files for details.
