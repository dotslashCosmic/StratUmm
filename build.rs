// Author: dotslashCosmic
use std::env;
use std::path::PathBuf;

fn main() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());
    let lib_dir_suffix = if target_arch == "x86_64" { "x64" } else { "x86" };

    let mut found_lib_path = None;

    let potential_base_paths = [
        PathBuf::from("C:\\Program Files\\Npcap\\SDK\\Lib"),
        PathBuf::from("C:\\Program Files\\Npcap\\Lib"),
    ];

    for base_path in potential_base_paths.iter() {
        let mut path_to_check = base_path.clone();
        path_to_check.push(lib_dir_suffix);

        eprintln!("Attempting to find Npcap Libs in: {}", path_to_check.display());

        if path_to_check.exists() && path_to_check.is_dir() {
            found_lib_path = Some(path_to_check);
            break;
        }
    }

    if let Some(path) = found_lib_path {
        println!("cargo:rustc-link-search=native={}", path.display());
        println!("cargo:rustc-link-lib=static=Packet");
        println!("cargo:rustc-link-lib=static=wpcap");
        println!("cargo:rustc-link-lib=static=ws2_32");
        println!("cargo:rustc-link-lib=static=iphlpapi");
        println!("cargo:rustc-link-lib=static=advapi32");
        eprintln!("SUCCESS: Found Npcap SDK libraries at: {}", path.display());
    } else {
        eprintln!("ERROR: Npcap SDK 'Lib' directory not found in the following common locations:");
        for base_path in potential_base_paths.iter() {
            let mut path_to_check = base_path.clone();
            path_to_check.push(lib_dir_suffix);
            eprintln!("  - {}", path_to_check.display());
        }
        eprintln!("Please ensure Npcap is installed with the 'Install Npcap SDK' option checked.");
        eprintln!("If Npcap is installed in a custom location, you may need to manually set the");
        eprintln!("LIB environment variable or modify this build.rs script.");
        eprintln!("Example for LIB variable (in your command prompt before `cargo build`):");
        eprintln!("set LIB=%LIB%;C:\\Path\\To\\Your\\Npcap\\Lib\\{}", lib_dir_suffix);
    }

    if cfg!(windows) {
        embed_resource::compile("src/windows/app.rc", embed_resource::NONE);
    }
}
