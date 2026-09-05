#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::copy;
use std::path::{Path, PathBuf};
use flate2::read::GzDecoder;
use tar::Archive;
use reqwest::blocking::Client;
use cgroups_rs::*;
use cgroups_rs::cgroup_builder::*;
use oci_spec::runtime::Spec;

use std::process::Command;

/// Pulls a rootfs tarball or OCI image from a given URL/alias and extracts it.
/// Tenta usar `skopeo` + `umoci` primeiro. Se falhar (não instalados ou não suportado),
/// cai para o modo raw tarball com `reqwest` + `tar`.
pub fn pull_and_extract_image(url: &str, target_dir: &Path) -> Result<(), String> {
    println!("Pulling image from {}...", url);

    // Se a URL for um repositório Docker (ex: docker://alpine), tenta com skopeo/umoci
    if url.starts_with("docker://") || url.starts_with("oci://") {
        println!("Tentando baixar via skopeo e extrair via umoci...");
        let oci_layout_dir = "/tmp/nuk4sd_oci_layout";
        let _ = std::fs::remove_dir_all(oci_layout_dir);

        /* FIX #9: usar paths absolutos para skopeo/umoci — previne supply-chain attack
         * via PATH comprometido. Tenta /usr/bin primeiro (Debian/Ubuntu/Kali),
         * /usr/local/bin como fallback (instalação manual). */
        let skopeo_bin = if std::path::Path::new("/usr/bin/skopeo").exists() {
            "/usr/bin/skopeo"
        } else {
            "/usr/local/bin/skopeo"
        };
        let umoci_bin = if std::path::Path::new("/usr/bin/umoci").exists() {
            "/usr/bin/umoci"
        } else {
            "/usr/local/bin/umoci"
        };

        let skopeo_status = Command::new(skopeo_bin)
            .arg("copy")
            .arg(url)
            .arg(format!("oci:{}", oci_layout_dir))
            .status();

        if let Ok(status) = skopeo_status {
            if status.success() {
                println!("Imagem baixada com skopeo. Extraindo com umoci...");
                let umoci_status = Command::new(umoci_bin)
                    .arg("unpack")
                    .arg("--image")
                    .arg(format!("{}:latest", oci_layout_dir))
                    .arg(target_dir.to_str().unwrap())
                    .status();

                if let Ok(ustatus) = umoci_status {
                    if ustatus.success() {
                        println!("Imagem extraída com umoci em {:?}", target_dir);
                        let _ = std::fs::remove_dir_all(oci_layout_dir);
                        return Ok(());
                    }
                }
                println!("Falha na extração com umoci. Tentando método fallback...");
            } else {
                println!("Falha no download com skopeo. Tentando método fallback...");
            }
        } else {
            println!("skopeo/umoci não encontrados. Tentando método fallback HTTP...");
        }
    }

    // Fallback: raw tarball HTTP download
    let client = Client::new();
    let mut response = client.get(url).send().map_err(|e| format!("Failed to download image: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("Failed to download image, status code: {}", response.status()));
    }

    let temp_tarball = PathBuf::from("/tmp/nuk4sd_pulled_image.tar.gz");
    let mut dest = File::create(&temp_tarball).map_err(|e| format!("Failed to create temp file: {}", e))?;
    copy(&mut response, &mut dest).map_err(|e| format!("Failed to write to temp file: {}", e))?;

    println!("Image downloaded. Extracting to {:?}...", target_dir);
    let tar_gz = File::open(&temp_tarball).map_err(|e| format!("Failed to open temp tarball: {}", e))?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive.unpack(target_dir).map_err(|e| format!("Failed to unpack tarball: {}", e))?;
    let _ = std::fs::remove_file(temp_tarball);
    
    println!("Image successfully extracted to {:?}", target_dir);
    Ok(())
}

/// Creates a cgroup v2 with CPU/Memory limits.
pub fn apply_cgroup_limits(cgroup_name: &str, pid: u64, memory_limit_mb: i64, cpu_shares: u64) -> Result<Cgroup, String> {
    let hier = cgroups_rs::hierarchies::auto();
    let cg = CgroupBuilder::new(cgroup_name)
        .memory()
            .memory_hard_limit(memory_limit_mb * 1024 * 1024)
            .done()
        .cpu()
            .shares(cpu_shares)
            .done()
        .build(hier)
        .map_err(|e| format!("Failed to build cgroup: {}", e))?;

    let cpus: &cgroups_rs::cpu::CpuController = cg.controller_of().unwrap();
    cpus.add_task(&CgroupPid::from(pid)).map_err(|e| format!("Failed to add task to cgroup: {}", e))?;

    println!("Cgroup '{}' limits applied to PID {}", cgroup_name, pid);
    Ok(cg)
}

/// Reads a standard OCI config.json to configure the sandbox.
pub fn parse_oci_manifest(config_path: &str) -> Result<(), String> {
    let spec = Spec::load(config_path).map_err(|e| format!("Failed to load OCI spec: {}", e))?;
    
    println!("--- OCI Spec Loaded ---");
    if let Some(process) = spec.process() {
        println!("Entrypoint: {:?}", process.args());
        println!("CWD: {:?}", process.cwd());
        if let Some(caps) = process.capabilities() {
            println!("Capabilities to bound: {:?}", caps.bounding());
        }
    }
    
    if let Some(root) = spec.root() {
        println!("Rootfs path: {}", root.path().display());
        println!("Readonly rootfs: {}", root.readonly().unwrap_or(false));
    }
    
    if let Some(mounts) = spec.mounts() {
        println!("OCI Mounts defined: {}", mounts.len());
    }
    
    Ok(())
}
