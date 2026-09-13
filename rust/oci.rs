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
/// Attempts to use `skopeo` + `umoci` first. If that fails (not installed or unsupported),
/// falls back to raw tarball mode with `reqwest` + `tar`.
pub fn pull_and_extract_image(url: &str, target_dir: &Path) -> Result<(), String> {
    println!("Pulling image from {}...", url);

    // If URL is a Docker repository (e.g., docker://alpine), attempt skopeo/umoci
    if url.starts_with("docker://") || url.starts_with("oci://") {
        println!("Attempting download via skopeo and extraction via umoci...");
        let oci_layout_dir = "/tmp/nuk4sd_oci_layout";
        let _ = std::fs::remove_dir_all(oci_layout_dir);

        /* FIX #9: use absolute paths for skopeo/umoci — prevents supply-chain attack
         * via compromised PATH. Tries /usr/bin first (Debian/Ubuntu/Kali),
         * /usr/local/bin as fallback (manual installation). */
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
                println!("Image downloaded with skopeo. Extracting with umoci...");
                let umoci_status = Command::new(umoci_bin)
                    .arg("unpack")
                    .arg("--image")
                    .arg(format!("{}:latest", oci_layout_dir))
                    .arg(target_dir.to_str().unwrap())
                    .status();

                if let Ok(ustatus) = umoci_status {
                    if ustatus.success() {
                        println!("Image extracted with umoci to {:?}", target_dir);
                        let _ = std::fs::remove_dir_all(oci_layout_dir);
                        return Ok(());
                    }
                }
                println!("Extraction failed with umoci. Trying fallback method...");
            } else {
                println!("Download failed with skopeo. Trying fallback method...");
            }
        } else {
            println!("skopeo/umoci not found. Trying HTTP fallback method...");
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

/// Creates a cgroup v1/v2 with CPU, Memory, and PID limits, and assigns `pid` to it.
pub fn apply_cgroup_limits(
    cgroup_name: &str,
    pid: u64,
    memory_limit_mb: i64,
    cpu_shares: u64,
    cpu_quota_us: i64,
    max_procs: i64,
) -> Result<Cgroup, String> {
    let hier = cgroups_rs::hierarchies::auto();
    let mut builder = CgroupBuilder::new(cgroup_name);

    if memory_limit_mb > 0 {
        let bytes = memory_limit_mb.saturating_mul(1024 * 1024);
        builder = builder.memory().memory_hard_limit(bytes).done();
    }

    if cpu_shares > 0 || cpu_quota_us > 0 {
        let mut cpu_b = builder.cpu();
        if cpu_shares > 0 {
            cpu_b = cpu_b.shares(cpu_shares);
        }
        if cpu_quota_us > 0 {
            cpu_b = cpu_b.quota(cpu_quota_us).period(100_000);
        }
        builder = cpu_b.done();
    }

    if max_procs > 0 {
        builder = builder
            .pid()
            .maximum_number_of_processes(cgroups_rs::MaxValue::Value(max_procs))
            .done();
    }

    let cg = builder
        .build(hier)
        .map_err(|e| format!("Failed to build cgroup '{}': {}", cgroup_name, e))?;

    let cpid = CgroupPid::from(pid);
    let mut attached = false;

    // Attach PID to CPU controller if available
    if let Some(cpus) = cg.controller_of::<cgroups_rs::cpu::CpuController>() {
        if let Err(e) = cpus.add_task(&cpid) {
            eprintln!("[CGROUP] Warning: failed to add PID {} to cpu controller: {}", pid, e);
        } else {
            attached = true;
        }
    }

    // Attach PID to Memory controller if available
    if let Some(mem) = cg.controller_of::<cgroups_rs::memory::MemController>() {
        if let Err(e) = mem.add_task(&cpid) {
            eprintln!("[CGROUP] Warning: failed to add PID {} to memory controller: {}", pid, e);
        } else {
            attached = true;
        }
    }

    // Attach PID to PID controller if available
    if let Some(pids) = cg.controller_of::<cgroups_rs::pid::PidController>() {
        if let Err(e) = pids.add_task(&cpid) {
            eprintln!("[CGROUP] Warning: failed to add PID {} to pid controller: {}", pid, e);
        } else {
            attached = true;
        }
    }

    if !attached {
        return Err(format!("Could not attach PID {} to any cgroup controller in '{}'", pid, cgroup_name));
    }

    println!("[CGROUP] Cgroup '{}' limits applied to PID {}", cgroup_name, pid);
    Ok(cg)
}

/// Deletes an existing cgroup by name.
pub fn remove_cgroup(cgroup_name: &str) -> Result<(), String> {
    let hier = cgroups_rs::hierarchies::auto();
    let cg = Cgroup::load(hier, cgroup_name);
    cg.delete().map_err(|e| format!("Failed to delete cgroup '{}': {}", cgroup_name, e))
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
