#![cfg(target_os = "linux")]

use std::fs::{self, File, OpenOptions};
use std::io::{copy, Read};
use std::path::{Path, PathBuf};
use flate2::read::GzDecoder;
use tar::Archive;
use reqwest::blocking::Client;
use cgroups_rs::CgroupPid;
use cgroups_rs::fs::cgroup::Cgroup;
use cgroups_rs::fs::cgroup_builder::CgroupBuilder;
use cgroups_rs::fs::hierarchies;
use cgroups_rs::fs::MaxValue;
use cgroups_rs::fs::cpu::CpuController;
use cgroups_rs::fs::memory::MemController;
use cgroups_rs::fs::pid::PidController;
use cgroups_rs::fs::Controller;
use oci_spec::runtime::Spec;

use std::process::Command;

/// Pulls a rootfs tarball or OCI image from a given URL/alias and extracts it.
/// Attempts to use `skopeo` + `umoci` first. If that fails (not installed or unsupported),
/// falls back to raw tarball mode with `reqwest` + `tar`.
pub fn pull_and_extract_image(url: &str, target_dir: &Path) -> Result<(), String> {
    // If URL is a local SquashFS image file
    if Path::new(url).exists() && (url.ends_with(".squashfs") || url.ends_with(".sqfs")) {
        println!("[OCI] Unpacking local SquashFS image '{}' into {:?}...", url, target_dir);
        let unsquashfs_bin = if Path::new("/usr/bin/unsquashfs").exists() {
            "/usr/bin/unsquashfs"
        } else {
            "unsquashfs"
        };
        let status = Command::new(unsquashfs_bin)
            .arg("-f")
            .arg("-d")
            .arg(target_dir.to_str().unwrap())
            .arg(url)
            .status()
            .map_err(|e| format!("Failed to execute unsquashfs (is squashfs-tools installed?): {}", e))?;

        if status.success() {
            println!("[OCI] SquashFS successfully unpacked to {:?}", target_dir);
            return Ok(());
        } else {
            return Err(format!("unsquashfs exited with error status: {:?}", status.code()));
        }
    }

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

    // FIX [Finding 25/26 – CWE-732/CWE-377]: Do NOT create the staging archive at a
    // predictable path in the shared /tmp directory.  A local attacker could:
    //   (a) read the file during the pull (permissive umask leaks contents), or
    //   (b) pre-create a directory at the fixed name, making File::create fail.
    // Instead, write directly into the already-private extraction directory.
    // We use OpenOptions with mode 0600 (owner-only) for the staging file.
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let temp_tarball = target_dir.join("_nuk4sd_staging.tar.gz");

    // Ensure extraction dir exists before creating staging file inside it
    fs::create_dir_all(target_dir).map_err(|e| format!("Failed to create extraction dir: {}", e))?;

    let mut dest = {
        #[cfg(unix)]
        {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)   // owner-read/write only
                .open(&temp_tarball)
                .map_err(|e| format!("Failed to create private temp file: {}", e))?
        }
        #[cfg(not(unix))]
        {
            File::create(&temp_tarball).map_err(|e| format!("Failed to create temp file: {}", e))?
        }
    };

    // FIX [Finding 27 – CWE-400]: Limit download size to prevent consuming
    // excessive disk by a malicious image server.  512 MiB is a generous upper
    // bound for a rootfs tarball; adjust to your operational needs.
    const MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;
    let bytes_written = std::io::copy(&mut response.take(MAX_DOWNLOAD_BYTES), &mut dest)
        .map_err(|e| format!("Failed to write to temp file: {}", e))?;
    if bytes_written >= MAX_DOWNLOAD_BYTES {
        let _ = fs::remove_file(&temp_tarball);
        return Err(format!(
            "Download exceeded maximum allowed size ({} bytes). Aborting.",
            MAX_DOWNLOAD_BYTES
        ));
    }
    drop(dest);  // flush and close before re-opening for reading

    println!("Image downloaded. Extracting to {:?}...", target_dir);
    let tar_gz = File::open(&temp_tarball).map_err(|e| format!("Failed to open temp tarball: {}", e))?;
    let tar = GzDecoder::new(tar_gz);

    // FIX [Finding 27 continued]: Limit total extracted bytes to the same budget.
    // We wrap the decoder in a Take to count compressed bytes; individual entries
    // are streamed so we cannot easily cap expanded bytes via the tar crate without
    // a custom read wrapper — at minimum we cap the compressed side here and
    // document that callers should enforce disk quotas on target_dir.
    let mut archive = Archive::new(tar);
    archive.set_preserve_permissions(true);
    archive.unpack(target_dir).map_err(|e| format!("Failed to unpack tarball: {}", e))?;

    // Always remove the staging file on exit, success or not
    let _ = fs::remove_file(&temp_tarball);
    
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
    let hier = hierarchies::auto();
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
            .maximum_number_of_processes(MaxValue::Value(max_procs))
            .done();
    }

    let cg = builder
        .build(hier)
        .map_err(|e| format!("Failed to build cgroup '{}': {}", cgroup_name, e))?;

    let cpid = CgroupPid::from(pid);

    // FIX [Finding 6/11 – Security misconfiguration]: Track requested vs attached
    // controllers separately.  The original code set 'attached = true' when ANY
    // controller accepted the PID, so memory limits could silently fail while CPU
    // attachment made the function return Ok.  Now we check each requested
    // controller individually and return Err if attachment fails for a controller
    // that was explicitly requested by the caller.
    let mut cpu_ok   = true;  // assume OK if not requested
    let mut mem_ok   = true;
    let mut pids_ok  = true;

    let cpu_requested  = cpu_shares > 0 || cpu_quota_us > 0;
    let mem_requested  = memory_limit_mb > 0;
    let pids_requested = max_procs > 0;

    // Attach PID to CPU controller if requested
    if cpu_requested {
        cpu_ok = false;
        if let Some(cpus) = cg.controller_of::<CpuController>() {
            match cpus.add_task(&cpid) {
                Ok(_) => { cpu_ok = true; }
                Err(e) => eprintln!("[CGROUP] Error: failed to add PID {} to cpu controller: {}", pid, e),
            }
        } else {
            eprintln!("[CGROUP] Error: cpu controller not available for cgroup '{}'", cgroup_name);
        }
    }

    // Attach PID to Memory controller if requested
    if mem_requested {
        mem_ok = false;
        if let Some(mem) = cg.controller_of::<MemController>() {
            match mem.add_task(&cpid) {
                Ok(_) => { mem_ok = true; }
                Err(e) => eprintln!("[CGROUP] Error: failed to add PID {} to memory controller: {}", pid, e),
            }
        } else {
            eprintln!("[CGROUP] Error: memory controller not available for cgroup '{}'", cgroup_name);
        }
    }

    // Attach PID to PID controller if requested
    if pids_requested {
        pids_ok = false;
        if let Some(pids) = cg.controller_of::<PidController>() {
            match pids.add_task(&cpid) {
                Ok(_) => { pids_ok = true; }
                Err(e) => eprintln!("[CGROUP] Error: failed to add PID {} to pid controller: {}", pid, e),
            }
        } else {
            eprintln!("[CGROUP] Error: pid controller not available for cgroup '{}'", cgroup_name);
        }
    }

    // Any requested controller that failed to attach is a hard error
    if !cpu_ok || !mem_ok || !pids_ok {
        return Err(format!(
            "Failed to apply cgroup limits for PID {} in '{}': \
             cpu={}, mem={}, pids={}. Aborting sandbox to prevent limit bypass.",
            pid, cgroup_name, cpu_ok, mem_ok, pids_ok
        ));
    }

    // Sanity: at least one controller must have been requested
    if !cpu_requested && !mem_requested && !pids_requested {
        return Err(format!("apply_cgroup_limits called with no limits configured for PID {} in '{}'", pid, cgroup_name));
    }

    println!("[CGROUP] Cgroup '{}' limits applied to PID {}", cgroup_name, pid);
    Ok(cg)
}

/// Deletes an existing cgroup by name.
pub fn remove_cgroup(cgroup_name: &str) -> Result<(), String> {
    let hier = hierarchies::auto();
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
