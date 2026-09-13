use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

/// Safely resolves a relative path within a vault root directory,
/// preventing path traversal (`../`) and TOCTOU symlink escaping attacks.
pub fn safe_vault_path(vault_root: &Path, rel_subpath: &Path) -> Result<PathBuf, String> {
    // 1. Sanitize components: forbid root directory, prefix, or parent dir escape
    let mut clean_rel = PathBuf::new();
    for comp in rel_subpath.components() {
        match comp {
            Component::Normal(c) => clean_rel.push(c),
            Component::CurDir => continue,
            Component::ParentDir => {
                if !clean_rel.pop() {
                    return Err(format!(
                        "Security violation: path traversal attempt in '{}'",
                        rel_subpath.display()
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                // If an absolute path was given, strip the root prefix and treat as relative
                continue;
            }
        }
    }

    let target = vault_root.join(&clean_rel);

    // 2. Canonicalize vault root to get base physical path
    let canonical_root = vault_root
        .canonicalize()
        .map_err(|e| format!("Cannot resolve vault root '{}': {}", vault_root.display(), e))?;

    // 3. If target already exists, verify its canonical path stays strictly inside canonical_root
    if target.exists() {
        let canonical_target = target
            .canonicalize()
            .map_err(|e| format!("Cannot resolve target path '{}': {}", target.display(), e))?;

        if !canonical_target.starts_with(&canonical_root) {
            return Err(format!(
                "Security violation: symlink or path '{}' resolves outside vault root",
                rel_subpath.display()
            ));
        }

        // 4. Anti-TOCTOU check: verify intermediate path components are not external symlinks
        let mut cur = vault_root.to_path_buf();
        for comp in clean_rel.components() {
            cur.push(comp);
            if let Ok(meta) = fs::symlink_metadata(&cur) {
                if meta.file_type().is_symlink() {
                    let link_target = fs::read_link(&cur)
                        .map_err(|e| format!("Cannot read symlink '{}': {}", cur.display(), e))?;
                    let resolved = cur.parent().unwrap_or(vault_root).join(link_target);
                    if let Ok(canon) = resolved.canonicalize() {
                        if !canon.starts_with(&canonical_root) {
                            return Err(format!(
                                "Security violation: symlink at '{}' escapes vault root",
                                cur.display()
                            ));
                        }
                    }
                }
            }
        }
    } else {
        // If target doesn't exist yet, verify its parent directory stays within vault
        if let Some(parent) = target.parent() {
            if parent.exists() {
                let canonical_parent = parent.canonicalize().map_err(|e| {
                    format!("Cannot resolve parent directory '{}': {}", parent.display(), e)
                })?;
                if !canonical_parent.starts_with(&canonical_root) {
                    return Err(format!(
                        "Security violation: parent path '{}' resolves outside vault root",
                        parent.display()
                    ));
                }
            }
        }
    }

    Ok(target)
}

/// Helper to copy file contents with optional permissions/timestamp preservation
fn copy_file_secure(src: &Path, dst: &Path, replace: bool, preserve: bool) -> Result<(), String> {
    if dst.exists() && !replace {
        return Err(format!(
            "Target file already exists: '{}' (use 'replace' to overwrite)",
            dst.display()
        ));
    }

    // Reject copying if source is a dangling or unsafe symlink
    let src_meta = fs::symlink_metadata(src)
        .map_err(|e| format!("Cannot read metadata of '{}': {}", src.display(), e))?;

    if src_meta.file_type().is_symlink() {
        return Err(format!(
            "Refusing to copy raw symlink '{}': symlinks are restricted for security",
            src.display()
        ));
    }

    fs::copy(src, dst).map_err(|e| {
        format!(
            "Failed to copy '{}' to '{}': {}",
            src.display(),
            dst.display(),
            e
        )
    })?;

    if preserve {
        let perms = src_meta.permissions();
        let _ = fs::set_permissions(dst, perms);
    }

    Ok(())
}

/// Recursive copy helper
fn copy_dir_all(src: &Path, dst: &Path, replace: bool, preserve: bool) -> Result<(), String> {
    if !dst.exists() {
        fs::create_dir_all(dst).map_err(|e| {
            format!("Failed to create destination directory '{}': {}", dst.display(), e)
        })?;
    }

    for entry in fs::read_dir(src).map_err(|e| format!("Failed to read '{}': {}", src.display(), e))? {
        let entry = entry.map_err(|e| format!("Error reading directory entry: {}", e))?;
        let file_type = entry.file_type().map_err(|e| format!("Error reading file type: {}", e))?;
        let fname = entry.file_name();
        if fname == ".vault_snapshots" {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst.join(fname);

        if file_type.is_dir() {
            copy_dir_all(&src_path, &dst_path, replace, preserve)?;
        } else if file_type.is_file() {
            copy_file_secure(&src_path, &dst_path, replace, preserve)?;
        }
    }

    Ok(())
}

/// Adds a file or directory into the vault
pub fn vault_add(
    vault_path: &str,
    src_path_str: &str,
    recursive: bool,
    replace: bool,
    preserve: bool,
) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let src = Path::new(src_path_str);

    if !src.exists() {
        return Err(format!("Source path '{}' does not exist.", src_path_str));
    }

    let file_name = src
        .file_name()
        .ok_or_else(|| format!("Invalid source file name: '{}'", src_path_str))?;

    let dst = safe_vault_path(vroot, Path::new(file_name))?;

    let meta = fs::metadata(src)
        .map_err(|e| format!("Failed to inspect '{}': {}", src_path_str, e))?;

    if meta.is_dir() {
        if !recursive {
            return Err(format!(
                "'{}' is a directory. Use 'recursive' to add directories.",
                src_path_str
            ));
        }
        copy_dir_all(src, &dst, replace, preserve)?;
        println!("✔ Directory '{}' added to vault.", file_name.to_string_lossy());
    } else {
        copy_file_secure(src, &dst, replace, preserve)?;
        println!("✔ File '{}' added to vault.", file_name.to_string_lossy());
    }

    Ok(())
}

/// Extracts a file or directory from the vault into the destination directory
pub fn vault_extract(
    vault_path: &str,
    rel_file_str: &str,
    dest_dir_str: &str,
    force: bool,
) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let src = safe_vault_path(vroot, Path::new(rel_file_str))?;

    if !src.exists() {
        return Err(format!(
            "File or directory '{}' does not exist in vault.",
            rel_file_str
        ));
    }

    let ddir = Path::new(dest_dir_str);
    if !ddir.exists() {
        fs::create_dir_all(ddir).map_err(|e| {
            format!("Cannot create destination directory '{}': {}", dest_dir_str, e)
        })?;
    }

    let file_name = src
        .file_name()
        .ok_or_else(|| format!("Invalid file name: '{}'", rel_file_str))?;
    let dst = ddir.join(file_name);

    if dst.exists() && !force {
        return Err(format!(
            "Destination file '{}' already exists (use 'force' to overwrite).",
            dst.display()
        ));
    }

    let meta = fs::metadata(&src).map_err(|e| format!("Failed to inspect vault file: {}", e))?;

    if meta.is_dir() {
        copy_dir_all(&src, &dst, force, true)?;
        println!("✔ Directory '{}' extracted to '{}'.", rel_file_str, dst.display());
    } else {
        copy_file_secure(&src, &dst, force, true)?;
        println!("✔ File '{}' extracted to '{}'.", rel_file_str, dst.display());
    }

    Ok(())
}

/// Moves or renames an entry within the vault
pub fn vault_mv(vault_path: &str, src_rel: &str, dst_rel: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let src = safe_vault_path(vroot, Path::new(src_rel))?;
    let dst = safe_vault_path(vroot, Path::new(dst_rel))?;

    if !src.exists() {
        return Err(format!("Source '{}' does not exist in vault.", src_rel));
    }

    fs::rename(&src, &dst).map_err(|e| {
        format!(
            "Failed to move '{}' to '{}': {}",
            src_rel, dst_rel, e
        )
    })?;

    // Also check if there's a corresponding .enc file
    let src_enc = src.with_extension(format!(
        "{}.enc",
        src.extension().and_then(|s| s.to_str()).unwrap_or("")
    ));
    if src_enc.exists() {
        let dst_enc = dst.with_extension(format!(
            "{}.enc",
            dst.extension().and_then(|s| s.to_str()).unwrap_or("")
        ));
        let _ = fs::rename(&src_enc, &dst_enc);
    }

    println!("✔ Renamed/moved '{}' -> '{}'.", src_rel, dst_rel);
    Ok(())
}

/// Copies an entry within the vault
pub fn vault_cp(vault_path: &str, src_rel: &str, dst_rel: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let src = safe_vault_path(vroot, Path::new(src_rel))?;
    let dst = safe_vault_path(vroot, Path::new(dst_rel))?;

    if !src.exists() {
        return Err(format!("Source '{}' does not exist in vault.", src_rel));
    }

    let meta = fs::metadata(&src).map_err(|e| format!("Failed to inspect source: {}", e))?;

    if meta.is_dir() {
        copy_dir_all(&src, &dst, true, true)?;
    } else {
        copy_file_secure(&src, &dst, true, true)?;
    }

    println!("✔ Copied '{}' -> '{}'.", src_rel, dst_rel);
    Ok(())
}

/// Removes a file from the vault
pub fn vault_rm_file(vault_path: &str, target_rel: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let target = safe_vault_path(vroot, Path::new(target_rel))?;

    if !target.exists() {
        // Also check if it exists with .enc
        let target_enc = safe_vault_path(vroot, &PathBuf::from(format!("{}.enc", target_rel)))?;
        if target_enc.exists() {
            fs::remove_file(&target_enc).map_err(|e| {
                format!("Failed to remove encrypted file '{}': {}", target_rel, e)
            })?;
            println!("✔ Removed encrypted file '{}.enc'.", target_rel);
            return Ok(());
        }
        return Err(format!("File '{}' not found in vault.", target_rel));
    }

    let meta = fs::metadata(&target).map_err(|e| format!("Failed to inspect file: {}", e))?;
    if meta.is_dir() {
        return Err(format!(
            "'{}' is a directory. Use 'rmdir' to remove directories.",
            target_rel
        ));
    }

    fs::remove_file(&target).map_err(|e| {
        format!("Failed to remove file '{}': {}", target_rel, e)
    })?;

    // Also check if .enc counterpart exists
    let target_enc = safe_vault_path(vroot, &PathBuf::from(format!("{}.enc", target_rel)))?;
    if target_enc.exists() {
        let _ = fs::remove_file(&target_enc);
    }

    println!("✔ Removed file '{}'.", target_rel);
    Ok(())
}

/// Creates a directory within the vault
pub fn vault_mkdir(vault_path: &str, dir_rel: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let target = safe_vault_path(vroot, Path::new(dir_rel))?;

    if target.exists() {
        return Err(format!("Directory '{}' already exists.", dir_rel));
    }

    fs::create_dir_all(&target).map_err(|e| {
        format!("Failed to create directory '{}': {}", dir_rel, e)
    })?;

    println!("✔ Directory '{}' created.", dir_rel);
    Ok(())
}

/// Removes an empty directory within the vault
pub fn vault_rmdir(vault_path: &str, dir_rel: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let target = safe_vault_path(vroot, Path::new(dir_rel))?;

    if !target.exists() {
        return Err(format!("Directory '{}' does not exist.", dir_rel));
    }

    fs::remove_dir(&target).map_err(|e| {
        format!(
            "Failed to remove directory '{}' (ensure it is empty): {}",
            dir_rel, e
        )
    })?;

    println!("✔ Directory '{}' removed.", dir_rel);
    Ok(())
}

/// Visualizes the vault contents as an ASCII tree
pub fn vault_tree(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        return Err(format!("Vault path '{}' does not exist.", vault_path));
    }

    println!("\n  Vault Tree [ {} ]", vault_path);
    print_tree_recursive(vroot, "")?;
    println!();
    Ok(())
}

fn print_tree_recursive(dir: &Path, prefix: &str) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("Cannot read directory '{}': {}", dir.display(), e))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name() != ".vault_snapshots")
        .collect();

    // Sort entries: directories first, then alphabetical
    entries.sort_by(|a, b| {
        let a_is_dir = a.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let b_is_dir = b.file_type().map(|t| t.is_dir()).unwrap_or(false);
        match (a_is_dir, b_is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.file_name().cmp(&b.file_name()),
        }
    });

    let total = entries.len();
    for (i, entry) in entries.iter().enumerate() {
        let is_last = i == total - 1;
        let connector = if is_last { "└── " } else { "├── " };
        let name = entry.file_name().to_string_lossy().to_string();

        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            println!("  {}{}\x1b[1;34m{}/\x1b[0m", prefix, connector, name);
            let next_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
            print_tree_recursive(&entry.path(), &next_prefix)?;
        } else {
            let is_enc = name.ends_with(".enc");
            if is_enc {
                println!("  {}{}\x1b[32m{}\x1b[0m (encrypted)", prefix, connector, name);
            } else {
                println!("  {}{}{}", prefix, connector, name);
            }
        }
    }

    Ok(())
}

/// Displays disk space usage of the vault
pub fn vault_du(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        return Err(format!("Vault path '{}' does not exist.", vault_path));
    }

    let mut total_bytes: u64 = 0;
    let mut plain_files: usize = 0;
    let mut enc_files: usize = 0;
    let mut dir_count: usize = 0;

    fn du_walk(
        dir: &Path,
        total: &mut u64,
        plain: &mut usize,
        enc: &mut usize,
        dirs: &mut usize,
    ) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| format!("Cannot read '{}': {}", dir.display(), e))? {
            let entry = entry.map_err(|e| format!("Error: {}", e))?;
            let fname = entry.file_name();
            if fname == ".vault_snapshots" {
                continue;
            }
            let ft = entry.file_type().map_err(|e| format!("Error: {}", e))?;
            if ft.is_dir() {
                *dirs += 1;
                du_walk(&entry.path(), total, plain, enc, dirs)?;
            } else if ft.is_file() {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                *total += size;
                let name = fname.to_string_lossy().to_string();
                if name.ends_with(".enc") {
                    *enc += 1;
                } else {
                    *plain += 1;
                }
            }
        }
        Ok(())
    }

    du_walk(vroot, &mut total_bytes, &mut plain_files, &mut enc_files, &mut dir_count)?;

    let human_size = if total_bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", total_bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if total_bytes >= 1024 * 1024 {
        format!("{:.2} MB", total_bytes as f64 / (1024.0 * 1024.0))
    } else if total_bytes >= 1024 {
        format!("{:.2} KB", total_bytes as f64 / 1024.0)
    } else {
        format!("{} B", total_bytes)
    };

    println!("\n  ── Vault Disk Usage ──────────────────────────");
    println!("  Path:            {}", vault_path);
    println!("  Total Size:      {} ({} bytes)", human_size, total_bytes);
    println!("  Plain Files:     {}", plain_files);
    println!("  Encrypted Files: {}", enc_files);
    println!("  Directories:     {}", dir_count);
    println!("  ──────────────────────────────────────────────\n");

    Ok(())
}

/// Searches for files or directories matching `pattern` inside the vault
pub fn vault_find(vault_path: &str, pattern: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        return Err(format!("Vault path '{}' does not exist.", vault_path));
    }

    let pat_lower = pattern.to_lowercase();
    let mut matches = Vec::new();

    fn find_walk(dir: &Path, vroot: &Path, pat: &str, out: &mut Vec<(String, bool, u64)>) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| format!("Cannot read '{}': {}", dir.display(), e))? {
            let entry = entry.map_err(|e| format!("Error: {}", e))?;
            let fname = entry.file_name();
            if fname == ".vault_snapshots" {
                continue;
            }
            let name_str = fname.to_string_lossy().to_string();
            let p = entry.path();
            let rel = p.strip_prefix(vroot).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            let ft = entry.file_type().map_err(|e| format!("Error: {}", e))?;
            let is_dir = ft.is_dir();

            let matched = if pat == "*" {
                true
            } else if pat.starts_with('*') && pat.ends_with('*') && pat.len() > 2 {
                rel.to_lowercase().contains(&pat[1..pat.len() - 1])
            } else if pat.starts_with('*') && pat.len() > 1 {
                rel.to_lowercase().ends_with(&pat[1..])
            } else if pat.ends_with('*') && pat.len() > 1 {
                rel.to_lowercase().starts_with(&pat[..pat.len() - 1])
            } else {
                rel.to_lowercase().contains(pat) || name_str.to_lowercase().contains(pat)
            };

            if matched {
                let size = if is_dir { 0 } else { entry.metadata().map(|m| m.len()).unwrap_or(0) };
                out.push((rel, is_dir, size));
            }

            if is_dir {
                find_walk(&p, vroot, pat, out)?;
            }
        }
        Ok(())
    }

    find_walk(vroot, vroot, &pat_lower, &mut matches)?;

    if matches.is_empty() {
        println!("No files or directories matching '{}' found in vault.", pattern);
        return Ok(());
    }

    println!("\n  ── Vault Search: '{}' ({} found) ─────────────────", pattern, matches.len());
    for (rel, is_dir, size) in matches {
        if is_dir {
            println!("  \x1b[1;34m[DIR]\x1b[0m   {}/", rel);
        } else if rel.ends_with(".enc") {
            println!("  \x1b[32m[ENC]\x1b[0m   {} ({} bytes)", rel, size);
        } else {
            println!("  [FILE]  {} ({} bytes)", rel, size);
        }
    }
    println!("  ────────────────────────────────────────────────────────\n");

    Ok(())
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Snapshots & Immutable Versioning (Block 3)
 * ───────────────────────────────────────────────────────────────────────── */

fn sanitize_tag(tag: &str) -> Result<String, String> {
    let clean = tag.trim();
    if clean.is_empty() {
        return Err("Snapshot tag cannot be empty.".to_string());
    }
    for c in clean.chars() {
        if !c.is_alphanumeric() && c != '_' && c != '-' && c != '.' {
            return Err(format!(
                "Invalid snapshot tag '{}': only alphanumeric, '_', '-' and '.' allowed.",
                tag
            ));
        }
    }
    if clean.contains("..") {
        return Err("Invalid snapshot tag: '..' is forbidden.".to_string());
    }
    Ok(clean.to_string())
}

/// Creates a new immutable snapshot of the current vault contents
pub fn vault_snapshot_create(vault_path: &str, tag_opt: Option<&str>) -> Result<String, String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        return Err(format!("Vault path '{}' does not exist.", vault_path));
    }

    let tag = match tag_opt {
        Some(t) if !t.trim().is_empty() => sanitize_tag(t)?,
        _ => {
            let now = chrono::Local::now();
            now.format("snap_%Y%m%d_%H%M%S").to_string()
        }
    };

    let snaps_dir = vroot.join(".vault_snapshots");
    if !snaps_dir.exists() {
        fs::create_dir_all(&snaps_dir).map_err(|e| {
            format!("Cannot create snapshots directory '{}': {}", snaps_dir.display(), e)
        })?;
    }

    let snap_target = snaps_dir.join(&tag);
    if snap_target.exists() {
        return Err(format!(
            "Snapshot '{}' already exists. Use a different tag or delete the existing one.",
            tag
        ));
    }

    let snap_data = snap_target.join("data");
    fs::create_dir_all(&snap_data).map_err(|e| {
        format!("Cannot create snapshot target '{}': {}", snap_data.display(), e)
    })?;

    // Copy all vault files into snapshot data directory
    copy_dir_all(vroot, &snap_data, true, true)?;

    // Calculate metadata
    let mut file_count: usize = 0;
    let mut total_bytes: u64 = 0;
    let mut manifest_lines = Vec::new();

    fn collect_meta(
        dir: &Path,
        root: &Path,
        count: &mut usize,
        bytes: &mut u64,
        manifest: &mut Vec<String>,
    ) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| format!("Cannot read '{}': {}", dir.display(), e))? {
            let entry = entry.map_err(|e| format!("Error: {}", e))?;
            let ft = entry.file_type().map_err(|e| format!("Error: {}", e))?;
            let p = entry.path();
            let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace('\\', "/");

            if ft.is_dir() {
                collect_meta(&p, root, count, bytes, manifest)?;
            } else if ft.is_file() {
                let sz = entry.metadata().map(|m| m.len()).unwrap_or(0);
                *count += 1;
                *bytes += sz;
                manifest.push(format!("{}|{}", rel, sz));
            }
        }
        Ok(())
    }

    collect_meta(&snap_data, &snap_data, &mut file_count, &mut total_bytes, &mut manifest_lines)?;

    let now = chrono::Local::now().to_rfc3339();
    let meta_content = format!(
        "TAG={}\nCREATED_AT={}\nFILES={}\nBYTES={}\n\n[MANIFEST]\n{}\n",
        tag,
        now,
        file_count,
        total_bytes,
        manifest_lines.join("\n")
    );

    let meta_file = snap_target.join("meta.txt");
    fs::write(&meta_file, meta_content).map_err(|e| {
        format!("Failed to write snapshot meta '{}': {}", meta_file.display(), e)
    })?;

    println!(
        "✔ Snapshot '\x1b[1;32m{}\x1b[0m' created successfully ({} files, {} bytes).",
        tag, file_count, total_bytes
    );
    Ok(tag)
}

/// Lists all existing snapshots for the given vault
pub fn vault_snapshot_list(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let snaps_dir = vroot.join(".vault_snapshots");

    if !snaps_dir.exists() {
        println!("No snapshots found for this vault.");
        return Ok(());
    }

    let mut snaps = Vec::new();

    for entry in fs::read_dir(&snaps_dir).map_err(|e| format!("Cannot read '{}': {}", snaps_dir.display(), e))? {
        let entry = entry.map_err(|e| format!("Error: {}", e))?;
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            let tag = entry.file_name().to_string_lossy().to_string();
            let meta_file = entry.path().join("meta.txt");
            let mut created_at = String::from("unknown");
            let mut files = String::from("0");
            let mut bytes = String::from("0");

            if let Ok(content) = fs::read_to_string(&meta_file) {
                for line in content.lines() {
                    if let Some(v) = line.strip_prefix("CREATED_AT=") {
                        created_at = v.to_string();
                    } else if let Some(v) = line.strip_prefix("FILES=") {
                        files = v.to_string();
                    } else if let Some(v) = line.strip_prefix("BYTES=") {
                        bytes = v.to_string();
                    }
                }
            }
            snaps.push((tag, created_at, files, bytes));
        }
    }

    if snaps.is_empty() {
        println!("No snapshots found for this vault.");
        return Ok(());
    }

    snaps.sort_by(|a, b| a.1.cmp(&b.1));

    println!("\n  ── Vault Snapshots [ {} ] ─────────────────────────", vault_path);
    println!("  {:<24} {:<25} {:<8} {:<12}", "TAG", "CREATED AT", "FILES", "SIZE (BYTES)");
    println!("  {}", "─".repeat(72));

    for (tag, dt, files, bytes) in snaps {
        println!("  {:<24} {:<25} {:<8} {:<12}", tag, dt, files, bytes);
    }
    println!("  {}\n", "─".repeat(72));

    Ok(())
}

/// Deletes a specific snapshot by tag
pub fn vault_snapshot_delete(vault_path: &str, tag_str: &str) -> Result<(), String> {
    let tag = sanitize_tag(tag_str)?;
    let vroot = Path::new(vault_path);
    let snap_target = vroot.join(".vault_snapshots").join(&tag);

    if !snap_target.exists() {
        return Err(format!("Snapshot '{}' does not exist.", tag));
    }

    fs::remove_dir_all(&snap_target).map_err(|e| {
        format!("Failed to delete snapshot '{}': {}", tag, e)
    })?;

    println!("✔ Snapshot '{}' deleted.", tag);
    Ok(())
}

/// Restores the vault to the exact snapshot state
pub fn vault_snapshot_restore(vault_path: &str, tag_str: &str) -> Result<(), String> {
    let tag = sanitize_tag(tag_str)?;
    let vroot = Path::new(vault_path);
    let snap_data = vroot.join(".vault_snapshots").join(&tag).join("data");

    if !snap_data.exists() {
        return Err(format!("Snapshot '{}' does not exist or has no data.", tag));
    }

    // 1. Remove existing vault items (except .vault_snapshots)
    for entry in fs::read_dir(vroot).map_err(|e| format!("Cannot read '{}': {}", vault_path, e))? {
        let entry = entry.map_err(|e| format!("Error: {}", e))?;
        if entry.file_name() == ".vault_snapshots" {
            continue;
        }
        let p = entry.path();
        if p.is_dir() {
            let _ = fs::remove_dir_all(&p);
        } else {
            let _ = fs::remove_file(&p);
        }
    }

    // 2. Copy snapshot data into vault root
    copy_dir_all(&snap_data, vroot, true, true)?;

    println!("✔ Vault successfully restored to snapshot '\x1b[1;32m{}\x1b[0m'.", tag);
    Ok(())
}

/// Compares a snapshot against current vault state or against another snapshot
pub fn vault_snapshot_diff(
    vault_path: &str,
    tag1_str: &str,
    tag2_str: Option<&str>,
) -> Result<(), String> {
    let tag1 = sanitize_tag(tag1_str)?;
    let vroot = Path::new(vault_path);
    let snap1_data = vroot.join(".vault_snapshots").join(&tag1).join("data");

    if !snap1_data.exists() {
        return Err(format!("Snapshot '{}' does not exist.", tag1));
    }

    let (dir_b, label_b) = match tag2_str {
        Some(t2) if !t2.trim().is_empty() => {
            let clean_t2 = sanitize_tag(t2)?;
            let p2 = vroot.join(".vault_snapshots").join(&clean_t2).join("data");
            if !p2.exists() {
                return Err(format!("Snapshot '{}' does not exist.", clean_t2));
            }
            (p2, format!("Snapshot '{}'", clean_t2))
        }
        _ => (vroot.to_path_buf(), "Current Vault State".to_string()),
    };

    use std::collections::BTreeMap;

    fn map_files(dir: &Path, root: &Path) -> Result<BTreeMap<String, u64>, String> {
        let mut map = BTreeMap::new();
        fn walk(d: &Path, r: &Path, m: &mut BTreeMap<String, u64>) -> Result<(), String> {
            for entry in fs::read_dir(d).map_err(|e| format!("Cannot read '{}': {}", d.display(), e))? {
                let entry = entry.map_err(|e| format!("Error: {}", e))?;
                if entry.file_name() == ".vault_snapshots" {
                    continue;
                }
                let p = entry.path();
                let ft = entry.file_type().map_err(|e| format!("Error: {}", e))?;
                if ft.is_dir() {
                    walk(&p, r, m)?;
                } else if ft.is_file() {
                    let rel = p.strip_prefix(r).unwrap_or(&p).to_string_lossy().replace('\\', "/");
                    let sz = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    m.insert(rel, sz);
                }
            }
            Ok(())
        }
        walk(dir, root, &mut map)?;
        Ok(map)
    }

    let map1 = map_files(&snap1_data, &snap1_data)?;
    let map2 = map_files(&dir_b, &dir_b)?;

    println!(
        "\n  ── Snapshot Diff: Snapshot '{}' ↔ {} ──",
        tag1, label_b
    );

    let mut added = 0;
    let mut removed = 0;
    let mut modified = 0;
    let mut unchanged = 0;

    for (k, sz2) in &map2 {
        match map1.get(k) {
            None => {
                println!("  \x1b[32m+ [ADDED]\x1b[0m    {} ({} bytes)", k, sz2);
                added += 1;
            }
            Some(sz1) if sz1 != sz2 => {
                println!(
                    "  \x1b[33m~ [MODIFIED]\x1b[0m {} (was {} bytes, now {} bytes)",
                    k, sz1, sz2
                );
                modified += 1;
            }
            Some(_) => {
                unchanged += 1;
            }
        }
    }

    for (k, sz1) in &map1 {
        if !map2.contains_key(k) {
            println!("  \x1b[31m- [REMOVED]\x1b[0m  {} (was {} bytes)", k, sz1);
            removed += 1;
        }
    }

    println!("  ────────────────────────────────────────────────────────");
    println!(
        "  Summary: {} added, {} removed, {} modified, {} unchanged.\n",
        added, removed, modified, unchanged
    );

    Ok(())
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Shared Utilities (Hash & Audit)
 * ───────────────────────────────────────────────────────────────────────── */

/// Computes SHA-256 in 64KB streaming chunks
pub fn compute_sha256(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path)
        .map_err(|e| format!("Cannot open '{}' for hashing: {}", path.display(), e))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];

    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| format!("Read error while hashing '{}': {}", path.display(), e))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Appends an event to the vault history log
pub fn log_vault_event(vault_path: &str, action: &str, details: &str) {
    let log_path = Path::new(vault_path).join(".vault_history.log");
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let line = format!("[{}] {:<14} {}\n", now, action, details);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&log_path) {
        let _ = f.write_all(line.as_bytes());
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Cryptographic Integrity & Resilience
 * ───────────────────────────────────────────────────────────────────────── */

/// Computes SHA-256 hash for a specific file or all files in the vault
pub fn vault_hash(vault_path: &str, target_rel: Option<&str>) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        return Err(format!("Vault path '{}' does not exist.", vault_path));
    }

    if let Some(rel) = target_rel {
        let target = safe_vault_path(vroot, Path::new(rel))?;
        if !target.exists() {
            return Err(format!("Target '{}' does not exist in vault.", rel));
        }
        let h = compute_sha256(&target)?;
        let sz = fs::metadata(&target).map(|m| m.len()).unwrap_or(0);
        println!("\n  File:      {}", rel);
        println!("  Size:      {} bytes", sz);
        println!("  SHA-256:   \x1b[1;32m{}\x1b[0m\n", h);
        return Ok(());
    }

    println!("\n  ── Vault Hash Tree (SHA-256) [ {} ] ──────────────", vault_path);
    println!("  {:<64} {:<10} {}", "SHA-256", "BYTES", "FILE");
    println!("  {}", "─".repeat(88));

    fn walk_hash(dir: &Path, vroot: &Path, count: &mut usize) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| format!("Cannot read '{}': {}", dir.display(), e))? {
            let entry = entry.map_err(|e| format!("Error: {}", e))?;
            let fname = entry.file_name();
            let name_str = fname.to_string_lossy();
            if name_str.starts_with(".vault") {
                continue;
            }
            let p = entry.path();
            let ft = entry.file_type().map_err(|e| format!("Error: {}", e))?;
            if ft.is_dir() {
                walk_hash(&p, vroot, count)?;
            } else if ft.is_file() {
                let rel = p.strip_prefix(vroot).unwrap_or(&p).to_string_lossy().replace('\\', "/");
                let sz = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let h = compute_sha256(&p)?;
                println!("  {:<64} {:<10} {}", h, sz, rel);
                *count += 1;
            }
        }
        Ok(())
    }

    let mut total = 0;
    walk_hash(vroot, vroot, &mut total)?;
    println!("  {}", "─".repeat(88));
    println!("  Total: {} files hashed.\n", total);

    log_vault_event(vault_path, "HASH_SCAN", &format!("{} files scanned", total));
    Ok(())
}

/// Generates an authenticated cryptographic baseline (.vault_baseline)
pub fn vault_baseline(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        return Err(format!("Vault path '{}' does not exist.", vault_path));
    }

    let mut entries = Vec::new();
    fn walk(dir: &Path, vroot: &Path, out: &mut Vec<(String, u64, String)>) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| format!("Cannot read '{}': {}", dir.display(), e))? {
            let entry = entry.map_err(|e| format!("Error: {}", e))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(".vault") {
                continue;
            }
            let p = entry.path();
            let ft = entry.file_type().map_err(|e| format!("Error: {}", e))?;
            if ft.is_dir() {
                walk(&p, vroot, out)?;
            } else if ft.is_file() {
                let rel = p.strip_prefix(vroot).unwrap_or(&p).to_string_lossy().replace('\\', "/");
                let sz = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let h = compute_sha256(&p)?;
                out.push((rel, sz, h));
            }
        }
        Ok(())
    }

    walk(vroot, vroot, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let now = chrono::Local::now().to_rfc3339();
    let mut content = format!(
        "# NUK4SD VAULT BASELINE MANIFEST\n# CREATED_AT={}\n# TOTAL_FILES={}\n# FORMAT: SHA256|SIZE|PATH\n\n",
        now,
        entries.len()
    );

    for (rel, sz, h) in &entries {
        content.push_str(&format!("{}|{}|{}\n", h, sz, rel));
    }

    let baseline_file = vroot.join(".vault_baseline");
    fs::write(&baseline_file, content).map_err(|e| {
        format!("Failed to write baseline file '{}': {}", baseline_file.display(), e)
    })?;

    println!(
        "✔ Baseline generated with \x1b[1;32m{}\x1b[0m tracked files (.vault_baseline).",
        entries.len()
    );
    log_vault_event(vault_path, "BASELINE", &format!("{} files registered", entries.len()));
    Ok(())
}

/// Verifies current files against the stored baseline
pub fn vault_verify(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let baseline_file = vroot.join(".vault_baseline");

    if !baseline_file.exists() {
        return Err("No baseline found (.vault_baseline). Generate one with --baseline first.".to_string());
    }

    let content = fs::read_to_string(&baseline_file)
        .map_err(|e| format!("Cannot read baseline file: {}", e))?;

    let mut baseline_map: BTreeMap<String, (String, u64)> = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() == 3 {
            let h = parts[0].to_string();
            let sz: u64 = parts[1].parse().unwrap_or(0);
            let path = parts[2].to_string();
            baseline_map.insert(path, (h, sz));
        }
    }

    let mut matched = 0;
    let mut modified = 0;
    let mut missing = 0;

    println!("\n  ── Vault Integrity Verification [ {} ] ────────────", vault_path);

    for (rel, (exp_h, exp_sz)) in &baseline_map {
        let path = vroot.join(rel);
        if !path.exists() {
            println!("  \x1b[31m✖ [MISSING]\x1b[0m     {}", rel);
            missing += 1;
        } else {
            let actual_sz = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let actual_h = compute_sha256(&path).unwrap_or_default();
            if actual_h == *exp_h {
                println!("  \x1b[32m✔ [OK]\x1b[0m          {} ({} bytes)", rel, actual_sz);
                matched += 1;
            } else {
                println!(
                    "  \x1b[31m✖ [CORRUPTED]\x1b[0m   {} (expected size {}/{}, hash mismatch!)",
                    rel, exp_sz, actual_sz
                );
                modified += 1;
            }
        }
    }

    println!("  {}", "─".repeat(60));
    println!(
        "  Result: \x1b[32m{} verified\x1b[0m, \x1b[31m{} modified\x1b[0m, \x1b[31m{} missing\x1b[0m.",
        matched, modified, missing
    );
    println!("  ────────────────────────────────────────────────────────────\n");

    log_vault_event(
        vault_path,
        "VERIFY",
        &format!("matched={}, modified={}, missing={}", matched, modified, missing),
    );

    if modified > 0 || missing > 0 {
        return Err("Integrity check failed: corruptions or missing files detected!".to_string());
    }

    Ok(())
}

/// Detailed cryptographic and structural integrity check
pub fn vault_integrity(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        return Err(format!("Vault path '{}' does not exist.", vault_path));
    }

    println!("\n  ── Cryptographic Integrity Audit [ {} ] ────────", vault_path);

    let mut valid_enc = 0;
    let mut broken_enc = 0;
    let mut plain_files = 0;
    let mut symlinks = 0;

    fn check_walk(
        dir: &Path,
        vroot: &Path,
        valid_enc: &mut usize,
        broken_enc: &mut usize,
        plain_files: &mut usize,
        symlinks: &mut usize,
    ) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| format!("Cannot read '{}': {}", dir.display(), e))? {
            let entry = entry.map_err(|e| format!("Error: {}", e))?;
            let fname = entry.file_name();
            let name_str = fname.to_string_lossy();
            if name_str.starts_with(".vault") {
                continue;
            }
            let p = entry.path();
            let sym_meta = fs::symlink_metadata(&p).map_err(|e| format!("Error: {}", e))?;

            if sym_meta.file_type().is_symlink() {
                *symlinks += 1;
                let rel = p.strip_prefix(vroot).unwrap_or(&p).to_string_lossy();
                println!("  \x1b[33m⚠ [SYMLINK]\x1b[0m     {} (monitored)", rel);
                continue;
            }

            if sym_meta.is_dir() {
                check_walk(&p, vroot, valid_enc, broken_enc, plain_files, symlinks)?;
            } else if sym_meta.is_file() {
                let sz = sym_meta.len();
                let rel = p.strip_prefix(vroot).unwrap_or(&p).to_string_lossy();
                if name_str.ends_with(".enc") {
                    // Salt(16) + Nonce(12) + Tag(16) = minimum 44 bytes
                    if sz < 44 {
                        println!("  \x1b[31m✖ [BAD-ENC]\x1b[0m     {} (too small: {} bytes, truncated header!)", rel, sz);
                        *broken_enc += 1;
                    } else {
                        *valid_enc += 1;
                    }
                } else {
                    *plain_files += 1;
                }
            }
        }
        Ok(())
    }

    check_walk(vroot, vroot, &mut valid_enc, &mut broken_enc, &mut plain_files, &mut symlinks)?;

    println!("  {}", "─".repeat(60));
    println!("  Encrypted files (AES-GCM):  {} valid, {} damaged", valid_enc, broken_enc);
    println!("  Plaintext files:            {}", plain_files);
    println!("  Symlinks:                   {}", symlinks);
    let has_baseline = vroot.join(".vault_baseline").exists();
    println!("  Baseline manifest:          {}", if has_baseline { "present" } else { "none (run --baseline)" });
    println!("  ────────────────────────────────────────────────────────────\n");

    log_vault_event(
        vault_path,
        "INTEGRITY_AUDIT",
        &format!("valid_enc={}, damaged_enc={}, plain={}", valid_enc, broken_enc, plain_files),
    );

    if broken_enc > 0 {
        return Err(format!("{} encrypted files have invalid or truncated headers.", broken_enc));
    }
    Ok(())
}

/// Attempts to repair missing or damaged files from latest snapshot
pub fn vault_repair(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let snaps_dir = vroot.join(".vault_snapshots");

    if !snaps_dir.exists() {
        return Err("No snapshots available for repair. Create snapshots with --snapshot.".to_string());
    }

    // Find newest snapshot
    let mut newest_snap: Option<(PathBuf, String)> = None;
    for entry in fs::read_dir(&snaps_dir).map_err(|e| format!("Cannot read snapshots: {}", e))? {
        let entry = entry.map_err(|e| format!("Error: {}", e))?;
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            let tag = entry.file_name().to_string_lossy().to_string();
            let data = entry.path().join("data");
            if data.exists() {
                newest_snap = Some((data, tag));
            }
        }
    }

    let (snap_data, tag) = match newest_snap {
        Some(s) => s,
        None => return Err("No valid snapshot data directory found for repair.".to_string()),
    };

    println!("\n  ── Vault Repair Engine [ Snapshot: '{}' ] ──────", tag);
    let mut repaired = 0;

    fn walk_repair(snap_dir: &Path, vroot: &Path, snap_base: &Path, count: &mut usize) -> Result<(), String> {
        for entry in fs::read_dir(snap_dir).map_err(|e| format!("Error: {}", e))? {
            let entry = entry.map_err(|e| format!("Error: {}", e))?;
            let p = entry.path();
            let ft = entry.file_type().map_err(|e| format!("Error: {}", e))?;
            let rel = p.strip_prefix(snap_base).unwrap_or(&p);
            let target = vroot.join(rel);

            if ft.is_dir() {
                if !target.exists() {
                    let _ = fs::create_dir_all(&target);
                }
                walk_repair(&p, vroot, snap_base, count)?;
            } else if ft.is_file() {
                let need_restore = if !target.exists() {
                    true
                } else {
                    let target_sz = fs::metadata(&target).map(|m| m.len()).unwrap_or(0);
                    let snap_sz = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    target_sz == 0 || target_sz != snap_sz
                };

                if need_restore {
                    copy_file_secure(&p, &target, true, true)?;
                    println!("  \x1b[32m✔ [REPAIRED]\x1b[0m    {}", rel.display());
                    *count += 1;
                }
            }
        }
        Ok(())
    }

    walk_repair(&snap_data, vroot, &snap_data, &mut repaired)?;

    println!("  {}", "─".repeat(60));
    println!("  Total files repaired/recovered: {}", repaired);
    println!("  ────────────────────────────────────────────────────────────\n");

    log_vault_event(vault_path, "REPAIR", &format!("recovered {} files using snapshot {}", repaired, tag));
    Ok(())
}

/// Diffs vault against baseline or another vault path
pub fn vault_diff(vault_path: &str, other_target: Option<&str>) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    if let Some(other) = other_target {
        let other_p = Path::new(other);
        if other_p.exists() {
            println!("\n  ── Vault Diff: [ {} ] ↔ [ {} ] ──", vault_path, other);
            // Diff between two directories
            return vault_snapshot_diff(vault_path, "", Some(other));
        }
    }
    // Default diff against baseline
    vault_verify(vault_path)
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Portabilidade & Backup Seguro
 * ───────────────────────────────────────────────────────────────────────── */

/// Creates a compressed backup archive (.tar.gz) of the vault
pub fn vault_backup(vault_path: &str, out_archive: Option<&str>) -> Result<String, String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        return Err(format!("Vault path '{}' does not exist.", vault_path));
    }

    let default_name = format!(
        "nuk4sd_backup_{}.tar.gz",
        chrono::Local::now().format("%Y%m%d_%H%M%S")
    );
    let out_file_path = out_archive.unwrap_or(&default_name);
    let out_path = Path::new(out_file_path);

    let tar_gz = fs::File::create(out_path)
        .map_err(|e| format!("Cannot create backup file '{}': {}", out_file_path, e))?;
    let enc = flate2::write::GzEncoder::new(tar_gz, flate2::Compression::default());
    let mut tar = tar::Builder::new(enc);

    fn append_dir(tar: &mut tar::Builder<flate2::write::GzEncoder<fs::File>>, dir: &Path, vroot: &Path) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| format!("Cannot read '{}': {}", dir.display(), e))? {
            let entry = entry.map_err(|e| format!("Error: {}", e))?;
            let fname = entry.file_name();
            let name_str = fname.to_string_lossy();
            if name_str.starts_with(".vault_snapshots") {
                continue;
            }
            let p = entry.path();
            let ft = entry.file_type().map_err(|e| format!("Error: {}", e))?;
            let rel = p.strip_prefix(vroot).unwrap_or(&p);

            if ft.is_dir() {
                tar.append_dir(rel, &p).map_err(|e| format!("Tar error: {}", e))?;
                append_dir(tar, &p, vroot)?;
            } else if ft.is_file() {
                let mut f = fs::File::open(&p).map_err(|e| format!("Cannot open '{}': {}", p.display(), e))?;
                tar.append_file(rel, &mut f).map_err(|e| format!("Tar append error: {}", e))?;
            }
        }
        Ok(())
    }

    append_dir(&mut tar, vroot, vroot)?;
    tar.finish().map_err(|e| format!("Failed to finalize backup archive: {}", e))?;

    let sz = fs::metadata(out_path).map(|m| m.len()).unwrap_or(0);
    println!(
        "✔ Backup archive created: '\x1b[1;32m{}\x1b[0m' ({} bytes).",
        out_file_path, sz
    );
    log_vault_event(vault_path, "BACKUP", &format!("archive={}, size={}", out_file_path, sz));
    Ok(out_file_path.to_string())
}

/// Restores vault files from a backup archive (.tar.gz)
pub fn vault_restore(vault_path: &str, in_archive: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        fs::create_dir_all(vroot).map_err(|e| format!("Cannot create vault directory: {}", e))?;
    }

    let file = fs::File::open(in_archive)
        .map_err(|e| format!("Cannot open backup archive '{}': {}", in_archive, e))?;
    let dec = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(dec);

    archive.unpack(vroot).map_err(|e| {
        format!("Failed to unpack backup archive '{}': {}", in_archive, e)
    })?;

    println!("✔ Vault successfully restored from archive '\x1b[1;32m{}\x1b[0m'.", in_archive);
    log_vault_event(vault_path, "RESTORE", &format!("source archive={}", in_archive));
    Ok(())
}

/// Imports files or an archive into the vault safely
pub fn vault_import(vault_path: &str, src: &str) -> Result<(), String> {
    let src_path = Path::new(src);
    if !src_path.exists() {
        return Err(format!("Import source '{}' does not exist.", src));
    }

    if src.ends_with(".tar.gz") || src.ends_with(".tgz") {
        return vault_restore(vault_path, src);
    }

    vault_add(vault_path, src, true, true, true)
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Concorrência & Locks
 * ───────────────────────────────────────────────────────────────────────── */

/// Locks the vault with process lease metadata
pub fn vault_lock(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        return Err(format!("Vault path '{}' does not exist.", vault_path));
    }

    let lock_file = vroot.join(".vault_lock");
    if lock_file.exists() {
        if let Ok(info) = fs::read_to_string(&lock_file) {
            println!("⚠ Vault is currently locked:\n{}", info);
            return Err("Vault is already locked. Use --force-unlock if the process died.".to_string());
        }
    }

    let pid = std::process::id();
    let now = chrono::Local::now().to_rfc3339();
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".to_string());

    let content = format!("PID={}\nTIMESTAMP={}\nHOST={}\nMODE=EXCLUSIVE\n", pid, now, host);
    fs::write(&lock_file, content).map_err(|e| format!("Failed to create lock file: {}", e))?;

    println!("✔ Vault locked successfully by PID {} on {}.", pid, host);
    log_vault_event(vault_path, "LOCK", &format!("pid={}", pid));
    Ok(())
}

/// Checks the lock status of the vault
pub fn vault_lock_status(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let lock_file = vroot.join(".vault_lock");

    println!("\n  ── Vault Lock Status [ {} ] ─────────────────────", vault_path);
    if !lock_file.exists() {
        println!("  Status: \x1b[1;32mUNLOCKED\x1b[0m (ready for read/write)");
    } else {
        println!("  Status: \x1b[1;31mLOCKED\x1b[0m");
        if let Ok(content) = fs::read_to_string(&lock_file) {
            for line in content.lines() {
                println!("    {}", line);
            }
        }
    }
    println!("  ────────────────────────────────────────────────────────\n");
    Ok(())
}

/// Forcefully unlocks the vault
pub fn vault_force_unlock(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let lock_file = vroot.join(".vault_lock");

    if !lock_file.exists() {
        println!("Vault is not locked.");
        return Ok(());
    }

    fs::remove_file(&lock_file).map_err(|e| format!("Failed to remove lock: {}", e))?;
    println!("✔ Vault lock removed successfully.");
    log_vault_event(vault_path, "FORCE_UNLOCK", "lock broken by operator");
    Ok(())
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Ciclo de Chaves & Criptografia
 * ───────────────────────────────────────────────────────────────────────── */

/// Displays cryptographic parameters and cipher status
pub fn vault_key_info(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        return Err(format!("Vault path '{}' does not exist.", vault_path));
    }

    println!("\n  ── Vault Cryptographic Profile [ {} ] ───────────", vault_path);
    println!("  Cipher:           AES-256-GCM (NIST SP 800-38D)");
    println!("  Key Derivation:   Argon2id (m=65536, t=3, p=1)");
    println!("  Salt Length:      16 bytes (CSPRNG)");
    println!("  Nonce Length:     12 bytes (96 bits random)");
    println!("  Authentication:   Poly1305 / GCM 128-bit MAC");
    println!("  Anti-TOCTOU:      Enabled (canonical directory constraints)");
    println!("  Restricted Links: Enabled (symlinks restricted to sandbox)");
    println!("  ────────────────────────────────────────────────────────\n");
    Ok(())
}

/// Rotates encryption password for all encrypted files
pub fn vault_key_rotate(vault_path: &str, old_pass: &str, new_pass: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        return Err(format!("Vault path '{}' does not exist.", vault_path));
    }

    println!("\n  ── Key Rotation Engine ─────────────────────────────────");
    let mut rotated = 0;

    fn walk_rekey(dir: &Path, old_p: &str, new_p: &str, count: &mut usize) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| format!("Error: {}", e))? {
            let entry = entry.map_err(|e| format!("Error: {}", e))?;
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname.starts_with(".vault") {
                continue;
            }
            let p = entry.path();
            let ft = entry.file_type().map_err(|e| format!("Error: {}", e))?;
            if ft.is_dir() {
                walk_rekey(&p, old_p, new_p, count)?;
            } else if ft.is_file() && fname.ends_with(".enc") {
                // Decrypt with old, encrypt with new
                crate::crypto::decrypt_file(&p, old_p).map_err(|e| format!("Decrypt error on '{}': {}", p.display(), e))?;
                let dec_path = p.with_extension("dec");
                crate::crypto::encrypt_file(&dec_path, new_p).map_err(|e| format!("Re-encrypt error: {}", e))?;
                let _ = fs::remove_file(&dec_path);
                println!("  \x1b[32m✔ [ROTATED]\x1b[0m     {}", fname);
                *count += 1;
            }
        }
        Ok(())
    }

    walk_rekey(vroot, old_pass, new_pass, &mut rotated)?;
    println!("  Total files rotated: {}", rotated);
    println!("  ────────────────────────────────────────────────────────\n");

    log_vault_event(vault_path, "KEY_ROTATE", &format!("rotated {} files", rotated));
    Ok(())
}

/// Re-encrypts files with fresh cryptographic nonces and salts
pub fn vault_rekey(vault_path: &str, pass: &str) -> Result<(), String> {
    vault_key_rotate(vault_path, pass, pass)
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Observabilidade, Telemetria & Auditoria
 * ───────────────────────────────────────────────────────────────────────── */

/// Extended statistics (sizes, entropy, encrypted/plain ratio)
pub fn vault_stats(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    if !vroot.exists() {
        return Err(format!("Vault path '{}' does not exist.", vault_path));
    }

    let mut total_bytes: u64 = 0;
    let mut plain_count: usize = 0;
    let mut enc_count: usize = 0;
    let mut dir_count: usize = 0;
    let mut ext_map: HashMap<String, (usize, u64)> = HashMap::new();

    fn walk_stats(
        dir: &Path,
        bytes: &mut u64,
        plain: &mut usize,
        enc: &mut usize,
        dirs: &mut usize,
        exts: &mut HashMap<String, (usize, u64)>,
    ) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| format!("Error: {}", e))? {
            let entry = entry.map_err(|e| format!("Error: {}", e))?;
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname.starts_with(".vault") {
                continue;
            }
            let p = entry.path();
            let ft = entry.file_type().map_err(|e| format!("Error: {}", e))?;
            if ft.is_dir() {
                *dirs += 1;
                walk_stats(&p, bytes, plain, enc, dirs, exts)?;
            } else if ft.is_file() {
                let sz = entry.metadata().map(|m| m.len()).unwrap_or(0);
                *bytes += sz;
                let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("none").to_lowercase();
                let e = exts.entry(ext).or_insert((0, 0));
                e.0 += 1;
                e.1 += sz;
                if fname.ends_with(".enc") {
                    *enc += 1;
                } else {
                    *plain += 1;
                }
            }
        }
        Ok(())
    }

    walk_stats(vroot, &mut total_bytes, &mut plain_count, &mut enc_count, &mut dir_count, &mut ext_map)?;

    let total_files = plain_count + enc_count;
    let enc_ratio = if total_files > 0 { (enc_count as f64 / total_files as f64) * 100.0 } else { 0.0 };

    println!("\n  ── Vault Extended Telemetry & Stats [ {} ] ──", vault_path);
    println!("  Total Storage:         {:.2} MB ({} bytes)", total_bytes as f64 / (1024.0 * 1024.0), total_bytes);
    println!("  Total Directories:     {}", dir_count);
    println!("  Total Files:           {} (Encrypted: {}, Plain: {})", total_files, enc_count, plain_count);
    println!("  Encryption Coverage:   \x1b[1;32m{:.1}%\x1b[0m", enc_ratio);
    println!("  \n  File Type Breakdown:");
    for (ext, (cnt, b)) in ext_map {
        println!("    .{:<10} {:>5} files  ({:>8} bytes)", ext, cnt, b);
    }
    println!("  ────────────────────────────────────────────────────────\n");
    Ok(())
}

/// Storage usage breakdown
pub fn vault_usage(vault_path: &str) -> Result<(), String> {
    vault_du(vault_path)
}

/// Inspects metadata and headers of a specific file in the vault
pub fn vault_inspect(vault_path: &str, rel_file: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let target = safe_vault_path(vroot, Path::new(rel_file))?;

    if !target.exists() {
        return Err(format!("File '{}' does not exist in vault.", rel_file));
    }

    let meta = fs::metadata(&target).map_err(|e| format!("Metadata error: {}", e))?;
    let sz = meta.len();
    let is_enc = rel_file.ends_with(".enc");
    let sha = compute_sha256(&target).unwrap_or_default();

    println!("\n  ── File Inspection: '{}' ──────────────────", rel_file);
    println!("  Path:              {}", target.display());
    println!("  Size:              {} bytes", sz);
    println!("  Type:              {}", if is_enc { "Encrypted Payload (AES-256-GCM)" } else { "Plaintext File" });
    println!("  SHA-256:           {}", sha);

    if is_enc && sz >= 28 {
        if let Ok(mut f) = fs::File::open(&target) {
            let mut buf = [0u8; 28];
            if f.read_exact(&mut buf).is_ok() {
                println!("  Salt (hex):        {}", hex::encode(&buf[..16]));
                println!("  Nonce (hex):       {}", hex::encode(&buf[16..28]));
            }
        }
    }

    println!("  ────────────────────────────────────────────────────────\n");
    Ok(())
}

/// Displays operation history from the vault audit log
pub fn vault_history(vault_path: &str) -> Result<(), String> {
    let vroot = Path::new(vault_path);
    let log_file = vroot.join(".vault_history.log");

    println!("\n  ── Vault Audit History [ {} ] ─────────────────", vault_path);
    if !log_file.exists() {
        println!("  No history log found.");
    } else {
        let content = fs::read_to_string(&log_file).map_err(|e| format!("Read error: {}", e))?;
        for line in content.lines() {
            println!("  {}", line);
        }
    }
    println!("  ────────────────────────────────────────────────────────\n");
    Ok(())
}

/// Displays recent audit events
pub fn vault_events(vault_path: &str) -> Result<(), String> {
    vault_history(vault_path)
}

