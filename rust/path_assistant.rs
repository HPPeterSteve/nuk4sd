use colored::*;
use inquire::Select;
use std::fs;
use std::path::{Path, PathBuf};
use std::io::IsTerminal;

/// Computes Levenshtein distance between two strings for fuzzy matching.
#[allow(dead_code)]
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    let m = s1_chars.len();
    let n = s2_chars.len();
    let mut dp = vec![vec![0; n + 1]; m + 1];

    for i in 0..=m {
        dp[i][0] = i;
    }
    for j in 0..=n {
        dp[0][j] = j;
    }

    for i in 1..=m {
        for j in 1..=n {
            if s1_chars[i - 1] == s2_chars[j - 1] {
                dp[i][j] = dp[i - 1][j - 1];
            } else {
                dp[i][j] = 1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1]);
            }
        }
    }
    dp[m][n]
}

/// Attempts to find a similar path if the original path does not exist.
/// Features robust error handling and informative messages.
#[allow(dead_code)]
pub fn get_valid_path(input: &str, is_dir: bool) -> Option<PathBuf> {
    let path = PathBuf::from(input);

    if path.exists() {
        return Some(path);
    }

    if std::env::args().len() > 1 {
        eprintln!(
            "{}",
            format!("✖ Path '{}' was not found.", input).yellow()
        );
        return None;
    }

    println!(
        "{}",
        format!("⚠ Path '{}' was not found.", input).yellow()
    );

    // Search for suggestions in parent or current directory
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));

    // Explicit error handling when reading directory
    let entries = match fs::read_dir(parent) {
        Ok(e) => e,
        Err(e) => {
            eprintln!(
                "{}",
                format!(
                    "✖ Error accessing parent directory '{}': {}",
                    parent.display(),
                    e
                )
                .red()
            );
            return None;
        }
    };

    let mut suggestions = Vec::new();
    let target_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => {
            eprintln!(
                "{}",
                "✖ Failed to extract file/directory name from provided path."
                    .red()
            );
            return None;
        }
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();

        // Robust filter by type (directory or file)
        if is_dir && !entry_path.is_dir() {
            continue;
        }
        if !is_dir && !entry_path.is_file() {
            continue;
        }

        if let Some(name) = entry_path.file_name().and_then(|n| n.to_str()) {
            let dist = levenshtein_distance(target_name, name);
            // Suggestion logic: Levenshtein distance or substring containment
            if dist <= 3 || name.contains(target_name) || target_name.contains(name) {
                suggestions.push(entry_path);
            }
        }
    }

    if suggestions.is_empty() {
        println!("{}", "✖ No close suggestions found.".red());
        return None;
    }

    // If there is only one close suggestion, ask interactively
    if suggestions.len() == 1 {
        let sug = &suggestions[0];
        let prompt = format!("Did you mean '{}'?", sug.display());
        let options = vec!["Yes", "No"];
        let ans = Select::new(&prompt, options).prompt().ok()?;

        if ans == "Yes" {
            return Some(sug.clone());
        }
    } else {
        // If multiple suggestions exist, let user choose interactively
        let mut options: Vec<String> = suggestions
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        options.push("None of these".to_string());

        let ans = Select::new(
            "Multiple matching paths found. Choose one:",
            options,
        )
        .prompt()
        .ok()?;
        if ans != "None of these" {
            return Some(PathBuf::from(ans));
        }
    }

    None
}

/// Ensures the user provides a valid path, either via argument or interactively.
#[allow(dead_code)]
pub fn ensure_path(provided: Option<&&str>, prompt: &str, is_dir: bool) -> Option<PathBuf> {
    if let Some(path_str) = provided {
        if let Some(valid) = get_valid_path(path_str, is_dir) {
            return Some(valid);
        }
    }

    if std::env::args().len() > 1 {
        eprintln!(
            "{}",
            format!("✖ Error: Path not provided or invalid (CLI mode).").red()
        );
        return None;
    }

    // If not provided or invalid, attempt fallback prompt
    println!("{}", format!("➜ {}", prompt).cyan());
    let input = if std::io::stdin().is_terminal() {
        match inquire::Text::new(prompt).prompt() {
            Ok(text) => text,
            Err(_) => return None, // User cancelled or prompt error
        }
    } else {
        let mut buf = String::new();
        if std::io::stdin().read_line(&mut buf).is_ok() {
            buf.trim().to_string()
        } else {
            return None;
        }
    };

    if input.trim().is_empty() {
        return None;
    }

    get_valid_path(&input, is_dir)
}
