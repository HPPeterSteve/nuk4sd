use colored::*;
use inquire::Select;
use std::fs;
use std::path::{Path, PathBuf};
use std::io::IsTerminal;

/// Calcula a distância de Levenshtein entre duas strings para fuzzy matching.
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

/// Tenta encontrar um caminho similar se o original não existir.
/// Agora com tratamento de erros mais robusto e mensagens informativas.
#[allow(dead_code)]
pub fn get_valid_path(input: &str, is_dir: bool) -> Option<PathBuf> {
    let path = PathBuf::from(input);

    if path.exists() {
        return Some(path);
    }

    if std::env::args().len() > 1 {
        eprintln!(
            "{}",
            format!("✖ O caminho '{}' não foi encontrado.", input).yellow()
        );
        return None;
    }

    println!(
        "{}",
        format!("⚠ O caminho '{}' não foi encontrado.", input).yellow()
    );

    // Buscar sugestões no diretório pai ou atual
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));

    // Tratamento de erro explícito ao ler diretório
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
                "✖ Não foi possível extrair o nome do arquivo/diretório do caminho fornecido."
                    .red()
            );
            return None;
        }
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();

        // Filtro robusto por tipo (diretório ou arquivo)
        if is_dir && !entry_path.is_dir() {
            continue;
        }
        if !is_dir && !entry_path.is_file() {
            continue;
        }

        if let Some(name) = entry_path.file_name().and_then(|n| n.to_str()) {
            let dist = levenshtein_distance(target_name, name);
            // Lógica de sugestão: distância de Levenshtein ou contenção de substring
            if dist <= 3 || name.contains(target_name) || target_name.contains(name) {
                suggestions.push(entry_path);
            }
        }
    }

    if suggestions.is_empty() {
        println!("{}", "✖ Nenhuma sugestão próxima encontrada.".red());
        return None;
    }

    // Se houver apenas uma sugestão muito próxima, perguntar de forma amigável
    if suggestions.len() == 1 {
        let sug = &suggestions[0];
        let prompt = format!("Você quis dizer '{}'?", sug.display());
        let options = vec!["Sim", "Não"];
        let ans = Select::new(&prompt, options).prompt().ok()?;

        if ans == "Sim" {
            return Some(sug.clone());
        }
    } else {
        // Se houver várias, deixar escolher interativamente
        let mut options: Vec<String> = suggestions
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        options.push("Nenhum destes".to_string());

        let ans = Select::new(
            "Vários caminhos parecidos encontrados. Escolha um:",
            options,
        )
        .prompt()
        .ok()?;
        if ans != "Nenhum destes" {
            return Some(PathBuf::from(ans));
        }
    }

    None
}

/// Garante que o usuário forneça um caminho válido, seja via argumento ou interativamente.
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
            format!("✖ Erro: Caminho não fornecido ou inválido (Modo CLI).").red()
        );
        return None;
    }

    // Se não foi fornecido ou o fornecido era inválido, tentar o rfd
    println!("{}", format!("➜ {}", prompt).cyan());
    println!(
        "{}",
        "(Abrindo janela de seleção... caso não abra, digite o caminho abaixo)".dimmed()
    );

    let picked = if std::io::stdin().is_terminal() {
        if is_dir {
            rfd::FileDialog::new().pick_folder()
        } else {
            rfd::FileDialog::new().pick_file()
        }
    } else {
        None
    };

    if let Some(p) = picked {
        println!("{}", format!("✔ Selecionado: {}", p.display()).green());
        return Some(p);
    }

    // Fallback: Se o usuário cancelou a janela gráfica ou falhou (ex: WSL)
    let input = if std::io::stdin().is_terminal() {
        match inquire::Text::new(prompt).prompt() {
            Ok(text) => text,
            Err(_) => return None, // Usuário cancelou ou erro no prompt
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
