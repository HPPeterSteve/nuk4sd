/*
 * repl.rs
 *
 * Nuk4sd — modo interativo (REPL)
 *
 * Chamado pelo main.rs quando não há argumentos CLI.
 * Lê comandos linha a linha e converte para argc/argv
 * que são passados ao vault_cli_parse_and_exec do core C.
 *
 * Comandos especiais do REPL (não passam pelo core C):
 *   help      → imprime ajuda rápida
 *   exit/quit → saída
 *   !<cmd>    → executa shell command
 */

use colored::*;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

extern "C" {
    fn vault_cli_parse_and_exec(argc: c_int, argv: *const *const c_char) -> c_int;
}

pub fn run() {
    println!("{}", "Nuk4sd — type --help for commands, exit to quit.".bright_green());

    let mut rl = DefaultEditor::new().unwrap();
    let prompt = "Nuk4sd> ".bright_blue().to_string();

    loop {
        match rl.readline(&prompt) {
            Ok(line) => {
                let input = line.trim();
                if input.is_empty() {
                    continue;
                }
                rl.add_history_entry(input).ok();

                match input {
                    "exit" | "quit" => break,

                    /* Shell passthrough: !ls, !cat arquivo, etc. */
                    s if s.starts_with('!') => {
                        let cmd = &s[1..];
                        let _ = std::process::Command::new("sh").arg("-c").arg(cmd).status();
                    }

                    /* Tudo mais vai pro core C como se fosse argv CLI */
                    _ => {
                        /* Tokeniza respeitando aspas simples e duplas */
                        let tokens = tokenize(input);
                        if tokens.is_empty() {
                            continue;
                        }

                        /* Prefixa com "Nuk4sd" para simular argv[0] */
                        let mut full: Vec<String> = vec!["Nuk4sd".to_string()];
                        full.extend(tokens);

                        let c_args: Vec<CString> = full
                            .iter()
                            .map(|s| CString::new(s.as_str()).unwrap_or_default())
                            .collect();

                        let c_ptrs: Vec<*const c_char> = c_args.iter().map(|s| s.as_ptr()).collect();

                        unsafe {
                            vault_cli_parse_and_exec(c_ptrs.len() as c_int, c_ptrs.as_ptr());
                        }
                    }
                }
            }

            Err(ReadlineError::Interrupted) => {
                println!("{}", "^C".yellow());
                break;
            }
            Err(ReadlineError::Eof) => break,
            Err(err) => {
                eprintln!("readline error: {:?}", err);
                break;
            }
        }
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Tokenizador simples — respeita aspas simples e duplas
 * ───────────── */
fn tokenize(input: &str) -> Vec<String> {
    /* Colapsa continuação de linha estilo shell: um '\' seguido
     * (com espaços em branco opcionais) por '\n' ou '\r\n' é
     * descartado, junto com a quebra de linha, em vez de virar
     * um token literal "\". Isso permite colar comandos
     * multi-linha (paste com '\' no fim de cada linha) sem que
     * a barra sobre como argumento espúrio para o exec. */
    let mut normalized = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' {
            let mut j = i + 1;
            while j < chars.len() && (chars[j] == ' ' || chars[j] == '\t') {
                j += 1;
            }
            if j < chars.len() && (chars[j] == '\n' || chars[j] == '\r') {
                if chars[j] == '\r' && j + 1 < chars.len() && chars[j + 1] == '\n' {
                    j += 1;
                }
                normalized.push(' ');
                i = j + 1;
                continue;
            }
        }
        normalized.push(chars[i]);
        i += 1;
    }

    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;

    for ch in normalized.chars() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ' ' | '\t' | '\n' | '\r' if !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::tokenize;

    #[test]
    fn continuation_backslash_is_dropped() {
        let input = "--run /bin/bash \\\n    --ro /usr --ro /etc \\\n    --ro /root";
        let toks = tokenize(input);
        assert_eq!(
            toks,
            vec!["--run", "/bin/bash", "--ro", "/usr", "--ro", "/etc", "--ro", "/root"]
        );
    }

    #[test]
    fn literal_backslash_inside_quotes_preserved() {
        let toks = tokenize("--path 'C:\\temp'");
        assert_eq!(toks, vec!["--path", "C:\\temp"]);
    }
}
