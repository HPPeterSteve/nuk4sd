use std::{env, process::Command as C};

fn main() {
    let o = env::var("OUT_DIR").unwrap();

    // Resolve include paths via pkg-config when available
    let fuse3_cflags = C::new("pkg-config")
        .args(["--cflags", "fuse3"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_default();

    let openssl_cflags = C::new("pkg-config")
        .args(["--cflags", "openssl"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_default();

    /* ── Vault core ─────────────────────────────────────────────────────────
     * vault_core.h é o header unificado — inclui structs, enums e declarações
     * de todas as subsistemas. Todos os .c abaixo dependem dele via -I. */
    let vault = [
        "c_src/vault/vault_crypto.c",
        "c_src/vault/vault_catalog.c",
        "c_src/vault/vault_monitor.c",
        "c_src/vault/vault_ffi.c",
        "c_src/vault/vault_fuse.c",
        "c_src/vault/vault_health.c",
    ];

    /* ── Sandbox subsystem ──────────────────────────────────────────────────
     * 5-layer defense-in-depth: userns → mounts → pivot_root → caps → seccomp.
     * sandbox.h é o header único do subsistema (estilo Firejail). */
    let sandbox = [
        "c_src/sandbox/caps.c",
        "c_src/sandbox/userns.c",
        "c_src/sandbox/mounts.c",
        "c_src/sandbox/rlimits.c",
        "c_src/sandbox/seccomp.c",
        "c_src/sandbox/landlock.c",
        "c_src/sandbox/jail.c",
        "c_src/sandbox/common.c",
        "c_src/sandbox/net.c",
    ];

    /* ── CLI interface ──────────────────────────────────────────────────────
     * vault_cli.c: parser principal + comandos. vault_cli_log.c: log colorido.
     * preset.h fica em sandbox/ mas é resolvível por todos via -I sandbox. */
    let cli = [
        "c_src/cli/vault_cli.c",
        "c_src/cli/vault_cli_log.c",
    ];

    /* ── Container subsystem ────────────────────────────────────────────────
     * overlay.c: montagem overlayfs com checagem WORM + sealed/whitelist.
     * container.c: funções de política (whitelist exclude/restore). */
    let container = [
        "c_src/container/overlay.c",
        "c_src/container/container.c",
    ];

    /* ── Experimental subsystem ───────────────────────────────────────────── */
    let experimental = [
        "c_src/experimental/nukfile.c",
        "c_src/experimental/nuk_sandbox.c",
    ];

    // Todos os sources num único iterador para o loop de compilação
    let all_sources: Vec<&str> = vault.iter()
        .chain(sandbox.iter())
        .chain(cli.iter())
        .chain(container.iter())
        .chain(experimental.iter())
        .copied()
        .collect();

    let mut x = Vec::new();

    for i in &all_sources {
        let f = i.rsplit('/').next().unwrap();
        let n = &f[..f.len() - 2];
        let p = format!("{}/{}.o", o, n);

        let mut cmd = C::new("gcc");
        cmd.args([
            "-Oz",                          // Máxima otimização de tamanho
            "-fstack-protector-strong",      // FIX auditoria: canaries em TODAS as funções C
            "-D_FORTIFY_SOURCE=3",           // FIX auditoria: fortifica memcpy/memset/vsprintf
            "-fno-asynchronous-unwind-tables",
            "-fno-unwind-tables",
            "-fdata-sections",              // Permite --gc-sections por dado
            "-ffunction-sections",          // Permite --gc-sections por função
            "-fmerge-all-constants",        // Funde constantes duplicadas
            "-fno-ident",                   // Remove .comment com versão do GCC
            "-fvisibility=hidden",          // Oculta símbolos internos do .a
            "-fno-plt",                     // Elimina trampolins PLT desnecessários
            "-fno-exceptions",              // Sem C++ exceptions (proj é C puro)
            "-D_FILE_OFFSET_BITS=64",
            "-DVAULT_FFI_BUILD",
            "-fPIC",
            "-c",
            /* Include paths — um por subdiretório de subsistema.
             * Cada arquivo usa includes simples (#include "vault_core.h", etc.)
             * sem precisar conhecer a localização no tree — o compilador resolve
             * via estas flags na ordem listada.
             *
             * Ordem importa: vault primeiro (vault_core.h é a base de tudo),
             * depois sandbox (sandbox.h inclui vault_core.h), cli e container. */
            "-I", "c_src/vault",
            "-I", "c_src/sandbox",
            "-I", "c_src/cli",
            "-I", "c_src/container",
            "-I", "c_src/experimental",
            i,
            "-o",
            &p,
        ]);

        // Append pkg-config cflags (include dirs) if available
        for flag in fuse3_cflags.split_whitespace() {
            cmd.arg(flag);
        }
        for flag in openssl_cflags.split_whitespace() {
            cmd.arg(flag);
        }

        assert!(cmd.status().unwrap().success());

        x.push(p);
    }

    let l = format!("{}/libvault_security.a", o);

    assert!(C::new("ar")
        .args(["rcs", &l])
        .args(&x)
        .status()
        .unwrap()
        .success());

    println!("cargo:rustc-link-search=native={}", o);
    println!("cargo:rustc-link-lib=static=vault_security");

    println!("cargo:rustc-link-arg=-Wl,--gc-sections");  // Remove seções não usadas
    // println!("cargo:rustc-link-arg=-Wl,--strip-all");     // Remove TODOS os símbolos
    println!("cargo:rustc-link-arg=-Wl,--as-needed");    // Só linka libs realmente usadas
    // FIX auditoria de segurança: RELRO reativado — a GOT read-only é uma mitigação
    // padrão contra corrupção de ponteiros de função (sobrescrita de GOT).
    // O custo de performance é irrelevante para uma ferramenta de linha de comando.
    println!("cargo:rustc-link-arg=-Wl,-z,relro");
    println!("cargo:rustc-link-arg=-Wl,-z,now");         // BIND_NOW: resolve todos os símbolos na carga

    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=seccomp");
    println!("cargo:rustc-link-lib=cap");
    println!("cargo:rustc-link-lib=fuse3");

    /* ── rerun-if-changed ───────────────────────────────────────────────────
     * Cargo só reexecuta build.rs quando um path EXPLICITAMENTE listado muda.
     * Sources são cobertos pelo loop abaixo; headers precisam ser listados
     * manualmente porque o Cargo não parseia #include.                      */

    // Sources (todos via loop)
    for s in &all_sources {
        println!("cargo:rerun-if-changed={}", s);
    }

    // Headers do vault core
    println!("cargo:rerun-if-changed=c_src/vault/vault_core.h");
    println!("cargo:rerun-if-changed=c_src/vault/vault_health.h");

    // Headers do sandbox
    /* FIX: todos os 7 .c do sandbox incluem sandbox.h — se não estiver aqui,
     * uma mudança em sandbox.h não dispara rebuild de nenhum deles. */
    println!("cargo:rerun-if-changed=c_src/sandbox/sandbox.h");
    /* FIX: vault_cli.c inclui preset.h — sem isso editar preset.h não
     * recompila vault_cli.o (bug de build incremental que causava segfault
     * silencioso em builds que não eram clean). */
    println!("cargo:rerun-if-changed=c_src/sandbox/preset.h");

    // Headers do CLI
    /* FIX: vault_cli.c e vault_cli_log.c incluem vault_cli_log.h */
    println!("cargo:rerun-if-changed=c_src/cli/vault_cli_log.h");

    // Headers do container
    println!("cargo:rerun-if-changed=c_src/container/overlay.h");
    println!("cargo:rerun-if-changed=c_src/container/container.h");
}
