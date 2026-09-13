use colored::Colorize;
use inquire::Select;

struct Page {
    title: &'static str,
    content: &'static str,
}

const PAGES: &[Page] = &[
    Page {
        title: "Page 1: Responsible Software Usage",
        content: "Nuk4sd was built to provide a secure and isolated environment for sensitive files.\n\n\
                  Responsible use of this software entails:\n\
                  • Do not use Nuk4sd to store, conceal, or transaction illegal materials, stolen data, or items violating local or international laws.\n\
                  • The software is a defensive tool. It must not be used as a vector to bypass legitimate corporate policies or legal audits.\n\
                  • You are solely responsible for maintaining backups of your keys and passwords.\n\n\
                  Nuk4sd is provided 'AS IS', without warranties of fitness for a particular purpose."
    },
    Page {
        title: "Page 2: Risks",
        content: "Although Nuk4sd uses state-of-the-art cryptography and rigorous sandboxing, absolute security does not exist.\n\n\
                  Known Risks:\n\
                  • Password Loss: If you forget your vault password, THE DATA IS LOST FOREVER. There is no 'forgot password' mechanism or backdoor.\n\
                  • Host Compromise: If the host operating system is compromised by a Kernel-level keylogger, the password may be captured during entry.\n\
                  • Physical Attacks: If an adversary gains physical access to the device while the vault is unlocked, the software cannot protect data in memory."
    },
    Page {
        title: "Page 3: Safeguards and Features",
        content: "Nuk4sd implements multiple defense layers to mitigate attacks:\n\n\
                  • Robust Cryptography: Strong algorithms for data at rest (AES-256-GCM / Argon2id).\n\
                  • Sandboxing (Linux): Process isolation utilizing chroot/pivot_root, namespaces, and syscall filtering (seccomp) to execute utilities securely.\n\
                  • Inotify Monitoring: FileBucket (Leaky-Bucket Algorithm) scores file access events, automatically locking the vault upon detecting stealthy malware or ransomware activity.\n\
                  • Isolation Engine (Honeyfile Labyrinth): Labyrinths of fake directories and decoy files to trick ransomware and trigger immediate alarms."
    },
    Page {
        title: "Page 4: Limitations and Out-of-Scope Risks",
        content: "Software Limitations:\n\n\
                  • Not an Antivirus/EDR replacement: Nuk4sd does not scan memory for virus signatures nor prevent initial system infection.\n\
                  • Does not guarantee network anonymity: The software isolates files, but does not mask your network identity (like Tor or a VPN would).\n\
                  • Compromised Hardware: CPU vulnerabilities (such as Meltdown/Spectre), disk firmware flaws, or malicious DMA (Direct Memory Access) escape the Nuk4sd threat model.\n\
                  • Nuk4sd protects FILES while at rest or inside the Sandbox. If exported from the vault to the Desktop, they lose protection."
    },
    Page {
        title: "Page 5: Security Recommendations",
        content: "To achieve maximum tool effectiveness, follow these best practices:\n\n\
                  1. Strong Passwords: Use a long, randomly generated passphrase (> 16 characters).\n\
                  2. Never Export Sensitive Files to Host: If editing a sensitive file, do so inside the integrated Sandbox to avoid leaking temporary data to the primary disk.\n\
                  3. Monitor Logs: Use the audit tools and Nuk4sd scan reports to ensure the vault has not been moved or modified offline.\n\
                  4. Keep Updated: Always keep Nuk4sd and your Host Operating System updated."
    }
];

pub fn show_manual() {
    let mut current_page = 0;

    loop {
        // Clear screen
        print!("\x1B[2J\x1B[1;1H");

        let page = &PAGES[current_page];

        println!(
            "{}",
            "===========================================================".cyan()
        );
        println!(
            "{} {}",
            "Nuk4sd OPERATIONAL MANUAL -".bold().cyan(),
            page.title.bold().yellow()
        );
        println!(
            "{}",
            "===========================================================".cyan()
        );
        println!();

        // Print content
        println!("{}", page.content.white());
        println!();
        println!(
            "{}",
            "===========================================================".cyan()
        );
        println!("Page {} of {}", current_page + 1, PAGES.len());
        println!();

        let mut options = Vec::new();

        if current_page < PAGES.len() - 1 {
            options.push("Next Page");
        }
        if current_page > 0 {
            options.push("Previous Page");
        }
        options.push("Exit Manual");

        let ans = Select::new("What would you like to do?", options).prompt();

        match ans {
            Ok(choice) => {
                if choice == "Next Page" {
                    current_page += 1;
                } else if choice == "Previous Page" {
                    current_page -= 1;
                } else if choice == "Exit Manual" {
                    println!("{}", "Exiting manual...".green());
                    break;
                }
            }
            Err(_) => {
                // User pressed Esc or interrupted
                break;
            }
        }
    }
}
