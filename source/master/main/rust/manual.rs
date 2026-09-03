use colored::Colorize;
use inquire::Select;

struct Page {
    title: &'static str,
    content: &'static str,
}

const PAGES: &[Page] = &[
    Page {
        title: "Página 1: Uso Responsável do Software",
        content: "O Nuk4sd foi construído para fornecer um ambiente seguro e isolado para arquivos sensíveis.\n\n\
                  O uso responsável deste software implica em:\n\
                   Não utilizar o Nuk4sd para armazenar, ocultar ou transacionar materiais ilegais, dados roubados ou itens que violem leis locais ou internacionais.\n\
                   O software é uma ferramenta de defesa. Não deve ser usado como vetor para burlar políticas corporativas legítimas ou auditorias legais.\n\
                   Você é o único responsável por manter o backup de suas chaves e senhas.\n\n\
                  O Nuk4sd é fornecido 'COMO ESTÁ', sem garantias de adequação a um propósito específico."
    },
    Page {
        title: "Página 2: Riscos",
        content: "Embora o Nuk4sd utilize criptografia de ponta e sandboxing rigoroso, a segurança absoluta não existe.\n\n\
                  Riscos conhecidos:\n\
                   Perda da Senha: Se você esquecer a senha do seu cofre, OS DADOS ESTARÃO PERDIDOS PARA SEMPRE. Não há mecanismo de 'esqueci minha senha' ou backdoor.\n\
                   Comprometimento do Host: Se a máquina (Sistema Operacional) estiver comprometida com um Keylogger no nível do Kernel, a senha pode ser capturada no momento da digitação.\n\
                   Ataques Físicos: Se um adversário obtiver acesso físico ao dispositivo com o cofre desbloqueado, o software não poderá proteger os dados em memória."
    },
    Page {
        title: "Página 3: Proteções e Recursos",
        content: "O Nuk4sd implementa múltiplas camadas de defesa para mitigar ataques:\n\n\
                   Criptografia Robusta: Algoritmos fortes em repouso (AES-256-GCM / ChaCha20).\n\
                   Sandboxing (No Linux): Isolamento de processos utilizando chroot/pivot_root, namespaces e filtragem de syscalls (seccomp) para rodar visualizadores e utilitários de forma segura.\n\
                   Monitoramento Inotify: O FileBucket (Leaky-Bucket Algorithm) pontua acessos a arquivos, travando automaticamente o cofre ao detectar ações furtivas de malwares ou ransomwares.\n\
                   Engine de Isolamento (Honeyfile Labyrinth): Labirintos de falsos diretórios e arquivos isca para enganar ransomwares e disparar alarmes imediatos."
    },
    Page {
        title: "Página 4: Limitações e O Que NÃO É Coberto",
        content: "Limitações do Software:\n\n\
                   Não substitui um Antivírus/EDR: O Nuk4sd não varre a memória em busca de assinaturas de vírus, nem impede a infecção inicial do sistema.\n\
                   Não garante anonimato: O software isola os arquivos, mas não disfarça a sua identidade na rede (como o Tor ou uma VPN fariam).\n\
                   Hardware Comprometido: Vulnerabilidades no processador (como Meltdown/Spectre), falhas em firmware de discos ou DMA (Direct Memory Access) malicioso escapam ao modelo de ameaça do Nuk4sd.\n\
                   O Nuk4sd protege OS ARQUIVOS enquanto repousam ou dentro da Sandbox. Se você os exportar do cofre para o Desktop, eles perdem a proteção."
    },
    Page {
        title: "Página 5: Recomendações de Segurança",
        content: "Para obter a máxima eficácia da ferramenta, siga estas práticas:\n\n\
                  1. Senhas Fortes: Use uma Passphrase longa (> 16 caracteres), gerada aleatoriamente.\n\
                  2. Nunca Exportar Sensíveis ao Host: Se precisar editar um arquivo seguro, faça-o de preferência com a Sandbox integrada, evitando vazar dados temporários para o disco principal.\n\
                  3. Fique atento a Logs: Use a ferramenta de auditoria e os relatórios de scan do Nuk4sd para garantir que o cofre não foi movido ou modificado offline.\n\
                  4. Atualizações: Mantenha sempre o Nuk4sd e seu Sistema Operacional atualizados."
    }
];

pub fn show_manual() {
    let mut current_page = 0;

    loop {
        // Limpa a tela
        print!("\x1B[2J\x1B[1;1H");

        let page = &PAGES[current_page];

        println!(
            "{}",
            "===========================================================".cyan()
        );
        println!(
            "{} {}",
            "MANUAL DE OPERAÇÃO Nuk4sd -".bold().cyan(),
            page.title.bold().yellow()
        );
        println!(
            "{}",
            "===========================================================".cyan()
        );
        println!();

        // Print content with word wrap handling implicitly (terminal will wrap)
        println!("{}", page.content.white());
        println!();
        println!(
            "{}",
            "===========================================================".cyan()
        );
        println!("Página {} de {}", current_page + 1, PAGES.len());
        println!();

        let mut options = Vec::new();

        if current_page < PAGES.len() - 1 {
            options.push("Avançar para a Próxima Página");
        }
        if current_page > 0 {
            options.push("Voltar para a Página Anterior");
        }
        options.push("Sair do Manual");

        let ans = Select::new("O que deseja fazer?", options).prompt();

        match ans {
            Ok(choice) => {
                if choice == "Avançar para a Próxima Página" {
                    current_page += 1;
                } else if choice == "Voltar para a Página Anterior" {
                    current_page -= 1;
                } else if choice == "Sair do Manual" {
                    println!("{}", "Saindo do manual...".green());
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
