use sysinfo::{Disks, Networks, System};

/// Lista todos os processos ativos com detalhes de consumo e status de isolamento
pub fn list_process_status(options: &SystemOptions) {
    let mut sys = System::new_all();
    sys.refresh_all();

    println!("\n{:<10} {:<25} {:<12} {:<15}", "PID", "PROCESSO", "MEMÓRIA", "STATUS");
    println!("{:-<62}", "");

    for (pid, process) in sys.processes() {
        let pid_u32 = pid.as_u32();
        let mem_mb = process.memory() as f64 / 1_048_576.0;
        let status = if process.cpu_usage() > 0.0 {
            "ISOLADO/ATIVO"
        } else {
            "ISOLADO/IDLE"
        };

        if options.processes {
            println!(
                "{:<10} {:<25} {:<12.2} MB {:<15}",
                pid_u32,
                process.name().to_string_lossy(),
                mem_mb,
                status
            );
        }
    }
}

// Estrutura de opções para escolher quais infos mostrar
pub struct SystemOptions {
    pub cpu: bool,
    pub memory: bool,
    pub disks: bool,
    pub networks: bool,
    pub processes: bool,
}

// Função principal para mostrar informações do sistema
pub fn system_information(options: SystemOptions) {
    let mut sys_info = System::new_all();
    sys_info.refresh_all();

    println!("--- System Nuk4sd ---");

    if options.cpu {
        println!("CPU:");
        for cpu in sys_info.cpus() {
            println!("  - {}: {:.2}% usage", cpu.name(), cpu.cpu_usage());
        }
    }

    if options.memory {
        println!("Memory:");
        let total_mem_mb = sys_info.total_memory() as f64 / 1_048_576.0;
        let used_mem_mb = sys_info.used_memory() as f64 / 1_048_576.0;
        let free_mem_mb = sys_info.free_memory() as f64 / 1_048_576.0;

        println!("  - Total: {:.2} MB", total_mem_mb);
        println!("  - Used:  {:.2} MB", used_mem_mb);
        println!("  - Free:  {:.2} MB", free_mem_mb);
    }

    if options.disks {
        println!("Disks:");
        let disks = Disks::new_with_refreshed_list();
        for disk in &disks {
            println!(
                "  - {:?}: {:.2} GB total, {:.2} GB available",
                disk.name(),
                disk.total_space() as f64 / 1_073_741_824.0,
                disk.available_space() as f64 / 1_073_741_824.0
            );
        }
    }

    if options.networks {
        println!("Networks:");
        let networks = Networks::new_with_refreshed_list();
        for (interface_name, network) in &networks {
            println!(
                "  - {}: {} bytes transmitted, {} bytes received",
                interface_name,
                network.transmitted(),
                network.received()
            );
        }
    }

    if options.processes {
        println!("Processes:");
        for (pid, process) in sys_info.processes() {
            println!(
                "  - {:?} (PID {}): {:.2}% CPU, {:.2} MB memory",
                process.name(),
                pid,
                process.cpu_usage(),
                process.memory() as f64 / 1_048_576.0
            );
        }
    }
}
