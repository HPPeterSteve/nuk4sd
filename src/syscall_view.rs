mod vault;

extern "C" {
    // Anexa ao processo filho antes do sandbox fechar
    fn ptrace_attach(pid: i32) -> c_int;
    
}