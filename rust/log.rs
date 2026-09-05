use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;
use std::process;
use std::thread;
use colored::*;

#[allow(dead_code)]
pub enum LogLevel {
    INFO,
    WARN,
    ERROR,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LogLevel::INFO => write!(f, "INFO"),
            LogLevel::WARN => write!(f, "WARN"),
            LogLevel::ERROR => write!(f, "ERROR"),
        }
    }
}

pub fn log(level: LogLevel, message: &str) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    let log_entry = format!("[{}] [{}] {}\n", timestamp, level, message);

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("Nuk4sd.log")
    {
        let _ = file.write_all(log_entry.as_bytes());
    }
}

pub fn info(message: &str) {
    log(LogLevel::INFO, message);
}

#[allow(dead_code)]
pub fn warn(message: &str) {
    log(LogLevel::WARN, message);
}

#[allow(dead_code)]
pub fn error(message: &str) {
    log(LogLevel::ERROR, message);
}

#[allow(dead_code)]
pub fn console_trace(step: &str, details: &str) {
    let timestamp = Local::now().format("%H:%M:%S%.6f");
    let pid = process::id();
    let thread_id = format!("{:?}", thread::current().id());
    
    let trace_log = format!(
        "{} [PID {} | TID {}] [{}] ➜ {}",
        timestamp.to_string().dimmed(),
        pid.to_string().cyan(),
        thread_id.cyan(),
        step.yellow().bold(),
        details
    );
    
    println!("{}", trace_log);
    
    // Also log it to the file so it persists
    let file_log = format!("[PID {} | TID {}] [{}] {}", pid, thread_id, step, details);
    log(LogLevel::INFO, &file_log);
}
