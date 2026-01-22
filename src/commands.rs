use anyhow::{anyhow, Context, Result};
use chrono::Local;
use clap::{Args, Parser, Subcommand};
use colored::*;
use dirs::home_dir;
use humansize::format_size;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use urlencoding::encode;

use crate::config::{Config, ConfigManager};
use crate::errors::ExporterError;

#[derive(Parser)]
#[command(name = "rustkpcli")]
#[command(version = "2.1.0")]
#[command(about = "Get receivable card report using command line interface ", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Setup SSRS configuration
    Setup(SetupArgs),

    /// Test authentication
    Login,

    /// Export a report
    Export(ExportArgs),

    /// Show current configuration
    Config,

    /// Clear all configuration and passwords
    Clear,

    /// Change password
    ChangePassword,
}

#[derive(Args)]
pub struct SetupArgs {
    /// SSRS server URL
    #[arg(short, long)]
    pub server: Option<String>,

    /// Report path
    #[arg(short, long)]
    pub report_path: Option<String>,

    /// Username for NTLM (domain\\user)
    #[arg(short, long)]
    pub username: Option<String>,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Agreement number
    pub no_perjanjian: String,

    /// Output format
    #[arg(short, long, default_value = "PDF")]
    pub format: String,

    /// Output file path
    #[arg(short, long)]
    pub output: Option<String>,
}

/// UI/UX Functions
pub fn show_banner() {
    println!();
    println!("{}", "╔══════════════════════════════════════════════════╗".cyan());
    println!("{}", "║                                                  ║".cyan());
    println!("{}", "║      ███████╗███████╗███████╗██████╗            ║".cyan().bold());
    println!("{}", "║      ██╔════╝██╔════╝██╔════╝██╔══██╗           ║".cyan().bold());
    println!("{}", "║      ███████╗█████╗  █████╗  ██████╔╝           ║".cyan().bold());
    println!("{}", "║      ╚════██║██╔══╝  ██╔══╝  ██╔══██╗           ║".cyan().bold());
    println!("{}", "║      ███████║███████╗███████╗██║  ██║           ║".cyan().bold());
    println!("{}", "║      ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝           ║".cyan().bold());
    println!("{}", "║                                                  ║".cyan());
    println!("{}", "║    Export Receivable Card Reports CLI           ║".yellow());
    println!("{}", "║    NTLM Authentication Built-in                 ║".dimmed());
    println!("{}", "║                                                  ║".cyan());
    println!("{}", "║  GitHub: https://github.com/neuxdotdev/rustkpcli ║".blue().underline());
    println!("{}", "╚══════════════════════════════════════════════════╝".cyan());
    println!();
}

fn format_filename(no_perjanjian: &str, format: &str) -> String {
    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S");
    let clean_no = no_perjanjian
        .trim()
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
        .collect::<String>();
    let ext = match format.to_lowercase().as_str() {
        "excel" => "xlsx",
        _ => "pdf",
    };
    format!("SSRS_{}_{}.{}", clean_no, timestamp, ext)
}

fn format_bytes(bytes: u64) -> String {
    format_size(bytes, humansize::DECIMAL)
}

/// Utility Functions
fn check_curl() -> bool {
    Command::new("curl")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn prompt_input(prompt: &str, default: Option<&str>) -> Result<String> {
    print!("{} ", prompt.yellow());
    if let Some(default) = default {
        print!("[{}]: ", default.dimmed());
    }
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if input.is_empty() {
        if let Some(default) = default {
            Ok(default.to_string())
        } else {
            Err(anyhow!("Input cannot be empty"))
        }
    } else {
        Ok(input.to_string())
    }
}

fn prompt_password() -> Result<String> {
    print!("{} ", "Password:".yellow());
    io::stdout().flush()?;
    let password = rpassword::read_password()
        .context("Failed to read password")?;
    if password.is_empty() {
        Err(anyhow!("Password cannot be empty"))
    } else {
        Ok(password)
    }
}

fn prompt_password_with_confirmation() -> Result<String> {
    loop {
        print!("{} ", "Password:".yellow());
        io::stdout().flush()?;
        let password1 = rpassword::read_password()?;
        print!("{} ", "Confirm password:".yellow());
        io::stdout().flush()?;
        let password2 = rpassword::read_password()?;
        if password1 == password2 {
            if password1.is_empty() {
                println!("{}", "Password cannot be empty".red());
                continue;
            }
            return Ok(password1);
        } else {
            println!("{}", "Passwords do not match. Try again.".red());
        }
    }
}

/// Command Handlers
pub fn setup_command(args: SetupArgs, verbose: bool) -> Result<()> {
    println!();
    println!("{}", "RUSTKPCLI Configuration Setup".cyan().bold());
    println!("{}", "Enter your SSRS connection details:\n".dimmed());

    let server = if let Some(server) = args.server {
        server
    } else {
        prompt_input("SSRS Server URL:", Some("http://example.com"))?
    };

    if !server.starts_with("http") {
        return Err(anyhow!("URL must start with http:// or https://"));
    }

    let report_path = if let Some(report_path) = args.report_path {
        report_path
    } else {
        prompt_input("Report Path:", Some("/Path/to/Dir"))?
    };

    let username = if let Some(username) = args.username {
        username
    } else {
        prompt_input("Username (domain\\user):", None)?
    };

    println!();
    let password = prompt_password_with_confirmation()?;

    if !check_curl() {
        println!();
        println!("{}", " curl is not installed or not in PATH".red());
        println!("{}", "Please install curl to use this tool:".yellow());
        println!("  Windows: {}", "https://curl.se/windows/".dimmed());
        println!("  macOS:   {}", "brew install curl".dimmed());
        println!("  Linux:   {}", "sudo apt-get install curl".dimmed());
        return Err(anyhow!("curl not found"));
    }

    let config_manager = ConfigManager::new()?;
    let mut config = Config {
        server,
        report_path,
        username,
        password_encrypted: String::new(),
        password_hash: String::new(),
    };
    config.validate()?;
    config_manager.save_with_password(&mut config, &password)?;

    println!();
    println!("{}", " Configuration saved successfully!".green());
    println!("{}", "  Passwords are encrypted and stored locally.".dimmed());

    if verbose {
        println!("{}", "\nTesting connection...".cyan());
    }

    match login_command(verbose) {
        Ok(_) => {
            println!("{}", " Connection test successful".green());
            println!("{}", "\nYou can now use the export command:".dimmed());
            println!("  {} 123456", "rustkpcli export".cyan());
        }
        Err(e) => {
            println!("{} {}", "".yellow(), format!("Connection test failed: {}", e).yellow());
            println!("{}", "You may need to check your credentials.".dimmed());
        }
    }
    Ok(())
}

pub fn login_command(verbose: bool) -> Result<()> {
    let config_manager = ConfigManager::new()?;
    let config = config_manager.load()?
        .ok_or_else(|| anyhow::Error::new(ExporterError::ConfigNotFound))?;
    let password = config_manager.get_decrypted_password(&config)?;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["", "", "", "", "", "", "", "", "", ""])
            .template("{spinner} {msg}")?
    );
    pb.set_message("Testing authentication...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let test_url = format!("{}/ReportServer", config.server);
    if verbose {
        pb.suspend(|| println!("{} {}", "Testing URL:".dimmed(), test_url.dimmed()));
    }

    let output = Command::new("curl")
        .args(&[
            "--ntlm",
            "-u", &format!("{}:{}", config.username, password),
            "--silent",
            "--show-error",
            "--head",
            "--output", if cfg!(windows) { "NUL" } else { "/dev/null" },
            "--write-out", "%{http_code}",
            &test_url,
        ])
        .output()
        .map_err(|_| anyhow::Error::new(ExporterError::CurlNotFound))?;

    pb.finish_and_clear();

    if output.status.success() {
        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let status_code: u16 = status.parse().unwrap_or(0);
        if status_code == 200 || status_code == 401 {
            if verbose {
                println!("{}", " Authentication test completed".green());
                println!("  {} {}", "Server:".dimmed(), config.server.dimmed());
                println!("  {} {}", "User:".dimmed(), config.username.dimmed());
                println!("  {} {}", "HTTP Status:".dimmed(), status.dimmed());
            } else {
                println!("{}", " Authentication successful".green());
            }
            Ok(())
        } else {
            Err(anyhow!("Unexpected HTTP status: {}", status))
        }
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        Err(anyhow!("Connection failed: {}", error))
    }
}

pub fn export_command(args: ExportArgs, verbose: bool) -> Result<()> {
    let config_manager = ConfigManager::new()?;
    let config = config_manager.load()?
        .ok_or_else(|| anyhow::Error::new(ExporterError::ConfigNotFound))?;
    let password = config_manager.get_decrypted_password(&config)?;

    let output_path = if let Some(output) = args.output {
        PathBuf::from(output)
    } else {
        let home = home_dir().ok_or_else(|| anyhow!("Could not find home directory"))?;
        let downloads_dir = home.join("Downloads");
        if !downloads_dir.exists() {
            fs::create_dir_all(&downloads_dir)?;
        }
        downloads_dir.join(format_filename(&args.no_perjanjian, &args.format))
    };

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let url = format!(
        "{}/ReportServer?{}&rs:Command=Render&rs:Format={}&NoPerjanjian={}",
        config.server,
        encode(&config.report_path),
        args.format.to_uppercase(),
        args.no_perjanjian.trim()
    );

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["", "", "", "", "", "", "", "", "", ""])
            .template("{spinner} {msg}")?
    );
    pb.set_message(format!("Exporting {}...", args.no_perjanjian));
    pb.enable_steady_tick(Duration::from_millis(100));

    if verbose {
        pb.suspend(|| println!("{} {}", "URL:".dimmed(), url.dimmed()));
    }

    let mut curl_args = vec![
        "--ntlm".to_string(),
        "-u".to_string(),
        format!("{}:{}", config.username, password),
        "-L".to_string(),
        "-o".to_string(),
        output_path.to_string_lossy().to_string(),
        "--silent".to_string(),
        "--show-error".to_string(),
        "--connect-timeout".to_string(),
        "30".to_string(),
        "--max-time".to_string(),
        "120".to_string(),
    ];

    if verbose {
        curl_args.push("--verbose".to_string());
    }
    curl_args.push(url);

    let output = Command::new("curl")
        .args(&curl_args)
        .output()
        .map_err(|_| anyhow::Error::new(ExporterError::CurlNotFound))?;

    pb.finish_and_clear();

    if output.status.success() {
        if output_path.exists() {
            let metadata = fs::metadata(&output_path)?;
            if metadata.len() == 0 {
                fs::remove_file(&output_path)?;
                return Err(anyhow!("Server returned empty file"));
            }

            if args.format.to_uppercase() == "PDF" {
                let mut file = File::open(&output_path)?;
                let mut header = [0u8; 4];
                file.read_exact(&mut header)?;
                if &header == b"%PDF" {
                    println!("{}", " PDF exported successfully!".green());
                } else {
                    println!("{}", " File saved but may not be valid PDF".yellow());
                }
            } else {
                println!("{}", " File exported successfully!".green());
            }

            println!("  {} {}", "File:".cyan(), output_path.display());
            println!("  {} {}", "Size:".cyan(), format_bytes(metadata.len()));
            Ok(())
        } else {
            Err(anyhow!("File was not created"))
        }
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        let error_str = error.to_string();
        if error_str.contains("401") {
            Err(anyhow::Error::new(ExporterError::AuthFailed("Check username/password".to_string())))
        } else if error_str.contains("404") {
            Err(anyhow!("Report not found. Check report path."))
        } else if error_str.contains("Could not resolve host") {
            Err(anyhow!("Cannot connect to server. Check server URL."))
        } else if error_str.contains("Connection refused") {
            Err(anyhow!("Connection refused. Server may be down."))
        } else if error_str.contains("timeout") {
            Err(anyhow!("Connection timeout. Server may be busy."))
        } else {
            Err(anyhow!("Export failed: {}", &error_str[..200.min(error_str.len())]))
        }
    }
}

pub fn config_command() -> Result<()> {
    let config_manager = ConfigManager::new()?;
    match config_manager.load()? {
        Some(config) => {
            println!();
            println!("{}", "Current Configuration:".cyan().bold());
            println!("  {} {}", "Server:".white(), config.server.yellow());
            println!("  {} {}", "Report Path:".white(), config.report_path.yellow());
            println!("  {} {}", "Username:".white(), config.username.yellow());
            if config.password_encrypted.is_empty() {
                println!("  {} {}", "Password:".white(), " (not configured)".red());
            } else {
                println!("  {} {}", "Password:".white(), " (encrypted and stored)".green());
            }
            println!("  {} {}", "Config File:".white(),
                     config_manager.get_path().display().to_string().dimmed());
            Ok(())
        }
        None => {
            println!("{}", "No configuration found. Run setup first.".yellow());
            Ok(())
        }
    }
}

pub fn clear_command() -> Result<()> {
    println!("Are you sure you want to clear all configuration and passwords? [y/N]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim().to_lowercase() == "y" {
        let config_manager = ConfigManager::new()?;
        if config_manager.load()?.is_some() {
            config_manager.clear()?;
            println!("{}", " All configuration cleared".green());
        } else {
            println!("{}", "No configuration to clear.".yellow());
        }
    } else {
        println!("{}", "Operation cancelled".dimmed());
    }
    Ok(())
}

pub fn change_password_command() -> Result<()> {
    let config_manager = ConfigManager::new()?;
    let mut config = config_manager.load()?
        .ok_or_else(|| anyhow::Error::new(ExporterError::ConfigNotFound))?;

    println!();
    println!("{}", "Change Password".cyan().bold());
    println!("{}", "Enter current password:".yellow());
    let current_password = prompt_password()?;

    if !config_manager.verify_password(&config, &current_password) {
        return Err(anyhow!("Current password is incorrect"));
    }

    println!();
    println!("{}", "Enter new password:".yellow());
    let new_password = prompt_password_with_confirmation()?;

    config_manager.save_with_password(&mut config, &new_password)?;

    println!();
    println!("{}", " Password changed successfully!".green());
    Ok(())
}