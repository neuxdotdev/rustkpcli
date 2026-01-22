use clap::Parser;
use rustkpcli::commands::{Cli, Commands, show_banner};

fn main() -> anyhow::Result<()> {
    show_banner();
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup(args) => rustkpcli::commands::setup_command(args, cli.verbose),
        Commands::Login => rustkpcli::commands::login_command(cli.verbose),
        Commands::Export(args) => rustkpcli::commands::export_command(args, cli.verbose),
        Commands::Config => rustkpcli::commands::config_command(),
        Commands::Clear => rustkpcli::commands::clear_command(),
        Commands::ChangePassword => rustkpcli::commands::change_password_command(),
    }
}