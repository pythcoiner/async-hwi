use std::{
    error::Error,
    ffi::OsString,
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
};

use async_hwi::{xpub_with_origin, AddressScript, DeviceKind};
use async_hwi_cli::command;

use bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    psbt::Psbt,
    Network,
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
    #[arg(long)]
    /// default will be the first connected device with the master fingerprint matching.
    #[arg(long, alias = "fg", value_parser = clap::value_parser!(bitcoin::bip32::Fingerprint))]
    fingerprint: Option<Fingerprint>,
    /// default will be the Bitcoin mainnet network.
    #[arg(long, value_parser = clap::value_parser!(bitcoin::Network), default_value_t = bitcoin::Network::Bitcoin)]
    network: Network,
    /// write command output to file instead of stdout.
    #[arg(short, long, global = true)]
    output: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(subcommand)]
    Address(AddressCommands),
    #[command(subcommand)]
    Device(DeviceCommands),
    #[command(subcommand)]
    Psbt(PsbtCommands),
    #[command(subcommand)]
    Wallet(WalletCommands),
    #[command(subcommand)]
    Persist(PersistCommands),
    #[command(subcommand)]
    Xpub(XpubCommands),
}

#[derive(Debug, Subcommand)]
enum AddressCommands {
    Display {
        /// address index
        #[arg(long)]
        index: Option<u32>,
        /// wallet name
        #[arg(long)]
        wallet_name: Option<String>,
        /// wallet policy
        #[arg(long)]
        wallet_policy: Option<String>,
        /// proof of registration, ledger only
        #[arg(long)]
        hmac: Option<String>,
        /// display a taproot address from path
        #[arg(long, value_parser = clap::value_parser!(bitcoin::bip32::DerivationPath))]
        p2tr: Option<DerivationPath>,
    },
}

#[derive(Debug, Subcommand)]
enum DeviceCommands {
    List,
}

#[derive(Debug, Subcommand)]
enum PsbtCommands {
    Sign {
        /// psbt to sign
        #[arg(long, value_parser = clap::value_parser!(bitcoin::psbt::Psbt))]
        psbt: Psbt,
        /// wallet name
        #[arg(long)]
        wallet_name: Option<String>,
        /// wallet policy
        #[arg(long)]
        wallet_policy: Option<String>,
        /// proof of registration, ledger only
        #[arg(long)]
        hmac: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum WalletCommands {
    Register {
        /// wallet name
        #[arg(long)]
        name: String,
        /// wallet policy
        #[arg(long)]
        policy: String,
    },
    IsRegistered {
        /// wallet name
        #[arg(long)]
        name: Option<String>,
        /// wallet policy
        #[arg(long)]
        policy: String,
    },
}

#[derive(Debug, Subcommand)]
enum PersistCommands {
    /// enable persistence
    Enable,
    /// disable persistence
    Disable,
    /// show persistence status
    Status,
}

#[derive(Debug, Subcommand)]
enum XpubCommands {
    Get {
        /// derivation path
        #[arg(long, value_parser = clap::value_parser!(bitcoin::bip32::DerivationPath))]
        path: DerivationPath,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let Args {
        command,
        fingerprint,
        network,
        output,
    } = parse_args()?;
    let paths = Paths::new()?;
    let persist = read_config(&paths)?.persist;

    match command {
        Commands::Address(AddressCommands::Display {
            index,
            wallet_name,
            wallet_policy,
            hmac,
            p2tr,
        }) => {
            if let Some(policy) = wallet_policy {
                for device in command::list(
                    network,
                    Some(command::Wallet {
                        name: wallet_name.as_ref(),
                        policy: Some(&policy),
                        hmac: hmac.as_ref(),
                    }),
                )
                .await?
                {
                    if !matches_fingerprint(fingerprint, device.fingerprint) {
                        continue;
                    }
                    device
                        .handle
                        .display_address(&AddressScript::Miniscript {
                            index: index.expect("Must be present"),
                            change: false,
                        })
                        .await?;
                    break;
                }
            } else if let Some(path) = p2tr {
                for device in command::list(network, None).await? {
                    if !matches_fingerprint(fingerprint, device.fingerprint) {
                        continue;
                    }
                    device
                        .handle
                        .display_address(&AddressScript::P2TR(path))
                        .await?;
                    break;
                }
            }
        }
        Commands::Device(DeviceCommands::List) => {
            for device in command::list(network, None).await? {
                print!("{}", device.fingerprint);
                print!(" {}", device.kind);
                if let Ok(version) = device.handle.get_version().await.map(|v| v.to_string()) {
                    print!(" {version}");
                }
                println!();
            }
        }
        Commands::Xpub(XpubCommands::Get { path }) => {
            let mut res = Vec::new();
            for device in command::list(network, None).await? {
                if !matches_fingerprint(fingerprint, device.fingerprint) {
                    continue;
                }
                let xpub = device.handle.get_extended_pubkey(&path).await?;
                res.push(xpub_with_origin(device.fingerprint, &path, xpub));
            }
            output_lines(output.as_ref(), &res)?;
        }
        Commands::Wallet(WalletCommands::Register { name, policy }) => {
            let mut res = Vec::new();
            for device in command::list(network, None).await? {
                if !matches_fingerprint(fingerprint, device.fingerprint) {
                    continue;
                }

                if let Some(hmac) = device.handle.register_wallet(&name, &policy).await? {
                    res.push(hex::encode(hmac));
                }
            }
            output_lines(output.as_ref(), &res)?;
        }
        Commands::Wallet(WalletCommands::IsRegistered { name, policy }) => {
            let mut res = Vec::new();
            for device in command::list(network, None).await? {
                if !matches_fingerprint(fingerprint, device.fingerprint) {
                    continue;
                }
                let (name, policy) = match device.kind {
                    DeviceKind::Ledger
                    | DeviceKind::LedgerSimulator
                    | DeviceKind::Coldcard
                    | DeviceKind::Jade => (name.clone().expect("name is required"), policy.clone()),
                    _ => ("".into(), policy.clone()),
                };
                let registered = device.handle.is_wallet_registered(&name, &policy).await?;
                res.push(registered.to_string());
            }
            output_lines(output.as_ref(), &res)?;
        }
        Commands::Psbt(PsbtCommands::Sign {
            mut psbt,
            wallet_name,
            wallet_policy,
            hmac,
        }) => {
            let mut res = Vec::new();
            for device in command::list(
                network,
                Some(command::Wallet {
                    name: wallet_name.as_ref(),
                    policy: wallet_policy.as_ref(),
                    hmac: hmac.as_ref(),
                }),
            )
            .await?
            {
                if !matches_fingerprint(fingerprint, device.fingerprint) {
                    continue;
                }
                device.handle.sign_tx(&mut psbt).await?;
                res.push(psbt.to_string());
            }
            output_lines(output.as_ref(), &res)?;
        }
        Commands::Persist(PersistCommands::Enable) => {
            write_config(&paths, Config { persist: true })?;
        }
        Commands::Persist(PersistCommands::Disable) => {
            write_config(&paths, Config { persist: false })?;
        }
        Commands::Persist(PersistCommands::Status) => {
            println!("{}", if persist { "enabled" } else { "disabled" });
        }
    }
    Ok(())
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut args = std::env::args_os().collect::<Vec<OsString>>();
    let mut stdin = io::stdin();
    if !stdin.is_terminal() {
        let mut input = String::new();
        stdin.read_to_string(&mut input)?;
        args.extend(input.trim_end().split_whitespace().map(OsString::from));
    }
    Ok(Args::parse_from(args))
}

fn matches_fingerprint(expected: Option<Fingerprint>, actual: Fingerprint) -> bool {
    expected.is_none_or(|expected| expected == actual)
}

#[derive(Default, Deserialize, Serialize)]
struct Config {
    persist: bool,
}

struct Paths {
    root: PathBuf,
}

impl Paths {
    fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self { root: app_dir()? })
    }

    fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }
}

fn app_dir() -> Result<PathBuf, Box<dyn Error>> {
    #[cfg(target_os = "linux")]
    {
        dirs::home_dir()
            .map(|home| home.join(".async-hwi"))
            .ok_or_else(|| invalid_input("home directory is unavailable"))
    }

    #[cfg(not(target_os = "linux"))]
    {
        dirs::config_dir()
            .map(|dir| dir.join("async-hwi"))
            .ok_or_else(|| invalid_input("config directory is unavailable"))
    }
}

fn read_config(paths: &Paths) -> Result<Config, Box<dyn Error>> {
    read_json_or_default(&paths.config())
}

fn write_config(paths: &Paths, config: Config) -> Result<(), Box<dyn Error>> {
    write_json(&paths.config(), &config)
}

fn read_json_or_default<T>(path: &Path) -> Result<T, Box<dyn Error>>
where
    T: Default + for<'a> Deserialize<'a>,
{
    if !path.exists() {
        return Ok(T::default());
    }

    let content = std::fs::read_to_string(path)?;
    if content.trim().is_empty() {
        return Ok(T::default());
    }

    Ok(serde_json::from_str(&content)?)
}

fn write_json<T: Serialize + ?Sized>(path: &PathBuf, value: &T) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn invalid_input(msg: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into()).into()
}

fn output_lines(output: Option<&PathBuf>, lines: &[String]) -> Result<(), Box<dyn Error>> {
    if let Some(output) = output {
        std::fs::write(output, lines.join("\n"))?;
    } else {
        for line in lines {
            println!("{line}");
        }
    }
    Ok(())
}
