use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsString,
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
};

use async_hwi::{bitbox::NoiseConfigData, xpub_with_origin, AddressScript, DeviceKind};
use async_hwi_cli::command;

use bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    psbt::Psbt,
    Network,
};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

const PSBT_SIGN_ABOUT: &str = "sign psbt from --psbt, --psbt-file, or stdin";
const WALLET_REGISTER_ABOUT: &str = "register wallet from persisted state or --name and --policy";
const WALLET_IS_REGISTERED_ABOUT: &str =
    "check wallet registration from persisted state or wallet name and policy";

fn persist_long_about(command_help: &str) -> String {
    format!(
        "{command_help}. When persistence is enabled, wallet metadata is loaded by device fingerprint from the async-hwi state directory. Command arguments must match existing persisted values."
    )
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
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
    State(StateCommands),
    #[command(subcommand)]
    Bitbox(BitboxCommands),
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
    #[command(
        about = PSBT_SIGN_ABOUT,
        long_about = persist_long_about(
            "Sign psbt from --psbt, --psbt-file, or stdin. Use persisted state or wallet name and policy to provide wallet metadata"
        )
    )]
    Sign {
        /// psbt to sign
        #[arg(long, value_parser = clap::value_parser!(bitcoin::psbt::Psbt))]
        psbt: Option<Psbt>,
        /// psbt to sign
        #[arg(value_parser = clap::value_parser!(bitcoin::psbt::Psbt), hide = true)]
        psbt_arg: Option<Psbt>,
        /// read psbt from file
        #[arg(long)]
        psbt_file: Option<PathBuf>,
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
    #[command(
        about = WALLET_REGISTER_ABOUT,
        long_about = persist_long_about("Register wallet from persisted state or --name and --policy")
    )]
    Register {
        /// wallet name
        #[arg(short, long)]
        name: Option<String>,
        /// wallet policy
        #[arg(short, long)]
        policy: Option<String>,
    },
    #[command(
        about = WALLET_IS_REGISTERED_ABOUT,
        long_about = persist_long_about(
            "Check wallet registration from persisted state or wallet name and policy"
        )
    )]
    IsRegistered {
        /// wallet name
        #[arg(short, long)]
        name: Option<String>,
        /// wallet policy
        #[arg(short, long)]
        policy: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum StateCommands {
    Clear,
    Show,
    Edit {
        field: StateField,
        value: Option<String>,
    },
    Rm {
        field: StateField,
    },
}

#[derive(Debug, Subcommand)]
enum BitboxCommands {
    Show,
}

#[derive(Debug, Subcommand)]
enum PersistCommands {
    Enable,
    Disable,
    Status,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[clap(rename_all = "snake_case")]
enum StateField {
    Name,
    Descriptor,
    Por,
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
            let args = WalletArgs::new(wallet_name, wallet_policy, hmac);
            let resolver = wallet_resolver(&paths, persist, args.clone());
            if args.has_any() || (persist && p2tr.is_none()) {
                let (devices, bitbox) =
                    command::list(network, Some(&resolver), read_bitbox(&paths, persist)?).await?;
                write_bitbox(&paths, persist, bitbox)?;

                for entry in devices {
                    if !matches_fingerprint(fingerprint, entry.fingerprint) {
                        continue;
                    }
                    entry
                        .device
                        .display_address(&AddressScript::Miniscript {
                            index: index.expect("Must be present"),
                            change: false,
                        })
                        .await?;
                    break;
                }
            } else if let Some(path) = p2tr {
                for entry in list_devices(network, None).await? {
                    if !matches_fingerprint(fingerprint, entry.fingerprint) {
                        continue;
                    }
                    entry
                        .device
                        .display_address(&AddressScript::P2TR(path))
                        .await?;
                    break;
                }
            }
        }
        Commands::Device(DeviceCommands::List) => {
            output_device_list(output.as_ref(), list_devices(network, None).await?).await?;
        }
        Commands::Xpub(XpubCommands::Get { path }) => {
            let mut res = Vec::new();
            for entry in list_devices(network, None).await? {
                if !matches_fingerprint(fingerprint, entry.fingerprint) {
                    continue;
                }
                let xpub = entry.device.get_extended_pubkey(&path).await?;
                res.push(xpub_with_origin(entry.fingerprint, &path, xpub));
            }
            output_lines(output.as_ref(), &res)?;
        }
        Commands::Wallet(WalletCommands::Register { name, policy }) => {
            let args = WalletArgs::new(name, policy, None);
            let mut res = Vec::new();
            for entry in list_devices(network, read_bitbox(&paths, persist)?).await? {
                if !matches_fingerprint(fingerprint, entry.fingerprint) {
                    continue;
                }
                let mut wallet = resolve_wallet_state(
                    &paths,
                    persist,
                    entry.fingerprint,
                    &args,
                    Some(entry.kind),
                )?
                .ok_or_else(|| invalid_input("wallet policy is required"))?;
                let name = wallet
                    .name
                    .as_ref()
                    .ok_or_else(|| invalid_input("wallet name is required"))?;
                let descriptor = wallet
                    .descriptor
                    .as_ref()
                    .ok_or_else(|| invalid_input("wallet policy is required"))?;

                if let Some(por) = entry.device.register_wallet(name, descriptor).await? {
                    let por = hex::encode(por);
                    merge_state_field(&mut wallet.por, Some(por.clone()), "proof of registration")?;
                    save_wallet_state(&paths, persist, entry.fingerprint, wallet)?;
                    res.push(por);
                } else {
                    save_wallet_state(&paths, persist, entry.fingerprint, wallet)?;
                }
            }
            output_lines(output.as_ref(), &res)?;
        }
        Commands::Wallet(WalletCommands::IsRegistered { name, policy }) => {
            let args = WalletArgs::new(name, policy, None);
            let mut res = Vec::new();
            for entry in list_devices(network, read_bitbox(&paths, persist)?).await? {
                if !matches_fingerprint(fingerprint, entry.fingerprint) {
                    continue;
                }
                let wallet = resolve_wallet_state(
                    &paths,
                    persist,
                    entry.fingerprint,
                    &args,
                    Some(entry.kind),
                )?
                .ok_or_else(|| invalid_input("wallet policy is required"))?;
                let descriptor = wallet
                    .descriptor
                    .as_ref()
                    .ok_or_else(|| invalid_input("wallet policy is required"))?;
                let name = wallet_name_for_device(entry.kind, wallet.name.as_ref())?;
                let registered = entry.device.is_wallet_registered(name, descriptor).await?;
                save_wallet_state(&paths, persist, entry.fingerprint, wallet)?;
                res.push(registered.to_string());
            }
            output_lines(output.as_ref(), &res)?;
        }
        Commands::Psbt(PsbtCommands::Sign {
            psbt,
            psbt_arg,
            psbt_file,
            wallet_name,
            wallet_policy,
            hmac,
        }) => {
            let mut psbt = resolve_psbt(psbt.or(psbt_arg), psbt_file)?;
            let args = WalletArgs::new(wallet_name, wallet_policy, hmac);
            let resolver = wallet_resolver(&paths, persist, args);
            let (devices, bitbox) =
                command::list(network, Some(&resolver), read_bitbox(&paths, persist)?).await?;
            write_bitbox(&paths, persist, bitbox)?;

            let mut res = Vec::new();
            for entry in devices {
                if !matches_fingerprint(fingerprint, entry.fingerprint) {
                    continue;
                }
                entry.device.sign_tx(&mut psbt).await?;
                res.push(psbt.to_string());
            }
            output_lines(output.as_ref(), &res)?;
        }
        Commands::State(StateCommands::Clear) => {
            clear_wallets(&paths)?;
        }
        Commands::State(StateCommands::Show) => {
            output_lines(output.as_ref(), &wallet_state_lines(&paths)?)?;
        }
        Commands::State(StateCommands::Edit { field, value }) => {
            let fingerprint = resolve_state_fingerprint(network, fingerprint).await?;
            let mut wallets = read_wallets(&paths, fingerprint)?;
            let index =
                select_wallet_index(&mut wallets, &WalletArgs::default())?.unwrap_or_else(|| {
                    wallets.push(WalletState::default());
                    wallets.len() - 1
                });
            wallets[index].set(field, Some(read_state_value(value)?));
            write_wallets(&paths, fingerprint, &wallets)?;
        }
        Commands::State(StateCommands::Rm { field }) => {
            let fingerprint = resolve_state_fingerprint(network, fingerprint).await?;
            let mut wallets = read_wallets(&paths, fingerprint)?;
            let index = select_wallet_index(&mut wallets, &WalletArgs::default())?
                .ok_or_else(|| invalid_input("wallet state is required"))?;
            wallets[index].set(field, None);
            write_wallets(&paths, fingerprint, &wallets)?;
        }
        Commands::Bitbox(BitboxCommands::Show) => {
            output_lines(output.as_ref(), &bitbox_pairing_lines(&paths)?)?;
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
        let input = input.trim_end();
        if !input.is_empty() {
            args.push(input.into());
        }
    }
    Ok(Args::parse_from(args))
}

#[derive(Clone, Default)]
struct WalletArgs {
    name: Option<String>,
    descriptor: Option<String>,
    por: Option<String>,
}

impl WalletArgs {
    fn new(name: Option<String>, descriptor: Option<String>, por: Option<String>) -> Self {
        Self {
            name,
            descriptor,
            por,
        }
    }

    fn has_any(&self) -> bool {
        self.name.is_some() || self.descriptor.is_some() || self.por.is_some()
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct WalletState {
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    por: Option<String>,
}

impl WalletState {
    fn set(&mut self, field: StateField, value: Option<String>) {
        match field {
            StateField::Name => self.name = value,
            StateField::Descriptor => self.descriptor = value,
            StateField::Por => self.por = value,
        }
    }
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

    fn bitbox(&self) -> PathBuf {
        self.root.join("bitbox.json")
    }

    fn state(&self) -> PathBuf {
        self.root.join("state.json")
    }
}

fn app_dir() -> Result<PathBuf, Box<dyn Error>> {
    #[cfg(target_os = "linux")]
    {
        return dirs::home_dir()
            .map(|home| home.join(".async-hwi"))
            .ok_or_else(|| invalid_input("home directory is unavailable"));
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

fn read_wallets(
    paths: &Paths,
    fingerprint: Fingerprint,
) -> Result<Vec<WalletState>, Box<dyn Error>> {
    let state: BTreeMap<String, Vec<WalletState>> = read_json_or_default(&paths.state())?;
    Ok(state
        .get(&fingerprint.to_string())
        .cloned()
        .unwrap_or_default())
}

fn write_wallets(
    paths: &Paths,
    fingerprint: Fingerprint,
    wallets: &[WalletState],
) -> Result<(), Box<dyn Error>> {
    let mut state: BTreeMap<String, Vec<WalletState>> = read_json_or_default(&paths.state())?;
    state.insert(fingerprint.to_string(), wallets.to_vec());
    write_json(&paths.state(), &state)
}

fn clear_wallets(paths: &Paths) -> Result<(), Box<dyn Error>> {
    write_json(&paths.state(), &BTreeMap::<String, Vec<WalletState>>::new())
}

fn wallet_state_lines(paths: &Paths) -> Result<Vec<String>, Box<dyn Error>> {
    let state: BTreeMap<String, Vec<WalletState>> = read_json_or_default(&paths.state())?;
    json_lines(&state)
}

fn json_lines<T: Serialize>(value: &T) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(serde_json::to_string_pretty(value)?
        .lines()
        .map(str::to_string)
        .collect())
}

fn bitbox_pairing_lines(paths: &Paths) -> Result<Vec<String>, Box<dyn Error>> {
    let bitbox: NoiseConfigData = read_json_or_default(&paths.bitbox())?;
    json_lines(&bitbox)
}

fn read_bitbox(paths: &Paths, persist: bool) -> Result<Option<NoiseConfigData>, Box<dyn Error>> {
    if persist {
        read_json_or_default(&paths.bitbox())
    } else {
        Ok(None)
    }
}

fn write_bitbox(
    paths: &Paths,
    persist: bool,
    bitbox: Option<NoiseConfigData>,
) -> Result<(), Box<dyn Error>> {
    if persist {
        if let Some(bitbox) = bitbox {
            write_json(&paths.bitbox(), &bitbox)?;
        }
    }
    Ok(())
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

fn wallet_resolver<'a>(
    paths: &'a Paths,
    persist: bool,
    args: WalletArgs,
) -> impl Fn(Fingerprint, DeviceKind) -> Result<Option<command::Wallet>, Box<dyn Error>> + 'a {
    move |fingerprint, kind| {
        resolve_wallet_state(paths, persist, fingerprint, &args, Some(kind)).map(|wallet| {
            wallet.map(|wallet| command::Wallet {
                name: wallet.name,
                policy: wallet.descriptor,
                hmac: wallet.por,
            })
        })
    }
}

fn resolve_wallet_state(
    paths: &Paths,
    persist: bool,
    fingerprint: Fingerprint,
    args: &WalletArgs,
    kind: Option<DeviceKind>,
) -> Result<Option<WalletState>, Box<dyn Error>> {
    if !persist {
        return Ok(args.has_any().then(|| WalletState {
            kind: kind.map(|kind| kind.to_string()),
            name: args.name.clone(),
            descriptor: args.descriptor.clone(),
            por: args.por.clone(),
        }));
    }

    let mut wallets = read_wallets(paths, fingerprint)?;
    let index = select_wallet_index(&mut wallets, args)?;
    if let Some(index) = index {
        merge_wallet(&mut wallets[index], args)?;
        set_kind(&mut wallets[index], kind);
        let wallet = wallets[index].clone();
        write_wallets(paths, fingerprint, &wallets)?;
        Ok(Some(wallet))
    } else if args.has_any() {
        let mut wallet = WalletState::default();
        merge_wallet(&mut wallet, args)?;
        set_kind(&mut wallet, kind);
        wallets.push(wallet.clone());
        write_wallets(paths, fingerprint, &wallets)?;
        Ok(Some(wallet))
    } else {
        Ok(None)
    }
}

fn set_kind(wallet: &mut WalletState, kind: Option<DeviceKind>) {
    if let Some(kind) = kind {
        wallet.kind = Some(kind.to_string());
    }
}

fn save_wallet_state(
    paths: &Paths,
    persist: bool,
    fingerprint: Fingerprint,
    wallet: WalletState,
) -> Result<(), Box<dyn Error>> {
    if !persist {
        return Ok(());
    }

    let mut wallets = read_wallets(paths, fingerprint)?;
    let index =
        select_wallet_index(&mut wallets, &WalletArgs::from(&wallet))?.unwrap_or_else(|| {
            wallets.push(WalletState::default());
            wallets.len() - 1
        });
    wallets[index] = wallet;
    write_wallets(paths, fingerprint, &wallets)
}

impl From<&WalletState> for WalletArgs {
    fn from(wallet: &WalletState) -> Self {
        Self {
            name: wallet.name.clone(),
            descriptor: wallet.descriptor.clone(),
            por: wallet.por.clone(),
        }
    }
}

fn select_wallet_index(
    wallets: &mut [WalletState],
    args: &WalletArgs,
) -> Result<Option<usize>, Box<dyn Error>> {
    if !args.has_any() {
        return match wallets.len() {
            0 => Ok(None),
            1 => Ok(Some(0)),
            _ => Err(invalid_input(
                "multiple wallet states, provide a wallet field",
            )),
        };
    }

    let matches = wallets
        .iter()
        .enumerate()
        .filter_map(|(i, wallet)| wallet_matches(wallet, args).then_some(i))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [index] => Ok(Some(*index)),
        _ => Err(invalid_input(
            "multiple wallet states match provided fields",
        )),
    }
}

fn wallet_matches(wallet: &WalletState, args: &WalletArgs) -> bool {
    field_matches(wallet.name.as_ref(), args.name.as_ref())
        || field_matches(wallet.descriptor.as_ref(), args.descriptor.as_ref())
        || field_matches(wallet.por.as_ref(), args.por.as_ref())
}

fn field_matches(state: Option<&String>, arg: Option<&String>) -> bool {
    matches!((state, arg), (Some(state), Some(arg)) if state == arg)
}

fn merge_wallet(wallet: &mut WalletState, args: &WalletArgs) -> Result<(), Box<dyn Error>> {
    merge_state_field(&mut wallet.name, args.name.clone(), "name")?;
    merge_state_field(
        &mut wallet.descriptor,
        args.descriptor.clone(),
        "descriptor",
    )?;
    merge_state_field(&mut wallet.por, args.por.clone(), "proof of registration")?;
    Ok(())
}

fn merge_state_field(
    state_value: &mut Option<String>,
    arg_value: Option<String>,
    field_name: &'static str,
) -> Result<(), Box<dyn Error>> {
    match (state_value.as_ref(), arg_value) {
        (Some(state_value), Some(arg_value)) if state_value != &arg_value => Err(invalid_input(
            format!("{field_name} does not match persisted state"),
        )),
        (None, Some(arg_value)) => {
            *state_value = Some(arg_value);
            Ok(())
        }
        _ => Ok(()),
    }
}

async fn list_devices(
    network: Network,
    bitbox: Option<NoiseConfigData>,
) -> Result<Vec<command::Device>, Box<dyn Error>> {
    command::list(network, None, bitbox)
        .await
        .map(|(devices, _)| devices)
}

async fn resolve_state_fingerprint(
    network: Network,
    fingerprint: Option<Fingerprint>,
) -> Result<Fingerprint, Box<dyn Error>> {
    if let Some(fingerprint) = fingerprint {
        return Ok(fingerprint);
    }

    let devices = list_devices(network, None).await?;
    match devices.as_slice() {
        [] => Err(invalid_input("no device connected")),
        [device] => Ok(device.fingerprint),
        _ => {
            let mut lines = vec!["multiple devices connected, pass --fingerprint:".to_string()];
            lines.extend(device_lines(devices).await?);
            Err(invalid_input(lines.join("\n")))
        }
    }
}

async fn output_device_list(
    output: Option<&PathBuf>,
    devices: Vec<command::Device>,
) -> Result<(), Box<dyn Error>> {
    output_lines(output, &device_lines(devices).await?)
}

async fn device_lines(mut devices: Vec<command::Device>) -> Result<Vec<String>, Box<dyn Error>> {
    let mut lines = Vec::new();
    for entry in devices.iter_mut() {
        let mut line = format!("{} {}", entry.fingerprint, entry.kind);
        if let Ok(version) = entry.device.get_version().await.map(|v| v.to_string()) {
            line.push_str(&format!(" {version}"));
        }
        lines.push(line);
    }
    Ok(lines)
}

fn wallet_name_for_device(kind: DeviceKind, name: Option<&String>) -> Result<&str, Box<dyn Error>> {
    match kind {
        DeviceKind::Ledger
        | DeviceKind::LedgerSimulator
        | DeviceKind::Coldcard
        | DeviceKind::Jade => name
            .map(String::as_str)
            .ok_or_else(|| invalid_input("wallet name is required")),
        DeviceKind::BitBox02
        | DeviceKind::Specter
        | DeviceKind::SpecterSimulator
        | DeviceKind::Trezor
        | DeviceKind::TrezorSimulator => Ok(""),
    }
}

fn matches_fingerprint(expected: Option<Fingerprint>, actual: Fingerprint) -> bool {
    expected.map_or(true, |expected| expected == actual)
}

fn read_state_value(value: Option<String>) -> Result<String, Box<dyn Error>> {
    if let Some(value) = value {
        return Ok(value);
    }

    read_stdin("value")
}

fn read_stdin(name: &'static str) -> Result<String, Box<dyn Error>> {
    let mut stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(invalid_input(format!(
            "{name} is required unless stdin is piped"
        )));
    }

    let mut input = String::new();
    stdin.read_to_string(&mut input)?;
    Ok(input.trim_end().to_string())
}

fn resolve_psbt(psbt: Option<Psbt>, psbt_file: Option<PathBuf>) -> Result<Psbt, Box<dyn Error>> {
    match (psbt, psbt_file) {
        (Some(_), Some(_)) => Err(invalid_input("use either --psbt or --psbt-file")),
        (Some(psbt), None) => Ok(psbt),
        (None, Some(path)) => Ok(std::fs::read_to_string(path)?.trim_end().parse()?),
        (None, None) => Ok(read_stdin("psbt")?.parse()?),
    }
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
