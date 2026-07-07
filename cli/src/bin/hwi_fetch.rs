use std::{error::Error, process::ExitCode, str::FromStr};

use async_hwi_cli::command;
use bitcoin::{bip32::DerivationPath, Network};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// default will be the Bitcoin mainnet network.
    #[arg(long, value_parser = clap::value_parser!(bitcoin::Network), default_value_t = bitcoin::Network::Bitcoin)]
    network: Network,
}

struct Stats {
    total: u32,
    success: u32,
    failure: u32,
}

#[tokio::main]
async fn main() -> Result<ExitCode, Box<dyn Error>> {
    let args = Args::parse();
    let Some(device) = command::list(args.network, None).await?.into_iter().next() else {
        return Err("no device found".into());
    };

    let mut stats = Stats {
        total: 0,
        success: 0,
        failure: 0,
    };
    let coin_type = match args.network {
        Network::Bitcoin => 0,
        Network::Testnet | Network::Testnet4 | Network::Signet | Network::Regtest => 1,
        _ => 1,
    };

    for purpose in [49, 84, 86] {
        for account in 0..10 {
            fetch_xpub(
                device.as_ref(),
                format!("m/{purpose}'/{coin_type}'/{account}'"),
                &mut stats,
            )
            .await;
        }
    }

    for account in 0..10 {
        for script_type in [1, 2] {
            fetch_xpub(
                device.as_ref(),
                format!("m/48'/{coin_type}'/{account}'/{script_type}'"),
                &mut stats,
            )
            .await;
        }
    }

    for account in 0..10 {
        fetch_xpub(
            device.as_ref(),
            format!("m/87'/{coin_type}'/{account}'"),
            &mut stats,
        )
        .await;
    }

    eprintln!();
    eprintln!("Total:   {}", stats.total);
    eprintln!("Success: {}", stats.success);
    eprintln!("Failure: {}", stats.failure);

    if stats.failure == 0 {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

async fn fetch_xpub(device: &(dyn async_hwi::HWI + Send), path: String, stats: &mut Stats) {
    stats.total += 1;

    let derivation = match DerivationPath::from_str(&path) {
        Ok(derivation) => derivation,
        Err(e) => {
            stats.failure += 1;
            eprintln!("ERROR path={path}");
            eprintln!("{e}");
            return;
        }
    };

    match device.get_extended_pubkey(&derivation).await {
        Ok(_) => {
            stats.success += 1;
            eprint!("+");
        }
        Err(e) => {
            stats.failure += 1;
            eprintln!("ERROR path={path}");
            eprintln!("{e}");
        }
    }
}
