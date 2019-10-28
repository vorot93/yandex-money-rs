#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::default_trait_access)]

use bigdecimal::*;
use chrono::prelude::*;
use phonenumber::*;
use serde::*;
use std::{path::*, str::FromStr};
use structopt::*;
use tokio::stream::*;
use url::Url;
use yandex_money::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    token: String,
}

fn config_location() -> PathBuf {
    let mut path = xdg::BaseDirectories::new().unwrap().get_config_home();
    path.push("yandex-money-cli/config.toml");

    path
}

#[derive(Debug, StructOpt)]
struct AuthorizeData {
    #[structopt(long, env = "CLIENT_ID")]
    client_id: String,
    #[structopt(long, env = "CLIENT_REDIRECT")]
    client_redirect: String,
    #[structopt(short)]
    do_not_store_on_disk: bool,
}

#[derive(Debug, StructOpt)]
enum UnauthorizedCmd {
    /// Authorize client
    Login(AuthorizeData),
}

#[derive(Debug, StructOpt)]
struct To {
    #[structopt(long, conflicts_with_all = &["to-email", "to-phone"])]
    to_account: Option<u64>,
    #[structopt(long, conflicts_with_all = &["to-account", "to-phone"])]
    to_email: Option<String>,
    #[structopt(long, conflicts_with_all = &["to-account", "to-email"])]
    to_phone: Option<PhoneNumber>,
}

impl From<To> for Option<UserId> {
    fn from(value: To) -> Self {
        if let Some(v) = value.to_account {
            return Some(UserId::Account(v));
        }

        if let Some(v) = value.to_email {
            return Some(UserId::Email(v));
        }

        if let Some(v) = value.to_phone {
            return Some(UserId::Phone(v));
        }

        None
    }
}

#[derive(Debug, StructOpt)]
struct Amount {
    #[structopt(long, conflicts_with = "amount-total")]
    amount_net: Option<BigDecimal>,
    #[structopt(long, conflicts_with = "amount-net")]
    amount_total: Option<BigDecimal>,
}

impl From<Amount> for Option<RequestAmount> {
    fn from(value: Amount) -> Self {
        if let Some(v) = value.amount_net {
            return Some(RequestAmount::Net(v));
        }

        if let Some(v) = value.amount_total {
            return Some(RequestAmount::Total(v));
        }

        None
    }
}

#[derive(Debug, StructOpt)]
#[allow(clippy::large_enum_variant)]
enum AuthorizedCmd {
    /// Reauthorize client
    Login(AuthorizeData),
    /// Revoke token
    Revoke,
    /// Request transfer
    RequestTransfer {
        #[structopt(flatten)]
        to: To,
        #[structopt(flatten)]
        amount: Amount,
        #[structopt(long)]
        comment: Option<String>,
        #[structopt(long)]
        message: Option<String>,
        #[structopt(long)]
        label: Option<String>,
        #[structopt(long)]
        codepro: Option<bool>,
        #[structopt(long)]
        hold_for_pickup: Option<bool>,
        #[structopt(long)]
        expire_period: Option<u32>,
    },
    /// Process existing payment
    ProcessPayment {
        #[structopt(long)]
        request_id: String,
        #[structopt(long)]
        money_source: ProcessPaymentMoneySource,
    },
    /// Show operation history
    OperationHistory {
        #[structopt(long)]
        from: Option<DateTime<Utc>>,
        #[structopt(long)]
        till: Option<DateTime<Utc>>,
        #[structopt(long)]
        detailed: bool,
    },
}

async fn do_authorize(
    AuthorizeData {
        client_id,
        client_redirect,
        do_not_store_on_disk,
    }: AuthorizeData,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = UnauthorizedClient::new(client_id, client_redirect);

    let permanent_token = client
        .authorize(
            vec![
                AccessScope::AccountInfo,
                AccessScope::OperationHistory,
                AccessScope::PaymentP2P,
            ]
            .into_iter()
            .collect(),
            |redirect_addr| async move {
                println!("Please open this page in your browser: {}", redirect_addr);
                println!("Copy and paste your redirect URI here");

                let mut stdin = tokio_util::codec::FramedRead::new(
                    tokio::io::stdin(),
                    tokio_util::codec::LinesCodec::new(),
                );
                let uri = stdin.next().await.unwrap().unwrap();

                let uri = Url::from_str(&uri.replace('\n', ""))?;

                let token = uri
                    .query_pairs()
                    .find_map(|(key, value)| {
                        if *key == *"code" {
                            Some(value.to_string())
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| "Authorization code not found in redirect URL")?;

                println!("Extracted token: {}", token);

                Ok(token)
            },
        )
        .await?;

    if !do_not_store_on_disk {
        let path = config_location();
        println!("Saving token on disk to {}", path.to_string_lossy());
        let _ = std::fs::create_dir_all(&path);
        tokio::fs::write(
            path,
            toml::to_vec(&Config {
                token: permanent_token.clone(),
            })
            .unwrap(),
        )
        .await
        .unwrap();
    }

    println!("Your permanent token is {:?}", permanent_token);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let token = match std::env::var("TOKEN").ok() {
        Some(v) => Some(v),
        None => {
            async move {
                if let Ok(data) = tokio::fs::read(config_location()).await {
                    if let Ok(config) = toml::from_slice::<Config>(&data) {
                        return Some(config.token);
                    }
                }

                return None;
            }
            .await
        }
    };

    match token {
        None => match UnauthorizedCmd::from_args() {
            UnauthorizedCmd::Login(data) => do_authorize(data).await?,
        },
        Some(token) => match AuthorizedCmd::from_args() {
            AuthorizedCmd::Login(data) => do_authorize(data).await?,
            other => {
                println!("Using token {}", token);
                let client = Client::new(Some(token.clone()));
                match other {
                    AuthorizedCmd::Revoke => {
                        client.revoke_token().await?;
                        println!("Token {} successfully revoked", token)
                    }
                    AuthorizedCmd::RequestTransfer {
                        to,
                        amount,
                        comment,
                        message,
                        label,
                        codepro,
                        hold_for_pickup,
                        expire_period,
                    } => {
                        let to = Option::from(to).ok_or("User ID not specified")?;
                        let amount = Option::from(amount).ok_or("Transfer amount not specified")?;

                        let payment_request = client.request_transfer(
                            to,
                            amount,
                            comment.unwrap_or_default(),
                            message.unwrap_or_default(),
                            label,
                            codepro.unwrap_or_default(),
                            hold_for_pickup.unwrap_or_default(),
                            expire_period.unwrap_or_default(),
                        );

                        let res = payment_request.send().await;

                        println!("Payment request result is {:?}", res);
                    }
                    AuthorizedCmd::OperationHistory {
                        detailed,
                        from,
                        till,
                    } => {
                        let mut history = client.operation_history(
                            Default::default(),
                            None,
                            from,
                            till,
                            0,
                            detailed,
                        );

                        while let Some(v) = history.next().await.transpose()? {
                            println!("{:?}", v);
                        }
                    }
                    other => unimplemented!("{:?}", other),
                }
            }
        },
    };

    Ok(())
}
