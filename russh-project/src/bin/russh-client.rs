use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use russh::client::Handler;
use russh::{ChannelMsg, CryptoVec};
use russh_keys::key::PublicKey;
use russh_project::crate_version;
use tokio::io::{AsyncWriteExt, stderr, stdout};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse()?;
    let (host, port) = split_target(&args.target)?;
    log::info!(
        "connecting to {host}:{port} as {} (russh {})",
        args.user,
        crate_version()
    );

    let config = Arc::new(russh::client::Config {
        inactivity_timeout: Some(Duration::from_secs(600)),
        ..Default::default()
    });
    let mut session = russh::client::connect(config, (host, port), ClientHandler)
        .await
        .with_context(|| format!("tcp connection to {host}:{port} failed"))?;

    let authenticated = if let Some(key_path) = &args.key {
        let key = russh_keys::load_secret_key(key_path, None)
            .with_context(|| format!("failed to load {}", key_path.display()))?;
        session
            .authenticate_publickey(&args.user, Arc::new(key))
            .await?
    } else {
        let password = args.password.clone().ok_or_else(|| {
            anyhow!("set --password, --key, RUSSH_PASSWORD, or LAB_SSH_PASSWORD")
        })?;
        session.authenticate_password(&args.user, password).await?
    };
    if !authenticated {
        anyhow::bail!("authentication failed for {}", args.user);
    }

    let mut channel = session.channel_open_session().await?;
    channel.exec(true, args.command.join(" ")).await?;

    let mut stdout = stdout();
    let mut stderr = stderr();
    let mut code = None;
    loop {
        let Some(msg) = channel.wait().await else {
            break;
        };
        match msg {
            ChannelMsg::Data { data } => {
                stdout.write_all(as_bytes(&data)).await?;
                stdout.flush().await?;
            }
            ChannelMsg::ExtendedData { data, ext: 1 } => {
                stderr.write_all(as_bytes(&data)).await?;
                stderr.flush().await?;
            }
            ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
            ChannelMsg::Eof | ChannelMsg::Close => break,
            ChannelMsg::Failure => anyhow::bail!("the server rejected the command"),
            _ => {}
        }
    }
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;
    std::process::exit(code.unwrap_or(1) as i32);
}

fn as_bytes(data: &CryptoVec) -> &[u8] {
    data
}

struct ClientHandler;

#[async_trait]
impl Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        self,
        server_public_key: &PublicKey,
    ) -> Result<(Self, bool), Self::Error> {
        log::info!(
            "accepting server host key {} (known_hosts checking is not enabled yet)",
            server_public_key.name()
        );
        Ok((self, true))
    }
}

struct Args {
    target: String,
    user: String,
    password: Option<String>,
    key: Option<PathBuf>,
    command: Vec<String>,
}

impl Args {
    fn parse() -> anyhow::Result<Self> {
        let mut target = None;
        let mut user = "lab".to_string();
        let mut password = std::env::var("RUSSH_PASSWORD")
            .or_else(|_| std::env::var("LAB_SSH_PASSWORD"))
            .ok();
        let mut key = None;
        let mut command = Vec::new();
        let mut argv = std::env::args().skip(1);
        while let Some(arg) = argv.next() {
            match arg.as_str() {
                "--target" => target = Some(need(&mut argv, "--target")?),
                "--user" => user = need(&mut argv, "--user")?,
                "--password" => password = Some(need(&mut argv, "--password")?),
                "--key" => key = Some(PathBuf::from(need(&mut argv, "--key")?)),
                "--" => {
                    command.extend(argv);
                    break;
                }
                "-h" | "--help" => {
                    println!("{}", usage());
                    std::process::exit(0);
                }
                other if command.is_empty() && !other.starts_with('-') && target.is_none() => {
                    target = Some(other.to_string());
                }
                other => anyhow::bail!("unknown argument {other}\n{}", usage()),
            }
        }
        let target = target.ok_or_else(|| anyhow!("missing --target HOST:PORT\n{}", usage()))?;
        if command.is_empty() {
            anyhow::bail!("missing command after --\n{}", usage());
        }
        Ok(Self {
            target,
            user,
            password,
            key,
            command,
        })
    }
}

fn need(argv: &mut impl Iterator<Item = String>, flag: &str) -> anyhow::Result<String> {
    argv.next()
        .ok_or_else(|| anyhow!("{flag} requires a value"))
}

fn usage() -> &'static str {
    "russh-client --target HOST:PORT [--user USER] [--password PASS | --key PATH] -- COMMAND...\n\
     \n\
     Opens one SSH exec channel and writes the remote output locally.\n\
     The process exit code is the remote command status.\n\
     Host key checking is intentionally open until lab keys are provisioned."
}

fn split_target(target: &str) -> anyhow::Result<(&str, u16)> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("target must look like HOST:PORT"))?;
    if host.is_empty() {
        anyhow::bail!("target host is empty");
    }
    let port = port
        .parse()
        .with_context(|| format!("invalid port in {target}"))?;
    Ok((host, port))
}
