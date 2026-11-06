use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use russh::server::{Auth, Msg, Session};
use russh::{ChannelId, CryptoVec, Pty};
use russh_keys::key::{KeyPair, PublicKey};
use russh_project::{authorized, crate_version, load_authorized_keys, password_accepted};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse()?;
    let host_key = load_or_create_host_key(&args.host_key)?;
    let authorized_keys = load_authorized_keys(&args.authorized_keys)?;
    log::info!(
        "russh-server listening on {} (russh {}), {} authorized public key(s)",
        args.listen,
        crate_version(),
        authorized_keys.len()
    );

    let config = Arc::new(russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_millis(200),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![host_key],
        ..Default::default()
    });
    let app = App {
        password: args.password,
        authorized_keys,
    };
    russh::server::run(config, &args.listen, app)
        .await
        .context("ssh listener failed")?;
    Ok(())
}

struct Args {
    listen: String,
    host_key: PathBuf,
    authorized_keys: PathBuf,
    password: String,
}

impl Args {
    fn parse() -> anyhow::Result<Self> {
        let mut listen = "0.0.0.0:2223".to_string();
        let mut host_key = PathBuf::from(
            std::env::var("RUSSH_HOST_KEY").unwrap_or_else(|_| "/etc/russh/ssh_host_ed25519_key".into()),
        );
        let mut authorized_keys = PathBuf::from(
            std::env::var("RUSSH_AUTHORIZED_KEYS")
                .unwrap_or_else(|_| "/etc/russh/authorized_keys".into()),
        );
        let mut password = std::env::var("RUSSH_PASSWORD")
            .or_else(|_| std::env::var("LAB_SSH_PASSWORD"))
            .ok();
        let mut argv = std::env::args().skip(1);
        while let Some(arg) = argv.next() {
            match arg.as_str() {
                "--listen" => listen = need(&mut argv, "--listen")?,
                "--host-key" => host_key = PathBuf::from(need(&mut argv, "--host-key")?),
                "--authorized-keys" => {
                    authorized_keys = PathBuf::from(need(&mut argv, "--authorized-keys")?)
                }
                "--password" => password = Some(need(&mut argv, "--password")?),
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument {other}\n{}", usage()),
            }
        }
        let password = password.ok_or_else(|| {
            anyhow!("set --password, RUSSH_PASSWORD, or LAB_SSH_PASSWORD")
        })?;
        if password.is_empty() {
            anyhow::bail!("the lab password is empty");
        }
        Ok(Self {
            listen,
            host_key,
            authorized_keys,
            password,
        })
    }
}

fn need(argv: &mut impl Iterator<Item = String>, flag: &str) -> anyhow::Result<String> {
    argv.next()
        .ok_or_else(|| anyhow!("{flag} requires a value"))
}

fn usage() -> &'static str {
    "russh-server [--listen ADDR:PORT] [--host-key PATH] [--authorized-keys PATH] [--password PASS]\n\
     \n\
     Listens for SSH sessions. Password authentication accepts root and lab.\n\
     Public keys in the authorized_keys file are accepted for those same names\n\
     when the file exists. A missing host key is generated and written to PATH."
}

fn print_usage() {
    println!("{}", usage());
}

fn load_or_create_host_key(path: &Path) -> anyhow::Result<KeyPair> {
    if path.exists() {
        return russh_keys::load_secret_key(path, None)
            .with_context(|| format!("failed to load host key {}", path.display()));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    let key = KeyPair::generate_ed25519().ok_or_else(|| anyhow!("ed25519 host key generation failed"))?;
    let mut file = std::fs::File::create(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    russh_keys::encode_pkcs8_pem(&key, &mut file)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    log::info!("wrote new host key to {}", path.display());
    Ok(key)
}

#[derive(Clone)]
struct App {
    password: String,
    authorized_keys: Vec<PublicKey>,
}

impl russh::server::Server for App {
    type Handler = Handler;
    fn new_client(&mut self, peer: Option<std::net::SocketAddr>) -> Self::Handler {
        log::info!("connection from {peer:?}");
        Handler {
            password: self.password.clone(),
            authorized_keys: self.authorized_keys.clone(),
            shell: None,
            shell_buf: String::new(),
        }
    }
}

struct Handler {
    password: String,
    authorized_keys: Vec<PublicKey>,
    shell: Option<ChannelId>,
    shell_buf: String,
}

#[async_trait]
impl russh::server::Handler for Handler {
    type Error = anyhow::Error;

    async fn auth_password(self, user: &str, password: &str) -> Result<(Self, Auth), Self::Error> {
        let ok = password_accepted(user, password, &self.password);
        log::info!("password authentication for {user}: {}", if ok { "accepted" } else { "rejected" });
        Ok((self, if ok { Auth::Accept } else { reject() }))
    }

    async fn auth_publickey_offered(
        self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<(Self, Auth), Self::Error> {
        let ok = authorized(user, public_key, &self.authorized_keys);
        Ok((self, if ok { Auth::Accept } else { reject() }))
    }

    async fn auth_publickey(self, user: &str, public_key: &PublicKey) -> Result<(Self, Auth), Self::Error> {
        let ok = authorized(user, public_key, &self.authorized_keys);
        log::info!("public key authentication for {user}: {}", if ok { "accepted" } else { "rejected" });
        Ok((self, if ok { Auth::Accept } else { reject() }))
    }

    async fn channel_open_session(
        self,
        _channel: russh::Channel<Msg>,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        Ok((self, true, session))
    }

    async fn pty_request(
        self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        session.channel_success(channel);
        Ok((self, session))
    }

    async fn env_request(
        self,
        channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        session.channel_success(channel);
        Ok((self, session))
    }

    async fn shell_request(
        mut self,
        channel: ChannelId,
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        session.channel_success(channel);
        self.shell = Some(channel);
        let banner = format!(
            "russh-project lab shell (russh {}). Type a command, or exit.\r\n",
            crate_version()
        );
        session.data(channel, cryptovec(banner.as_bytes()));
        Ok((self, session))
    }

    async fn exec_request(
        self,
        channel: ChannelId,
        data: &[u8],
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        session.channel_success(channel);
        let (code, stdout, stderr) = run_sh(&command).await;
        if !stdout.is_empty() {
            session.data(channel, cryptovec(&stdout));
        }
        if !stderr.is_empty() {
            session.extended_data(channel, 1, cryptovec(&stderr));
        }
        session.exit_status_request(channel, code);
        session.eof(channel);
        session.close(channel);
        Ok((self, session))
    }

    async fn data(
        mut self,
        channel: ChannelId,
        data: &[u8],
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if self.shell != Some(channel) {
            return Ok((self, session));
        }
        self.shell_buf.push_str(&String::from_utf8_lossy(data));
        if self.shell_buf.len() > 65_536 {
            self.shell_buf.clear();
            session.data(channel, cryptovec(b"command too long\r\n"));
            return Ok((self, session));
        }
        let mut lines = Vec::new();
        while let Some(index) = self.shell_buf.find('\n') {
            let mut line = self.shell_buf.drain(..=index).collect::<String>();
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
            let line = line.trim().to_string();
            if !line.is_empty() {
                lines.push(line);
            }
        }
        for line in lines {
            if line == "exit" {
                session.exit_status_request(channel, 0);
                session.eof(channel);
                session.close(channel);
                self.shell = None;
                break;
            }
            let (code, stdout, stderr) = run_sh(&line).await;
            if !stdout.is_empty() {
                session.data(channel, cryptovec(&stdout));
            }
            if !stderr.is_empty() {
                session.extended_data(channel, 1, cryptovec(&stderr));
            }
            if code != 0 {
                let note = format!("exit {code}\r\n");
                session.data(channel, cryptovec(note.as_bytes()));
            }
        }
        Ok((self, session))
    }
}

fn reject() -> Auth {
    Auth::Reject {
        proceed_with_methods: None,
    }
}

fn cryptovec(bytes: &[u8]) -> CryptoVec {
    CryptoVec::from(bytes.to_vec())
}

async fn run_sh(command: &str) -> (u32, Vec<u8>, Vec<u8>) {
    match tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .await
    {
        Ok(output) => {
            let code = output.status.code().unwrap_or(1);
            let code = if code < 0 { 1 } else { code as u32 };
            (code, output.stdout, output.stderr)
        }
        Err(err) => (127, format!("exec failed: {err}\n").into_bytes(), Vec::new()),
    }
}
