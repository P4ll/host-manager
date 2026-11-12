#![allow(dead_code)]

use std::{
    ffi::OsStr,
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

use chrono::{Days, Local};
use host_manager::{
    model::{Billing, BillingPeriod, Host, SshConfig},
    store::Environment,
};
use rust_decimal::Decimal;
use tempfile::TempDir;
use uuid::Uuid;

pub struct Fixture {
    pub temp: TempDir,
    pub env: Environment,
    pub root: PathBuf,
    pub dir: PathBuf,
}

impl Fixture {
    pub fn new() -> Self {
        // A short path also keeps gpg-agent's Unix socket below the platform limit.
        let temp = tempfile::Builder::new()
            .prefix("host-manager-")
            .tempdir_in("/tmp")
            .expect("temporary fixture");
        let base = fs::canonicalize(temp.path()).expect("canonical fixture path");
        let root = base.join("store");
        let dir = root.join("host-manager");
        let gnupg = base.join("gpg");
        fs::create_dir_all(&gnupg).expect("isolated GPG home");
        fs::set_permissions(&gnupg, fs::Permissions::from_mode(0o700)).expect("GPG permissions");
        let mut env: Environment = std::env::vars_os()
            .filter(|(key, _)| {
                let name = key.to_string_lossy();
                !name.starts_with("GIT_")
                    && !name.starts_with("PASSWORD_STORE_")
                    && !matches!(
                        name.as_ref(),
                        "HOST_MANAGER_PASS_DIR" | "GPG_AGENT_INFO" | "GPG_TTY" | "GNUPGHOME"
                    )
            })
            .collect();
        for (key, value) in [
            ("HOME", base.clone()),
            ("GNUPGHOME", gnupg),
            ("PASSWORD_STORE_DIR", root.clone()),
            ("XDG_CACHE_HOME", base.join("cache")),
        ] {
            env.insert(key.into(), value.into_os_string());
        }
        env.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
        env.insert("GIT_CONFIG_GLOBAL".into(), "/dev/null".into());
        env.insert("PASSWORD_STORE_ENABLE_EXTENSIONS".into(), "false".into());
        env.insert(
            "PASSWORD_STORE_GPG_OPTS".into(),
            "--batch --no-auto-key-retrieve".into(),
        );
        let fixture = Self {
            temp,
            env,
            root,
            dir,
        };
        let fingerprint = fixture.generate_key("Host Manager Test <test@example.invalid>");
        fixture.checked(fixture.command("pass").args(["init", &fingerprint]));
        fixture.checked(
            fixture
                .command("git")
                .arg("-C")
                .arg(&fixture.root)
                .arg("init"),
        );
        fixture.checked(fixture.command("git").arg("-C").arg(&fixture.root).args([
            "config",
            "user.name",
            "Host Manager Test",
        ]));
        fixture.checked(fixture.command("git").arg("-C").arg(&fixture.root).args([
            "config",
            "user.email",
            "test@example.invalid",
        ]));
        fixture.checked(
            fixture
                .command("git")
                .arg("-C")
                .arg(&fixture.root)
                .args(["add", ".gpg-id"]),
        );
        fixture.checked(fixture.command("git").arg("-C").arg(&fixture.root).args([
            "commit",
            "-m",
            "Initialize test store",
        ]));
        fixture
    }

    pub fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command.env_clear().envs(&self.env).stdin(Stdio::null());
        command
    }

    pub fn checked(&self, command: &mut Command) -> Output {
        let output = command
            .output()
            .expect("required real pass/GPG/Git tool is unavailable; storage check NOT performed");
        assert!(
            output.status.success(),
            "real isolated fixture command failed; storage check NOT performed"
        );
        output
    }

    pub fn generate_key(&self, identity: &str) -> String {
        self.checked(self.command("gpg").args([
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            identity,
            "default",
            "default",
            "1d",
        ]));
        let listed = self.checked(self.command("gpg").args([
            "--batch",
            "--with-colons",
            "--list-secret-keys",
            identity,
        ]));
        String::from_utf8(listed.stdout)
            .expect("GPG fingerprint output")
            .lines()
            .find_map(|line| {
                let fields: Vec<_> = line.split(':').collect();
                (fields.first() == Some(&"fpr"))
                    .then(|| fields.get(9).copied())
                    .flatten()
                    .map(str::to_owned)
            })
            .expect("isolated test key fingerprint")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(home) = self.env.get(OsStr::new("GNUPGHOME")) {
            let _ = self
                .command("gpgconf")
                .arg("--homedir")
                .arg(home)
                .args(["--kill", "gpg-agent"])
                .output();
        }
    }
}

pub fn sample_host() -> Host {
    Host {
        id: Uuid::new_v4(),
        name: "example-vps".into(),
        provider: "Example Hosting".into(),
        panel_url: None,
        account_login: None,
        account_password: None,
        notes: String::new(),
        archived: false,
        ssh: Some(SshConfig {
            host: "127.0.0.1".into(),
            user: Some("root".into()),
            port: Some(22),
            identity_file: None,
            password: None,
        }),
        billing: Billing {
            amount: Decimal::new(500, 2),
            currency: "EUR".into(),
            period: BillingPeriod::Month,
            period_note: None,
            next_due: Some(
                Local::now()
                    .date_naive()
                    .checked_add_days(Days::new(30))
                    .unwrap(),
            ),
        },
        payments: Vec::new(),
    }
}
