mod common;

use std::{
    ffi::OsStr,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use common::{Fixture, sample_host};
use host_manager::{
    model::{Catalog, Host},
    ssh::ssh_command,
    store::PassStore,
};
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_host-manager");
const SERVER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/askpass-server");
const PTY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/askpass-pty");

fn save(fixture: &Fixture, host: Host) {
    let mut store = PassStore::open(&fixture.dir, fixture.env.clone()).unwrap();
    store.load().unwrap();
    store
        .save(&Catalog {
            version: 1,
            hosts: vec![host],
        })
        .unwrap();
}

struct Snapshot {
    ciphertext: Vec<u8>,
    head: Vec<u8>,
    index: Vec<u8>,
}

impl Snapshot {
    fn take(fixture: &Fixture) -> Self {
        let output = fixture.checked(
            fixture
                .command("git")
                .arg("-C")
                .arg(&fixture.root)
                .args(["rev-parse", "HEAD"]),
        );
        Self {
            ciphertext: fs::read(fixture.dir.join("catalog.gpg")).unwrap(),
            head: output.stdout,
            index: fs::read(fixture.root.join(".git/index")).unwrap(),
        }
    }

    fn assert_unchanged(&self, fixture: &Fixture) {
        let after = Self::take(fixture);
        assert_eq!(self.ciphertext, after.ciphertext);
        assert_eq!(self.head, after.head);
        assert_eq!(self.index, after.index);
        assert!(!fixture.dir.join("catalog.pending.gpg").exists());
    }
}

fn no_secret(output: &Output, secret: &str) {
    for bytes in [&output.stdout, &output.stderr] {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "saved password leaked to output"
        );
    }
}

fn no_plaintext_files(directory: &Path, secret: &str) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let metadata = entry.file_type().unwrap();
        if metadata.is_dir() {
            no_plaintext_files(&entry.path(), secret);
        } else if metadata.is_file() {
            let bytes = fs::read(entry.path()).unwrap();
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "saved password leaked to a fixture file"
            );
        }
    }
}

fn no_plaintext_history(fixture: &Fixture, secret: &str) {
    let objects = fixture.checked(fixture.command("git").arg("-C").arg(&fixture.root).args([
        "rev-list",
        "--objects",
        "--all",
    ]));
    for line in String::from_utf8(objects.stdout).unwrap().lines() {
        let id = line.split_whitespace().next().unwrap();
        let blob = fixture
            .command("git")
            .arg("-C")
            .arg(&fixture.root)
            .args(["cat-file", "blob", id])
            .output()
            .unwrap();
        if blob.status.success() {
            no_secret(&blob, secret);
        }
    }
}

fn helper(fixture: &Fixture, host: &Host) -> Command {
    let config = host.ssh.as_ref().unwrap();
    let routing = ssh_command(config, host.id, &fixture.dir, &fixture.env).unwrap();
    for arg in routing.get_args() {
        assert!(
            !arg.to_string_lossy()
                .contains(config.password.as_deref().unwrap())
        );
    }
    let mut command = fixture.command(BIN);
    for (key, value) in routing.get_envs() {
        if let Some(value) = value {
            assert!(
                !value
                    .to_string_lossy()
                    .contains(config.password.as_deref().unwrap()),
                "saved password leaked to environment"
            );
            command.env(key, value);
        }
    }
    command
        .env("HOST_MANAGER_SSH_INTERNAL", "askpass")
        .env("HOST_MANAGER_ASKPASS_PID", std::process::id().to_string())
        .env_remove("SSH_ASKPASS_PROMPT")
        .arg("hmtest@127.0.0.1's password: ");
    command
}

#[test]
fn real_binary_helper_is_readonly_and_fails_closed() {
    let fixture = Fixture::new();
    let secret = format!("ASKPASS-{}", Uuid::new_v4());
    let mut host = sample_host();
    host.ssh.as_mut().unwrap().password = Some(secret.clone());
    save(&fixture, host.clone());
    let before = Snapshot::take(&fixture);

    let output = helper(&fixture, &host).output().unwrap();
    assert!(
        output.status.success(),
        "actual helper rejected valid isolated context"
    );
    assert!(
        output.stdout == format!("{secret}\n").as_bytes(),
        "helper did not return exactly one password line"
    );
    assert!(output.stderr.is_empty());
    before.assert_unchanged(&fixture);

    for (key, value) in [
        ("HOST_MANAGER_ASKPASS_TARGET", "0".repeat(64)),
        ("HOST_MANAGER_ASKPASS_ID", Uuid::new_v4().to_string()),
        ("HOST_MANAGER_ASKPASS_PID", "0".to_owned()),
    ] {
        let output = helper(&fixture, &host).env(key, value).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        no_secret(&output, &secret);
        before.assert_unchanged(&fixture);
    }

    let empty_keyring = fixture.temp.path().join("empty-keyring");
    fs::create_dir(&empty_keyring).unwrap();
    fs::set_permissions(&empty_keyring, fs::Permissions::from_mode(0o700)).unwrap();
    let output = helper(&fixture, &host)
        .env("GNUPGHOME", &empty_keyring)
        .output()
        .unwrap();
    let _ = fixture
        .command("gpgconf")
        .arg("--homedir")
        .arg(&empty_keyring)
        .args(["--kill", "gpg-agent"])
        .output();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    no_secret(&output, &secret);
    before.assert_unchanged(&fixture);

    let mut changed = host.clone();
    changed.ssh.as_mut().unwrap().host = "different-target.invalid".into();
    save(&fixture, changed);
    let changed_snapshot = Snapshot::take(&fixture);
    let output = helper(&fixture, &host).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    no_secret(&output, &secret);
    changed_snapshot.assert_unchanged(&fixture);
    for password in [None, Some(String::new())] {
        let mut changed = host.clone();
        changed.ssh.as_mut().unwrap().password = password;
        save(&fixture, changed);
        let snapshot = Snapshot::take(&fixture);
        let output = helper(&fixture, &host).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        no_secret(&output, &secret);
        snapshot.assert_unchanged(&fixture);
    }
    no_plaintext_files(fixture.temp.path(), &secret);
    no_plaintext_history(&fixture, &secret);
}

struct Server {
    state: tempfile::TempDir,
    port: u16,
}

impl Server {
    fn start(password: &str) -> Self {
        let state = tempfile::tempdir().unwrap();
        let mut child = Command::new(SERVER)
            .arg("start")
            .arg(state.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("real SSH prerequisite unavailable: executable server support is required");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{password}\n").as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        if !output.status.success() {
            let _ = Command::new(SERVER).arg("stop").arg(state.path()).output();
            panic!(
                "real SSH password check NOT performed: disposable Docker server setup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let port = fs::read_to_string(state.path().join("port"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let server = Self { state, port };
        let deadline = Instant::now() + Duration::from_secs(15);
        let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        loop {
            if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(200))
            {
                stream
                    .set_read_timeout(Some(Duration::from_millis(200)))
                    .unwrap();
                let mut banner = [0; 4];
                if stream.read_exact(&mut banner).is_ok() && banner == *b"SSH-" {
                    break;
                }
            }
            assert!(
                Instant::now() < deadline,
                "disposable real sshd did not become ready"
            );
            thread::sleep(Duration::from_millis(100));
        }
        server
    }

    fn container(&self) -> String {
        fs::read_to_string(self.state.path().join("container"))
            .unwrap()
            .trim()
            .to_owned()
    }

    fn logs(&self) -> String {
        let output = Command::new(SERVER)
            .arg("logs")
            .arg(self.state.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }

    fn trust(&self, known_hosts: &Path) {
        let public = fs::read_to_string(self.state.path().join("host_key.pub")).unwrap();
        let mut fields = public.split_whitespace();
        fs::write(
            known_hosts,
            format!(
                "[127.0.0.1]:{} {} {}\n",
                self.port,
                fields.next().unwrap(),
                fields.next().unwrap()
            ),
        )
        .unwrap();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = Command::new(SERVER)
            .arg("stop")
            .arg(self.state.path())
            .output();
    }
}

fn isolate_client(fixture: &mut Fixture) -> (PathBuf, PathBuf) {
    let bin = fixture.temp.path().join("ssh-bin");
    fs::create_dir(&bin).unwrap();
    let launcher = bin.join("ssh");
    fs::write(
        &launcher,
        "#!/bin/sh\nexec /usr/bin/ssh -F \"$HOST_MANAGER_TEST_SSH_CONFIG\" \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
    let config = fixture.temp.path().join("ssh_config");
    let known_hosts = fixture.temp.path().join("known_hosts");
    fs::write(&config, format!("Host *\n  UserKnownHostsFile \"{}\"\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking ask\n  IdentityAgent none\n  IdentityFile none\n  IdentitiesOnly yes\n  ConnectTimeout 3\n  ConnectionAttempts 1\n  LogLevel DEBUG1\n", known_hosts.display())).unwrap();
    let inherited = fixture
        .env
        .get(OsStr::new("PATH"))
        .cloned()
        .unwrap_or_default();
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(&inherited));
    fixture
        .env
        .insert("PATH".into(), std::env::join_paths(paths).unwrap());
    fixture.env.insert(
        "HOST_MANAGER_TEST_SSH_CONFIG".into(),
        config.clone().into_os_string(),
    );
    for key in [
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "SSH_ASKPASS_PROMPT",
        "HOST_MANAGER_SSH_INTERNAL",
        "HOST_MANAGER_ASKPASS_DIR",
        "HOST_MANAGER_ASKPASS_ID",
        "HOST_MANAGER_ASKPASS_TARGET",
        "HOST_MANAGER_ASKPASS_PID",
    ] {
        fixture.env.remove(OsStr::new(key));
    }
    (config, known_hosts)
}

fn pty(fixture: &Fixture, mode: &str, name: &str) -> Output {
    fixture
        .command(PTY)
        .arg(mode)
        .arg(BIN)
        .arg(&fixture.dir)
        .arg(name)
        .output()
        .expect("real SSH PTY check requires /usr/bin/expect; check NOT performed")
}

fn server_host(server: &Server, password: &str) -> Host {
    let mut host = sample_host();
    host.name = "password-vps".into();
    let ssh = host.ssh.as_mut().unwrap();
    ssh.user = Some("hmtest".into());
    ssh.port = Some(server.port);
    ssh.password = Some(password.to_owned());
    host
}

#[test]
#[ignore = "Real Docker/OpenSSH/expect integration: run cargo test --test askpass real_password_sessions -- --ignored --nocapture"]
fn real_password_sessions_preserve_hostkeys_secrets_and_store() {
    let password = format!("Hm-{}", Uuid::new_v4());
    let server = Server::start(&password);
    let mut fixture = Fixture::new();
    let (client_config, known_hosts) = isolate_client(&mut fixture);
    let host = server_host(&server, &password);
    save(&fixture, host.clone());
    let before = Snapshot::take(&fixture);

    // A genuine unknown key must prompt, and explicit rejection must not authenticate.
    let output = pty(&fixture, "refuse-hostkey", &host.name);
    assert_eq!(
        output.status.code(),
        Some(255),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    no_secret(&output, &password);
    assert!(!known_hosts.exists() || fs::read(&known_hosts).unwrap().is_empty());
    assert!(!server.logs().contains("Accepted password"));
    before.assert_unchanged(&fixture);

    // Trust only the key obtained out-of-band from our own disposable container.
    server.trust(&known_hosts);
    let output = pty(&fixture, "success", &host.name);
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("HOST_MANAGER_ASKPASS_OK"));
    no_secret(&output, &password);
    assert_eq!(
        server
            .logs()
            .matches("Accepted password for hmtest")
            .count(),
        1
    );
    before.assert_unchanged(&fixture);

    // No saved password must retain ordinary OpenSSH public-key authentication.
    let identity = fixture.temp.path().join("client-key");
    fixture.checked(
        fixture
            .command("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&identity),
    );
    let mut install = Command::new("docker").args(["exec", "-i"]).arg(server.container())
        .args(["/bin/sh", "-c", "mkdir -p /home/hmtest/.ssh; cat > /home/hmtest/.ssh/authorized_keys; chown -R hmtest:hmtest /home/hmtest/.ssh; chmod 700 /home/hmtest/.ssh; chmod 600 /home/hmtest/.ssh/authorized_keys"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    install
        .stdin
        .take()
        .unwrap()
        .write_all(&fs::read(identity.with_extension("pub")).unwrap())
        .unwrap();
    assert!(install.wait_with_output().unwrap().status.success());
    let mut key_host = host.clone();
    key_host.ssh.as_mut().unwrap().password = None;
    key_host.ssh.as_mut().unwrap().identity_file = Some(identity.to_string_lossy().into_owned());
    save(&fixture, key_host);
    let before_key = Snapshot::take(&fixture);
    let output = pty(&fixture, "success", &host.name);
    assert_eq!(output.status.code(), Some(7));
    no_secret(&output, &password);
    assert_eq!(
        server
            .logs()
            .matches("Accepted publickey for hmtest")
            .count(),
        1
    );
    before_key.assert_unchanged(&fixture);

    // The final password must never answer a ProxyJump child's password prompt.
    let config = fs::read_to_string(&client_config).unwrap();
    fs::write(&client_config, format!("{config}\nHost askpass-jump\n  HostName 127.0.0.1\n  Port {}\n  User hmtest\n  PreferredAuthentications password\n  PasswordAuthentication yes\n  PubkeyAuthentication no\n  KbdInteractiveAuthentication no\n  NumberOfPasswordPrompts 1\n  BatchMode no\n\nHost askpass-final\n  HostName 127.0.0.1\n  Port 22\n  User hmtest\n  ProxyJump askpass-jump\n", server.port)).unwrap();
    let mut jump_host = host.clone();
    jump_host.ssh.as_mut().unwrap().host = "askpass-final".into();
    jump_host.ssh.as_mut().unwrap().port = Some(22);
    save(&fixture, jump_host);
    let before_jump = Snapshot::take(&fixture);
    let trusted_keys = fs::read(&known_hosts).unwrap();
    let log = server.logs();
    let accepted = log.matches("Accepted password for hmtest").count();
    let failed = log.matches("Failed password for hmtest").count();
    let output = pty(&fixture, "jump-password", &host.name);
    assert_eq!(
        output.status.code(),
        Some(255),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("hmtest@127.0.0.1's password: "),
        "jump-host password must be requested manually"
    );
    no_secret(&output, &password);
    let log = server.logs();
    assert_eq!(
        log.matches("Accepted password for hmtest").count(),
        accepted,
        "final password must not authenticate the jump host"
    );
    assert_eq!(
        log.matches("Failed password for hmtest").count() - failed,
        1,
        "Jump output:\n{}\nServer log:\n{}",
        String::from_utf8_lossy(&output.stdout),
        log.replace(&password, "[REDACTED]"),
    );
    assert_eq!(fs::read(&known_hosts).unwrap(), trusted_keys);
    before_jump.assert_unchanged(&fixture);

    let wrong = format!("Wrong-{}", Uuid::new_v4());
    let mut wrong_host = host.clone();
    wrong_host.ssh.as_mut().unwrap().password = Some(wrong.clone());
    save(&fixture, wrong_host);
    let before_wrong = Snapshot::take(&fixture);
    let failures = server.logs().matches("Failed password for hmtest").count();
    let output = pty(&fixture, "failure", &host.name);
    assert_eq!(output.status.code(), Some(255));
    no_secret(&output, &password);
    no_secret(&output, &wrong);
    assert_eq!(
        server.logs().matches("Failed password for hmtest").count() - failures,
        1,
        "wrong saved password must cause exactly one authentication attempt"
    );
    before_wrong.assert_unchanged(&fixture);

    // An unrelated known-host key is equivalent to a server-key change.
    let unrelated = fixture.temp.path().join("unrelated-host-key");
    fixture.checked(
        fixture
            .command("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&unrelated),
    );
    let key = fs::read_to_string(unrelated.with_extension("pub")).unwrap();
    let mut fields = key.split_whitespace();
    fs::write(
        &known_hosts,
        format!(
            "[127.0.0.1]:{} {} {}\n",
            server.port,
            fields.next().unwrap(),
            fields.next().unwrap()
        ),
    )
    .unwrap();
    let failures = server.logs().matches("Failed password for hmtest").count();
    let output = pty(&fixture, "failure", &host.name);
    assert_eq!(output.status.code(), Some(255));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
    );
    no_secret(&output, &password);
    no_secret(&output, &wrong);
    assert_eq!(
        server.logs().matches("Failed password for hmtest").count(),
        failures
    );
    before_wrong.assert_unchanged(&fixture);
    assert!(!server.logs().contains(&password));
    assert!(!server.logs().contains(&wrong));
    no_plaintext_files(fixture.temp.path(), &password);
    no_plaintext_files(fixture.temp.path(), &wrong);
    no_plaintext_history(&fixture, &password);
    no_plaintext_history(&fixture, &wrong);
}

