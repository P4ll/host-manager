mod common;

use std::ffi::OsStr;
use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use common::{Fixture, sample_host};
use host_manager::model::{Catalog, Host, SshConfig};
use host_manager::store::{PassStore, load_catalog};
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_host-manager");

fn cli(fixture: &Fixture) -> Command {
    fixture.command(BIN)
}

fn host(name: &str) -> Host {
    let mut host = sample_host();
    host.id = Uuid::new_v4();
    host.name = name.to_owned();
    host
}

fn save(fixture: &Fixture, dir: &Path, hosts: Vec<Host>) -> PassStore {
    let mut store = PassStore::open(dir, fixture.env.clone()).unwrap();
    store.load().unwrap();
    store.save(&Catalog { version: 1, hosts }).unwrap();
    store
}

fn assert_code(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.windows(4).any(|bytes| bytes == b"\x1b[?1"));
    assert!(!output.stderr.windows(4).any(|bytes| bytes == b"\x1b[?1"));
    assert!(
        output.stdout.is_empty(),
        "connect must not print the decrypted catalog"
    );
}

struct Snapshot {
    ciphertext: Vec<u8>,
    head: Vec<u8>,
    index: Vec<u8>,
}

impl Snapshot {
    fn take(fixture: &Fixture, dir: &Path) -> Self {
        let output = fixture
            .command("git")
            .arg("-C")
            .arg(&fixture.root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        assert!(output.status.success());
        Self {
            ciphertext: fs::read(dir.join("catalog.gpg")).unwrap(),
            head: output.stdout,
            index: fs::read(fixture.root.join(".git/index")).unwrap(),
        }
    }

    fn assert_unchanged(&self, fixture: &Fixture, dir: &Path) {
        let after = Self::take(fixture, dir);
        assert_eq!(self.ciphertext, after.ciphertext);
        assert_eq!(self.head, after.head);
        assert_eq!(self.index, after.index);
        assert!(!dir.join("catalog.pending.gpg").exists());
    }
}

// Forward every invocation to real OpenSSH, with only isolated client configuration.
fn isolate_ssh(fixture: &Fixture, command: &mut Command) {
    let bin = fixture.temp.path().join("ssh-bin");
    fs::create_dir_all(&bin).unwrap();
    let launcher = bin.join("ssh");
    fs::write(
        &launcher,
        "#!/bin/sh\nexec /usr/bin/ssh -F \"$HOST_MANAGER_TEST_SSH_CONFIG\" \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
    let config = fixture.temp.path().join("ssh_config");
    let known_hosts = fixture.temp.path().join("known_hosts");
    fs::write(&config, format!(
        "Host *\n  UserKnownHostsFile \"{}\"\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  BatchMode yes\n  IdentityAgent none\n  IdentityFile none\n  IdentitiesOnly yes\n  ConnectTimeout 2\n  ConnectionAttempts 1\n",
        known_hosts.display(),
    )).unwrap();
    let inherited = fixture
        .env
        .get(OsStr::new("PATH"))
        .cloned()
        .unwrap_or_default();
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(&inherited));
    command
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("HOST_MANAGER_TEST_SSH_CONFIG", config);
}

fn refusal_host(name: &str) -> Host {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut host = host(name);
    host.ssh = Some(SshConfig {
        host: "127.0.0.1".to_owned(),
        user: None,
        port: Some(port),
        identity_file: None,
        password: Some("CLI_TEST_PASSWORD_MUST_NOT_LEAK".to_owned()),
    });
    host
}

#[test]
fn usage_errors_and_help_do_not_access_pass() {
    let temp = tempfile::tempdir().unwrap();
    let bad_arguments: &[&[&str]] = &[
        &["connect"],
        &["connect", ""],
        &["connect", "name\nsecret"],
        &["connect", "name", "extra"],
        &["unknown"],
        &["--unknown"],
        &["--host-manager-ssh"],
        &["--pass-dir"],
        &["--pass-dir", ""],
        &["--pass-dir", "one", "--pass-dir", "two"],
        &["connect", "name", "--", "extra"],
        &["template"],
        &["template", ""],
        &["template", "one", "two"],
        &["import"],
        &["import", ""],
        &["import", "one", "two"],
    ];
    for args in bad_arguments {
        let output = Command::new(BIN)
            .env_clear()
            .env("HOME", temp.path())
            .env("PATH", temp.path())
            .args(*args)
            .output()
            .unwrap();
        assert_code(&output, 2);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("name\nsecret"));
    }
    for args in [
        &["--help"][..],
        &["connect", "--help"][..],
        &["template", "--help"][..],
        &["import", "--help"][..],
    ] {
        let output = Command::new(BIN)
            .env_clear()
            .env("PATH", temp.path())
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("connect NAME"));
    }
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn connect_selection_is_exact_read_only_and_coexists_with_editor_lock() {
    let fixture = Fixture::new();
    let mut archived = host("archived");
    archived.archived = true;
    let mut no_ssh = host("without ssh");
    no_ssh.ssh = None;
    let mut active_and_archived = host("mixed");
    active_and_archived.archived = true;
    let mut active_mixed = host("mixed");
    active_mixed.ssh = None;
    let _editor = save(
        &fixture,
        &fixture.dir,
        vec![
            archived,
            no_ssh,
            host("duplicate"),
            host("duplicate"),
            host("Case Sensitive"),
            host("prod eu"),
            active_and_archived,
            active_mixed,
        ],
    );
    let before = Snapshot::take(&fixture, &fixture.dir);
    for (name, diagnostic) in [
        ("absent", "VPS не найден"),
        ("archived", "VPS находится в архиве"),
        ("duplicate", "Имя VPS неоднозначно"),
        ("without ssh", "SSH-доступ не настроен"),
        ("mixed", "SSH-доступ не настроен"),
        ("case sensitive", "VPS не найден"),
        ("prod", "VPS не найден"),
    ] {
        let output = cli(&fixture)
            .arg("--pass-dir")
            .arg(&fixture.dir)
            .args(["connect", name])
            .output()
            .unwrap();
        assert_code(&output, 1);
        assert!(String::from_utf8_lossy(&output.stderr).contains(diagnostic));
        before.assert_unchanged(&fixture, &fixture.dir);
    }
}

#[test]
fn connect_executes_real_ssh_and_pass_directory_precedence_is_consistent() {
    let fixture = Fixture::new();
    let alternate = fixture.root.join("alternate");
    let explicit = fixture.root.join("explicit");
    let _default_editor = save(&fixture, &fixture.dir, vec![refusal_host("default")]);
    let _alternate_editor = save(&fixture, &alternate, vec![refusal_host("prod eu")]);
    let _explicit_editor = save(&fixture, &explicit, vec![refusal_host("--literal")]);
    let snapshots = [
        (&fixture.dir, Snapshot::take(&fixture, &fixture.dir)),
        (&alternate, Snapshot::take(&fixture, &alternate)),
        (&explicit, Snapshot::take(&fixture, &explicit)),
    ];
    let mut commands = Vec::new();
    let mut default = cli(&fixture);
    default
        .env_remove("HOST_MANAGER_PASS_DIR")
        .args(["connect", "default"]);
    commands.push(default);
    let mut environment = cli(&fixture);
    environment
        .env("HOST_MANAGER_PASS_DIR", &alternate)
        .args(["connect", "prod eu"]);
    commands.push(environment);
    let mut before_name = cli(&fixture);
    before_name
        .env("HOST_MANAGER_PASS_DIR", &alternate)
        .arg("--pass-dir")
        .arg(&explicit)
        .args(["connect", "--", "--literal"]);
    commands.push(before_name);
    let mut after_name = cli(&fixture);
    after_name
        .env("HOST_MANAGER_PASS_DIR", &explicit)
        .args(["connect", "prod eu", "--pass-dir"])
        .arg(&alternate);
    commands.push(after_name);
    for mut command in commands {
        isolate_ssh(&fixture, &mut command);
        let output = command.output().unwrap();
        assert_code(&output, 255);
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("CLI_TEST_PASSWORD_MUST_NOT_LEAK")
        );
        for (dir, before) in &snapshots {
            before.assert_unchanged(&fixture, dir);
        }
    }
    assert!(!fixture.temp.path().join("known_hosts").exists());
}

#[test]
fn invalid_environment_and_missing_gpg_key_do_not_change_catalog() {
    let fixture = Fixture::new();
    let _editor = save(&fixture, &fixture.dir, vec![refusal_host("locked")]);
    let before = Snapshot::take(&fixture, &fixture.dir);
    let output = cli(&fixture)
        .env("HOST_MANAGER_PASS_DIR", "")
        .args(["connect", "locked"])
        .output()
        .unwrap();
    assert_code(&output, 1);
    before.assert_unchanged(&fixture, &fixture.dir);
    let empty_home = fixture.temp.path().join("empty-gpg");
    fs::create_dir(&empty_home).unwrap();
    fs::set_permissions(&empty_home, fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = cli(&fixture);
    isolate_ssh(&fixture, &mut command);
    let output = command
        .env("GNUPGHOME", &empty_home)
        .arg("--pass-dir")
        .arg(&fixture.dir)
        .args(["connect", "locked"])
        .output()
        .unwrap();
    let kill = fixture
        .command("gpgconf")
        .arg("--homedir")
        .arg(&empty_home)
        .args(["--kill", "gpg-agent"])
        .status()
        .unwrap();
    assert!(kill.success());
    assert_code(&output, 1);
    before.assert_unchanged(&fixture, &fixture.dir);
    assert!(!fixture.temp.path().join("known_hosts").exists());
}

#[test]
fn template_is_private_standalone_and_never_overwrites_files() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("заполнить VPS.json");
    let template = |path: &Path| {
        Command::new(BIN)
            .env_clear()
            .env("PATH", temp.path())
            .env("HOST_MANAGER_PASS_DIR", "")
            .arg("template")
            .arg(path)
            .output()
            .unwrap()
    };
    let output = template(&path);
    assert!(output.status.success());
    let bytes = fs::read(&path).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let first: Catalog = serde_json::from_slice(&bytes).unwrap();
    assert!(
        first.validate().is_err(),
        "unfilled template must not import accidentally"
    );
    let another = temp.path().join("second.json");
    assert!(template(&another).status.success());
    let second: Catalog = serde_json::from_slice(&fs::read(another).unwrap()).unwrap();
    assert_ne!(first.hosts[0].id, second.hosts[0].id);
    assert_code(&template(&path), 1);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let link = temp.path().join("link.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_code(&template(&link), 1);
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn filled_templates_import_as_one_append_and_cannot_be_repeated() {
    let fixture = Fixture::new();
    let original = sample_host();
    let original_id = original.id;
    let editor = save(&fixture, &fixture.dir, vec![original.clone()]);
    let path = fixture.temp.path().join("заполненный шаблон.json");
    assert!(
        cli(&fixture)
            .arg("template")
            .arg(&path)
            .output()
            .unwrap()
            .status
            .success()
    );
    let mut imported: Catalog = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let first = &mut imported.hosts[0];
    first.name = "Импортированный VPS".into();
    first.provider = "Новый хостер".into();
    first.account_password = Some("IMPORT-SECRET-DO-NOT-PRINT".into());
    first.ssh.as_mut().unwrap().host = "imported-alias".into();
    first.billing.amount = rust_decimal::Decimal::new(975, 2);
    first.billing.currency = "usd".into();
    first.notes = "Заметки из файла\nВторая строка".into();
    let second_path = fixture.temp.path().join("second.json");
    assert!(
        cli(&fixture)
            .arg("template")
            .arg(&second_path)
            .output()
            .unwrap()
            .status
            .success()
    );
    let mut second: Catalog = serde_json::from_slice(&fs::read(second_path).unwrap()).unwrap();
    second.hosts[0].name = "Без SSH".into();
    second.hosts[0].provider = "Другой хостер".into();
    second.hosts[0].ssh = None;
    imported.hosts.extend(second.hosts);
    let first_id = imported.hosts[0].id;
    let source = serde_json::to_vec_pretty(&imported).unwrap();
    fs::write(&path, &source).unwrap();
    let before = Snapshot::take(&fixture, &fixture.dir);
    let run = || {
        cli(&fixture)
            .arg("import")
            .arg(&path)
            .arg("--pass-dir")
            .arg(&fixture.dir)
            .env("HOST_MANAGER_PASS_DIR", fixture.root.join("unused"))
            .output()
            .unwrap()
    };
    assert_code(&run(), 1);
    before.assert_unchanged(&fixture, &fixture.dir);
    drop(editor);
    let output = run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Импортировано VPS: 2"));
    assert!(!output.stdout.contains(&0x1b));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("IMPORT-SECRET"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("IMPORT-SECRET"));
    let catalog = load_catalog(&fixture.dir, &fixture.env).unwrap();
    assert_eq!(catalog.hosts.len(), 3);
    assert!(
        catalog
            .hosts
            .iter()
            .find(|host| host.id == original_id)
            .unwrap()
            == &original
    );
    let added = catalog
        .hosts
        .iter()
        .find(|host| host.id == first_id)
        .unwrap();
    assert_eq!(added.name, "Импортированный VPS");
    assert_eq!(added.notes, "Заметки из файла\nВторая строка");
    assert_eq!(
        added.account_password.as_deref(),
        Some("IMPORT-SECRET-DO-NOT-PRINT")
    );
    assert_eq!(added.billing.amount, rust_decimal::Decimal::new(975, 2));
    assert_eq!(added.billing.currency, "USD");
    let saved = Snapshot::take(&fixture, &fixture.dir);
    assert_code(&run(), 1);
    saved.assert_unchanged(&fixture, &fixture.dir);
    assert_eq!(fs::read(path).unwrap(), source);
}

#[test]
fn invalid_import_batches_and_staged_changes_preserve_the_catalog() {
    let fixture = Fixture::new();
    let original = sample_host();
    let original_id = original.id;
    drop(save(&fixture, &fixture.dir, vec![original]));
    let before = Snapshot::take(&fixture, &fixture.dir);
    let path = fixture.temp.path().join("invalid.json");
    let mut incoming = Catalog {
        version: 1,
        hosts: vec![sample_host(), sample_host()],
    };
    let valid = serde_json::to_string(&incoming).unwrap();
    let mut invalid = vec![
        r#"{"SECRET-FROM-INVALID-FILE":"#.to_owned(),
        valid.replacen(r#""version":1"#, r#""version":2"#, 1),
        valid.replacen(
            r#""provider":"#,
            r#""SECRET-FROM-INVALID-FILE":null,"provider":"#,
            1,
        ),
        valid.replacen(r#""amount":"5.00""#, r#""amount":"-1""#, 1),
        valid.replacen(r#""next_due":""#, r#""next_due":"invalid-"#, 1),
        valid.replacen(r#""panel_url":null,"#, "", 1),
        r#"{"version":1,"hosts":[]}"#.to_owned(),
    ];
    incoming.hosts[1].id = incoming.hosts[0].id;
    invalid.push(serde_json::to_string(&incoming).unwrap());
    incoming.hosts[1].id = original_id;
    invalid.push(serde_json::to_string(&incoming).unwrap());
    for document in invalid {
        assert_ne!(document, valid);
        fs::write(&path, document).unwrap();
        let output = cli(&fixture)
            .arg("--pass-dir")
            .arg(&fixture.dir)
            .arg("import")
            .arg(&path)
            .output()
            .unwrap();
        assert_code(&output, 1);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRET-FROM-INVALID-FILE"));
        before.assert_unchanged(&fixture, &fixture.dir);
    }
    fs::write(&path, valid).unwrap();
    fs::write(fixture.root.join("unrelated"), "staged user change").unwrap();
    fixture.checked(
        fixture
            .command("git")
            .arg("-C")
            .arg(&fixture.root)
            .args(["add", "unrelated"]),
    );
    let staged = Snapshot::take(&fixture, &fixture.dir);
    let output = cli(&fixture).arg("import").arg(&path).output().unwrap();
    assert_code(&output, 1);
    staged.assert_unchanged(&fixture, &fixture.dir);
}
