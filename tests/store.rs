mod common;

use std::{
    ffi::OsStr,
    fs,
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::Stdio,
};

use common::{Fixture, ciphertexts, sample_host};
use host_manager::{
    model::{Catalog, Payment},
    store::{PassStore, SaveOutcome, load_catalog, resolve_pass_dir},
};

fn initial(fixture: &Fixture) -> (PassStore, Catalog) {
    let mut store = PassStore::open(&fixture.dir, fixture.env.clone()).unwrap();
    let mut catalog = store.load().unwrap();
    catalog.hosts.push(sample_host());
    assert_eq!(store.save(&catalog).unwrap(), SaveOutcome::Saved);
    (store, catalog)
}

fn insert(fixture: &Fixture, entry: &str, bytes: &[u8]) {
    let mut child = fixture
        .command("pass")
        .args(["insert", "--multiline", "--force", "--", entry])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            input.write_all(bytes).unwrap();
        });
        let output = child.wait_with_output().unwrap();
        writer.join().unwrap();
        assert!(output.status.success(), "isolated pass insertion failed");
    });
}

fn show(fixture: &Fixture, entry: &str) -> Vec<u8> {
    fixture
        .checked(fixture.command("pass").args(["show", "--", entry]))
        .stdout
}

fn host_stem(fixture: &Fixture, id: uuid::Uuid) -> String {
    let index: serde_json::Value =
        serde_json::from_slice(&show(fixture, "host-manager/index")).unwrap();
    assert_eq!(index["version"], 2);
    index["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|host| host["id"] == id.to_string())
        .unwrap()["name"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn assert_no_plaintext(path: &Path, secret: &[u8]) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_no_plaintext(&path, secret);
        } else if path.is_file() {
            assert!(
                !fs::read(path)
                    .unwrap()
                    .windows(secret.len())
                    .any(|part| part == secret),
                "plaintext found in test store"
            );
        }
    }
}

#[test]
fn encrypted_round_trip_git_history_and_readonly_lock() {
    let fixture = Fixture::new();
    let mut store = PassStore::open(&fixture.dir, fixture.env.clone()).unwrap();
    assert!(!fixture.dir.exists());
    let mut catalog = store.load().unwrap();
    let secret = format!("unique-test-secret-{}", uuid::Uuid::new_v4());
    let mut host = sample_host();
    host.account_password = Some(secret.clone());
    host.ssh.as_mut().unwrap().password = Some(secret.clone());
    catalog.hosts.push(host);
    assert_eq!(store.save(&catalog).unwrap(), SaveOutcome::Saved);
    assert!(PassStore::open(&fixture.dir, fixture.env.clone()).is_err());
    assert!(load_catalog(&fixture.dir, &fixture.env).unwrap() == catalog);
    let stem = host_stem(&fixture, catalog.hosts[0].id);
    let shown = String::from_utf8(show(&fixture, &format!("host-manager/hosts/{stem}"))).unwrap();
    assert!(shown.lines().next().unwrap() == secret);
    for field in [
        "name: example-vps",
        "provider: Example Hosting",
        "host: 127.0.0.1",
        "username: root",
        "port: 22",
    ] {
        assert!(shown.lines().any(|line| line == field));
    }
    assert_no_plaintext(&fixture.root, secret.as_bytes());
    let commits = fixture.checked(
        fixture
            .command("git")
            .arg("-C")
            .arg(&fixture.root)
            .args(["rev-list", "--all"]),
    );
    for commit in String::from_utf8(commits.stdout).unwrap().lines() {
        let tree = fixture.checked(
            fixture
                .command("git")
                .arg("-C")
                .arg(&fixture.root)
                .args(["ls-tree", "-r", commit]),
        );
        for line in String::from_utf8(tree.stdout).unwrap().lines() {
            let object = line.split_whitespace().nth(2).unwrap();
            let blob = fixture.checked(
                fixture
                    .command("git")
                    .arg("-C")
                    .arg(&fixture.root)
                    .args(["cat-file", "blob", object]),
            );
            assert!(
                !blob
                    .stdout
                    .windows(secret.len())
                    .any(|part| part == secret.as_bytes()),
                "plaintext found in Git history"
            );
        }
    }
    drop(store);
    let mut reopened = PassStore::open(&fixture.dir, fixture.env.clone()).unwrap();
    assert!(reopened.load().unwrap() == catalog);
}

#[test]
fn nested_recipients_and_missing_secret_key() {
    let fixture = Fixture::new();
    let second = fixture.generate_key("Host Manager Second <second@example.invalid>");
    fixture.checked(
        fixture
            .command("pass")
            .args(["init", "-p", "host-manager", &second]),
    );
    let (store, catalog) = initial(&fixture);
    let before = ciphertexts(&fixture.dir);
    let stem = host_stem(&fixture, catalog.hosts[0].id);
    let exported = fixture.checked(fixture.command("gpg").args([
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--export-secret-keys",
        &second,
    ]));
    let keyring = tempfile::Builder::new()
        .prefix("hm-ring-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(keyring.path(), fs::Permissions::from_mode(0o700)).unwrap();
    struct Agent<'a> {
        fixture: &'a Fixture,
        home: &'a Path,
    }
    impl Drop for Agent<'_> {
        fn drop(&mut self) {
            let _ = self
                .fixture
                .command("gpgconf")
                .arg("--homedir")
                .arg(self.home)
                .args(["--kill", "gpg-agent"])
                .output();
        }
    }
    let _agent = Agent {
        fixture: &fixture,
        home: keyring.path(),
    };
    let mut child = fixture
        .command("gpg")
        .env("GNUPGHOME", keyring.path())
        .args(["--batch", "--import"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            input.write_all(&exported.stdout).unwrap();
        });
        assert!(child.wait_with_output().unwrap().status.success());
        writer.join().unwrap();
    });
    let only_second = fixture.checked(
        fixture
            .command("gpg")
            .env("GNUPGHOME", keyring.path())
            .args(["--batch", "--with-colons", "--list-secret-keys"]),
    );
    assert_eq!(
        String::from_utf8(only_second.stdout)
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("sec:"))
            .count(),
        1
    );
    for entry in ["index".to_owned(), format!("hosts/{stem}")] {
        let decrypted = fixture.checked(
            fixture
                .command("gpg")
                .env("GNUPGHOME", keyring.path())
                .args(["--batch", "--decrypt"])
                .arg(fixture.dir.join(format!("{entry}.gpg"))),
        );
        assert!(decrypted.stdout == show(&fixture, &format!("host-manager/{entry}")));
    }
    let empty = tempfile::Builder::new()
        .prefix("hm-empty-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(empty.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let _empty_agent = Agent {
        fixture: &fixture,
        home: empty.path(),
    };
    let mut no_key = fixture.env.clone();
    no_key.insert("GNUPGHOME".into(), empty.path().as_os_str().to_owned());
    assert!(load_catalog(&fixture.dir, &no_key).is_err());
    drop(store);
    let mut editor = PassStore::open(&fixture.dir, no_key).unwrap();
    assert!(editor.load().is_err());
    assert!(editor.save(&catalog).is_err());
    assert_eq!(ciphertexts(&fixture.dir), before);
}

#[test]
fn corrupt_unknown_and_invalid_documents_never_enable_writes() {
    let fixture = Fixture::new();
    let catalog = Catalog {
        version: 1,
        hosts: vec![sample_host()],
    };
    let mut store = PassStore::open(&fixture.dir, fixture.env.clone()).unwrap();
    let valid = String::from_utf8(serde_json::to_vec(&catalog).unwrap()).unwrap();
    for invalid in [
        "{broken JSON".to_owned(),
        valid.replacen("\"version\":1", "\"version\":2", 1),
        valid.replacen("\"amount\":\"5.00\"", "\"amount\":\"-1\"", 1),
        valid.replacen(
            "\"amount\":\"5.00\"",
            "\"amount\":\"0.00000000000000000000000000001\"",
            1,
        ),
        valid.replacen("\"next_due\":\"", "\"next_due\":\"invalid-", 1),
        valid.replacen(
            "\"provider\":",
            "\"sensitive-unrecognized-key\":null,\"provider\":",
            1,
        ),
        valid.replacen("\"panel_url\":null,", "", 1),
    ] {
        assert_ne!(invalid, valid);
        insert(&fixture, "host-manager/catalog", invalid.as_bytes());
        let before = fs::read(fixture.dir.join("catalog.gpg")).unwrap();
        let diagnostic = store
            .load()
            .err()
            .expect("invalid catalog must fail")
            .to_string();
        assert!(!diagnostic.contains("sensitive-unrecognized-key"));
        assert!(store.save(&catalog).is_err());
        assert!(load_catalog(&fixture.dir, &fixture.env).is_err());
        assert_eq!(fs::read(fixture.dir.join("catalog.gpg")).unwrap(), before);
    }
}

#[test]
fn external_ciphertext_conflict_preserves_external_change() {
    let fixture = Fixture::new();
    let (mut store, mut catalog) = initial(&fixture);
    let stem = host_stem(&fixture, catalog.hosts[0].id);
    let entry = format!("host-manager/hosts/{stem}");
    let external = String::from_utf8(show(&fixture, &entry))
        .unwrap()
        .replace("provider: Example Hosting", "provider: External Hosting");
    insert(&fixture, &entry, external.as_bytes());
    let after_external_write = ciphertexts(&fixture.dir);
    catalog.hosts[0].notes = "local change".into();
    assert!(store.save(&catalog).is_err());
    assert_eq!(ciphertexts(&fixture.dir), after_external_write);
    let loaded = store.load().unwrap();
    assert_eq!(loaded.hosts[0].provider, "External Hosting");
    assert!(loaded.hosts[0].notes.is_empty());
}

#[test]
fn staged_unrelated_file_is_not_committed() {
    let fixture = Fixture::new();
    let (mut store, mut catalog) = initial(&fixture);
    let before = ciphertexts(&fixture.dir);
    let head = fixture
        .checked(
            fixture
                .command("git")
                .arg("-C")
                .arg(&fixture.root)
                .args(["rev-parse", "HEAD"]),
        )
        .stdout;
    fs::write(fixture.root.join("unrelated"), "user staged change").unwrap();
    fixture.checked(
        fixture
            .command("git")
            .arg("-C")
            .arg(&fixture.root)
            .args(["add", "unrelated"]),
    );
    catalog.hosts[0].notes = "changed".into();
    assert!(store.save(&catalog).is_err());
    assert_eq!(ciphertexts(&fixture.dir), before);
    assert_eq!(
        fixture
            .checked(
                fixture
                    .command("git")
                    .arg("-C")
                    .arg(&fixture.root)
                    .args(["rev-parse", "HEAD"])
            )
            .stdout,
        head
    );
    let staged = fixture.checked(fixture.command("git").arg("-C").arg(&fixture.root).args([
        "diff",
        "--cached",
        "--name-only",
    ]));
    assert_eq!(staged.stdout, b"unrelated\n");
    assert!(!fixture.dir.join("catalog.gpg").exists());
}

#[test]
fn git_hook_failure_warns_after_persisting_update() {
    let fixture = Fixture::new();
    let (mut store, mut catalog) = initial(&fixture);
    let git = |args: &[&str]| {
        fixture
            .checked(
                fixture
                    .command("git")
                    .arg("-C")
                    .arg(&fixture.root)
                    .args(args),
            )
            .stdout
    };
    let head = git(&["rev-parse", "HEAD"]);
    let hooks = fixture.temp.path().join("hooks");
    fs::create_dir(&hooks).unwrap();
    git(&["config", "core.hooksPath", hooks.to_str().unwrap()]);
    let hook = hooks.join("pre-commit");
    fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
    catalog.hosts[0].notes = "saved despite rejected commit".into();
    assert_eq!(
        store.save(&catalog).unwrap(),
        SaveOutcome::SavedWithPassWarning
    );
    assert!(load_catalog(&fixture.dir, &fixture.env).unwrap() == catalog);
    assert_eq!(git(&["rev-parse", "HEAD"]), head);
    fs::remove_file(hook).unwrap();
    let saved = store.load().unwrap();
    assert_eq!(store.save(&saved).unwrap(), SaveOutcome::Saved);
    assert_ne!(git(&["rev-parse", "HEAD"]), head);
}

#[test]
fn cli_migrates_legacy_and_subsequent_edit_only_updates_the_selected_host() {
    let fixture = Fixture::new();
    let mut host = sample_host();
    host.account_password = Some("panel-password".into());
    host.account_login = Some("panel-user".into());
    host.panel_url = Some("https://example.invalid/panel".into());
    host.archived = true;
    host.notes = "line one\nстрока два".into();
    let identity = fixture.temp.path().join("example-key");
    fs::write(&identity, b"test identity").unwrap();
    let ssh = host.ssh.as_mut().unwrap();
    ssh.password = Some("ssh-password".into());
    ssh.identity_file = Some(identity.to_str().unwrap().into());
    let next_due = host.billing.next_due.unwrap();
    host.payments.push(Payment {
        paid_on: chrono::Local::now().date_naive(),
        amount: host.billing.amount,
        currency: host.billing.currency.clone(),
        next_due,
    });
    let mut other = sample_host();
    other.ssh = None;
    let mut catalog = Catalog {
        version: 1,
        hosts: vec![host, other],
    };
    insert(
        &fixture,
        "host-manager/catalog",
        &serde_json::to_vec(&catalog).unwrap(),
    );
    let legacy = fs::read(fixture.dir.join("catalog.gpg")).unwrap();
    assert!(load_catalog(&fixture.dir, &fixture.env).unwrap() == catalog);
    let cli = || {
        let mut command = fixture.command(env!("CARGO_BIN_EXE_host-manager"));
        command.arg("--pass-dir").arg(&fixture.dir);
        command
    };
    let connect = cli()
        .args(["connect", &catalog.hosts[0].name])
        .output()
        .unwrap();
    assert_eq!(connect.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&connect.stderr).contains("SSH-доступ не настроен"));
    assert!(!fixture.dir.join("index.gpg").exists());
    assert_eq!(fs::read(fixture.dir.join("catalog.gpg")).unwrap(), legacy);

    fixture.checked(cli().arg("migrate"));
    assert_eq!(fs::read(fixture.dir.join("catalog.gpg")).unwrap(), legacy);
    assert!(load_catalog(&fixture.dir, &fixture.env).unwrap() == catalog);
    let selected = host_stem(&fixture, catalog.hosts[0].id);
    let shown = show(&fixture, &format!("host-manager/hosts/{selected}"));
    assert!(shown.starts_with(b"ssh-password\n"));
    let other = host_stem(&fixture, catalog.hosts[1].id);
    assert_ne!(selected, other);

    let mut store = PassStore::open(&fixture.dir, fixture.env.clone()).unwrap();
    assert!(store.load().unwrap() == catalog);
    let before = ciphertexts(&fixture.dir);
    catalog.hosts[0].notes.push_str("\nupdated");
    assert_eq!(store.save(&catalog).unwrap(), SaveOutcome::Saved);
    let after = ciphertexts(&fixture.dir);
    assert_eq!(before.0, after.0);
    assert_eq!(
        before.1[&format!("{other}.gpg")],
        after.1[&format!("{other}.gpg")]
    );
    assert_ne!(
        before.1[&format!("{selected}.gpg")],
        after.1[&format!("{selected}.gpg")]
    );
    let committed = fixture.checked(fixture.command("git").arg("-C").arg(&fixture.root).args([
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
        "HEAD",
    ]));
    assert_eq!(
        committed.stdout,
        format!("host-manager/hosts/{selected}.gpg\n").into_bytes()
    );
    assert_eq!(fs::read(fixture.dir.join("catalog.gpg")).unwrap(), legacy);
    assert!(load_catalog(&fixture.dir, &fixture.env).unwrap() == catalog);

    fs::remove_file(fixture.dir.join("index.gpg")).unwrap();
    assert!(load_catalog(&fixture.dir, &fixture.env).is_err());
    assert!(store.load().is_err());
    assert!(store.save(&catalog).is_err());
    assert_eq!(fs::read(fixture.dir.join("catalog.gpg")).unwrap(), legacy);
}

#[test]
fn first_write_finishes_interrupted_migration_without_hiding_legacy() {
    let fixture = Fixture::new();
    let mut catalog = Catalog {
        version: 1,
        hosts: vec![sample_host()],
    };
    insert(
        &fixture,
        "host-manager/catalog",
        &serde_json::to_vec(&catalog).unwrap(),
    );
    let legacy = fs::read(fixture.dir.join("catalog.gpg")).unwrap();
    // Seed a real encrypted host as if migration stopped before publishing the index.
    let staging = fixture.root.join("other-namespace");
    let mut seed = PassStore::open(&staging, fixture.env.clone()).unwrap();
    seed.load().unwrap();
    assert_eq!(seed.save(&catalog).unwrap(), SaveOutcome::Saved);
    drop(seed);
    fs::create_dir(fixture.dir.join("hosts")).unwrap();
    let encrypted = fs::read_dir(staging.join("hosts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    fs::copy(
        encrypted.path(),
        fixture.dir.join("hosts").join(encrypted.file_name()),
    )
    .unwrap();

    let mut store = PassStore::open(&fixture.dir, fixture.env.clone()).unwrap();
    assert!(store.load().unwrap() == catalog);
    assert!(load_catalog(&fixture.dir, &fixture.env).unwrap() == catalog);
    assert!(!fixture.dir.join("index.gpg").exists());
    let mut added = sample_host();
    added.name = "added-on-first-write".into();
    catalog.hosts.push(added);
    assert_eq!(store.save(&catalog).unwrap(), SaveOutcome::Saved);
    assert!(fixture.dir.join("index.gpg").is_file());
    assert!(load_catalog(&fixture.dir, &fixture.env).unwrap() == catalog);
    assert_eq!(fs::read(fixture.dir.join("catalog.gpg")).unwrap(), legacy);
}

#[test]
fn failed_encryption_and_pending_recovery_preserve_catalog() {
    let fixture = Fixture::new();
    let mut catalog = Catalog {
        version: 1,
        hosts: vec![sample_host()],
    };
    insert(
        &fixture,
        "host-manager/catalog",
        &serde_json::to_vec(&catalog).unwrap(),
    );
    let mut store = PassStore::open(&fixture.dir, fixture.env.clone()).unwrap();
    assert!(store.load().unwrap() == catalog);
    let original = fs::read(fixture.dir.join("catalog.gpg")).unwrap();
    fs::write(
        fixture.dir.join(".gpg-id"),
        "0000000000000000000000000000000000000000\n",
    )
    .unwrap();
    catalog.hosts[0].notes = "must not replace the original".into();
    assert!(store.save(&catalog).is_err());
    assert_eq!(fs::read(fixture.dir.join("catalog.gpg")).unwrap(), original);
    assert!(!fixture.dir.join("index.gpg").exists());
    assert!(
        load_catalog(&fixture.dir, &fixture.env).unwrap().hosts[0]
            .notes
            .is_empty()
    );
    fs::remove_file(fixture.dir.join(".gpg-id")).unwrap();
    drop(store);
    // A real encrypted leftover emulates interruption after pending was committed.
    insert(
        &fixture,
        "host-manager/catalog.pending",
        &serde_json::to_vec(&catalog).unwrap(),
    );
    let pending = fs::read(fixture.dir.join("catalog.pending.gpg")).unwrap();
    let mut reopened = PassStore::open(&fixture.dir, fixture.env.clone()).unwrap();
    let readable = reopened.load().unwrap();
    assert_ne!(readable.hosts[0].notes, catalog.hosts[0].notes);
    assert!(reopened.save(&catalog).is_err());
    assert_eq!(fs::read(fixture.dir.join("catalog.gpg")).unwrap(), original);
    assert!(!fixture.dir.join("index.gpg").exists());
    assert_eq!(
        fs::read(fixture.dir.join("catalog.pending.gpg")).unwrap(),
        pending
    );
    fs::remove_file(fixture.dir.join("catalog.gpg")).unwrap();
    assert!(reopened.load().is_err());
    assert!(reopened.save(&catalog).is_err());
    assert!(load_catalog(&fixture.dir, &fixture.env).is_err());
    assert!(!fixture.dir.join("catalog.gpg").exists());
}

#[test]
fn path_boundaries_configuration_and_readonly_have_no_side_effects() {
    let fixture = Fixture::new();
    assert!(PassStore::open(&fixture.root, fixture.env.clone()).is_err());
    assert!(PassStore::open(fixture.temp.path(), fixture.env.clone()).is_err());
    assert!(
        PassStore::open(
            &fixture.root.join("host-manager/../outside"),
            fixture.env.clone()
        )
        .is_err()
    );
    assert!(
        load_catalog(&fixture.dir, &fixture.env)
            .unwrap()
            .hosts
            .is_empty()
    );
    assert!(!fixture.dir.exists());
    assert!(!Path::new(fixture.env.get(OsStr::new("XDG_CACHE_HOME")).unwrap()).exists());
    symlink(fixture.temp.path(), fixture.root.join("link")).unwrap();
    assert!(PassStore::open(&fixture.root.join("link/host-manager"), fixture.env.clone()).is_err());
    fs::create_dir_all(&fixture.dir).unwrap();
    let external = fixture.temp.path().join("not-a-catalog");
    fs::write(&external, b"untouched").unwrap();
    symlink(&external, fixture.dir.join("catalog.gpg")).unwrap();
    assert!(load_catalog(&fixture.dir, &fixture.env).is_err());
    assert!(PassStore::open(&fixture.dir, fixture.env.clone()).is_err());
    fs::remove_file(fixture.dir.join("catalog.gpg")).unwrap();
    symlink(&external, fixture.dir.join("catalog.pending.gpg")).unwrap();
    assert!(load_catalog(&fixture.dir, &fixture.env).is_err());
    fs::remove_file(fixture.dir.join("catalog.pending.gpg")).unwrap();
    assert_eq!(fs::read(&external).unwrap(), b"untouched");
    fs::remove_file(fixture.root.join(".gpg-id")).unwrap();
    assert!(PassStore::open(&fixture.dir, fixture.env.clone()).is_err());
    fs::write(fixture.root.join(".gpg-id"), b"\n").unwrap();
    assert!(PassStore::open(&fixture.dir, fixture.env.clone()).is_err());
    fs::remove_dir_all(fixture.root.join(".git")).unwrap();
    assert!(PassStore::open(&fixture.dir, fixture.env.clone()).is_err());
}

#[test]
fn directory_precedence_empty_values_and_tilde() {
    let fixture = Fixture::new();
    let mut env = fixture.env.clone();
    assert_eq!(resolve_pass_dir(None, &env).unwrap(), fixture.dir);
    env.insert(
        "HOST_MANAGER_PASS_DIR".into(),
        fixture.root.join("from-env").into_os_string(),
    );
    assert_eq!(
        resolve_pass_dir(None, &env).unwrap(),
        fixture.root.join("from-env")
    );
    assert_eq!(
        resolve_pass_dir(Some(&fixture.dir), &env).unwrap(),
        fixture.dir
    );
    env.insert("HOST_MANAGER_PASS_DIR".into(), "".into());
    assert!(resolve_pass_dir(None, &env).is_err());
    assert!(resolve_pass_dir(Some(Path::new("")), &env).is_err());
    assert_eq!(
        resolve_pass_dir(Some(Path::new("~/store/host-manager")), &env).unwrap(),
        fixture.dir
    );
    env.remove(OsStr::new("HOST_MANAGER_PASS_DIR"));
    env.insert("PASSWORD_STORE_DIR".into(), "".into());
    assert!(resolve_pass_dir(None, &env).is_err());
}
