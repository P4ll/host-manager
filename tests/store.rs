mod common;

use std::{
    ffi::OsStr,
    fs,
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::Stdio,
};

use common::{Fixture, sample_host};
use host_manager::{
    model::Catalog,
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
    let shown =
        fixture.checked(
            fixture
                .command("pass")
                .args(["show", "--", "host-manager/catalog"]),
        );
    let decrypted: Catalog = serde_json::from_slice(&shown.stdout).unwrap();
    assert!(decrypted == catalog);
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
    let ciphertext = fs::read(fixture.dir.join("catalog.gpg")).unwrap();
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
    let decrypted = fixture.checked(
        fixture
            .command("gpg")
            .env("GNUPGHOME", keyring.path())
            .args(["--batch", "--decrypt"])
            .arg(fixture.dir.join("catalog.gpg")),
    );
    assert!(serde_json::from_slice::<Catalog>(&decrypted.stdout).unwrap() == catalog);
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
    assert_eq!(
        fs::read(fixture.dir.join("catalog.gpg")).unwrap(),
        ciphertext
    );
}

#[test]
fn corrupt_unknown_and_invalid_documents_never_enable_writes() {
    let fixture = Fixture::new();
    let (mut store, catalog) = initial(&fixture);
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
    let mut external = Catalog::default();
    let mut host = sample_host();
    host.name = "external".into();
    external.hosts.push(host);
    insert(
        &fixture,
        "host-manager/catalog",
        &serde_json::to_vec(&external).unwrap(),
    );
    let before = fs::read(fixture.dir.join("catalog.gpg")).unwrap();
    catalog.hosts[0].notes = "local change".into();
    assert!(store.save(&catalog).is_err());
    assert_eq!(fs::read(fixture.dir.join("catalog.gpg")).unwrap(), before);
    assert!(!fixture.dir.join("catalog.pending.gpg").exists());
    assert!(store.load().unwrap() == external);
}

#[test]
fn staged_unrelated_file_is_not_committed() {
    let fixture = Fixture::new();
    let (mut store, mut catalog) = initial(&fixture);
    let before = fs::read(fixture.dir.join("catalog.gpg")).unwrap();
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
    assert_eq!(fs::read(fixture.dir.join("catalog.gpg")).unwrap(), before);
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
    assert!(!fixture.dir.join("catalog.pending.gpg").exists());
}

#[test]
fn failed_encryption_and_pending_recovery_preserve_catalog() {
    let fixture = Fixture::new();
    let (mut store, mut catalog) = initial(&fixture);
    let original = fs::read(fixture.dir.join("catalog.gpg")).unwrap();
    fs::write(
        fixture.dir.join(".gpg-id"),
        "0000000000000000000000000000000000000000\n",
    )
    .unwrap();
    catalog.hosts[0].notes = "must not replace the original".into();
    assert!(store.save(&catalog).is_err());
    assert_eq!(fs::read(fixture.dir.join("catalog.gpg")).unwrap(), original);
    fs::remove_file(fixture.dir.join(".gpg-id")).unwrap();
    drop(store);
    // A real encrypted leftover emulates interruption after pending was committed.
    if fixture.dir.join("catalog.pending.gpg").exists() {
        fs::remove_file(fixture.dir.join("catalog.pending.gpg")).unwrap();
    }
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
