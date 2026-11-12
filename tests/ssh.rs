use std::{
    ffi::{OsStr, OsString},
    fs,
    path::Path,
    process::Command,
};

use host_manager::{
    model::SshConfig,
    ssh::{ssh_command, validate_config},
    store::Environment,
};
use tempfile::TempDir;
use uuid::Uuid;

fn config(host: &str) -> SshConfig {
    SshConfig {
        host: host.into(),
        user: None,
        port: None,
        identity_file: None,
        password: None,
    }
}

fn command(config: &SshConfig) -> anyhow::Result<Command> {
    ssh_command(
        config,
        Uuid::nil(),
        Path::new("/unused-pass-directory"),
        &Environment::new(),
    )
}

fn args(config: &SshConfig) -> Vec<OsString> {
    let command = command(config).unwrap();
    assert_eq!(command.get_program(), "ssh");
    assert_eq!(command.get_envs().count(), 0);
    command.get_args().map(OsString::from).collect()
}

fn environment(command: &Command) -> Environment {
    command
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
        .collect()
}

#[test]
fn aliases_ipv4_and_ipv6_remain_one_argument() {
    for host in [
        "prod-eu",
        "example.invalid",
        "192.0.2.10",
        "2001:db8::10",
        "fe80::1%en0",
    ] {
        assert_eq!(
            args(&config(host)),
            [OsString::from("--"), OsString::from(host)]
        );
    }
}

#[test]
fn explicit_options_and_identity_paths_with_spaces_remain_separate_arguments() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("identity with spaces");
    fs::write(&path, "isolated test file, not an actual key").unwrap();
    let mut config = config("2001:db8::1");
    config.user = Some("root".into());
    config.port = Some(2222);
    config.identity_file = Some(path.to_str().unwrap().into());
    assert_eq!(
        args(&config),
        [
            OsString::from("-l"),
            OsString::from("root"),
            OsString::from("-p"),
            OsString::from("2222"),
            OsString::from("-i"),
            path.into_os_string(),
            OsString::from("--"),
            OsString::from("2001:db8::1"),
        ]
    );
    assert!(validate_config(&config).is_ok());
}

#[test]
fn option_user_and_terminal_injection_are_rejected() {
    for host in [
        "",
        "-oProxyCommand=anything",
        "--",
        "user@example.invalid",
        "ssh://example.invalid",
        "https://example.invalid",
        "example.invalid/path",
        "example.invalid\\path",
        "example.invalid extra",
        "example.invalid\n-oForwardAgent=yes",
        "host\r",
        "host\t",
        "host\0",
        "host\u{1b}[2J",
        "host\u{85}",
        "host\u{a0}suffix",
    ] {
        let config = config(host);
        assert!(command(&config).is_err(), "accepted invalid host");
        assert!(validate_config(&config).is_err());
    }
    for user in [
        "",
        "-root",
        "root other",
        "root\n",
        "root\t",
        "root\u{1b}",
        "root\0",
        "root\u{a0}other",
    ] {
        let mut config = config("alias");
        config.user = Some(user.into());
        assert!(command(&config).is_err(), "accepted invalid user");
    }
    let mut config = config("alias");
    config.password = Some("secret\n".into());
    let error = command(&config).err().unwrap().to_string();
    assert!(!error.contains("secret"));
}

#[test]
fn port_and_key_path_boundaries() {
    let mut config = config("alias");
    config.port = Some(0);
    assert!(command(&config).is_err());
    for port in [1, 65535] {
        config.port = Some(port);
        assert_eq!(
            args(&config),
            [
                OsString::from("-p"),
                OsString::from(port.to_string()),
                OsString::from("--"),
                OsString::from("alias")
            ]
        );
    }
    let temp = TempDir::new().unwrap();
    for path in [
        "relative-key".to_owned(),
        "~another-user/key".to_owned(),
        String::new(),
        temp.path().join("missing").to_str().unwrap().to_owned(),
        temp.path().to_str().unwrap().to_owned(),
        "/bad\nkey".to_owned(),
    ] {
        config.identity_file = Some(path);
        assert!(command(&config).is_err());
        assert!(validate_config(&config).is_err());
    }
}

#[test]
fn tilde_expands_supplied_home_without_global_environment_changes() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("test identity");
    fs::write(&key, "isolated fixture").unwrap();
    let env = Environment::from([(OsString::from("HOME"), home.path().as_os_str().to_owned())]);
    let mut config = config("alias");
    config.identity_file = Some("~/test identity".into());
    let command = ssh_command(&config, Uuid::nil(), home.path(), &env).unwrap();
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [
            OsStr::new("-i"),
            key.as_os_str(),
            OsStr::new("--"),
            OsStr::new("alias")
        ]
    );
}

#[test]
fn absent_or_empty_password_keeps_user_openssh_configuration_and_strips_private_routes() {
    let env = Environment::from([
        ("SSH_ASKPASS".into(), "/external/askpass".into()),
        ("SSH_ASKPASS_REQUIRE".into(), "prefer".into()),
        ("HOST_MANAGER_SSH_INTERNAL".into(), "askpass".into()),
        ("HOST_MANAGER_ASKPASS_PID".into(), "123".into()),
        ("HOST_MANAGER_ASKPASS_FUTURE".into(), "stale".into()),
    ]);
    for password in [None, Some(String::new())] {
        let mut config = config("alias");
        config.password = password;
        let command = ssh_command(
            &config,
            Uuid::nil(),
            Path::new("relative-unused-directory"),
            &env,
        )
        .unwrap();
        assert_eq!(command.get_program(), "ssh");
        assert_eq!(command.get_args().collect::<Vec<_>>(), ["--", "alias"]);
        let actual = environment(&command);
        assert_eq!(
            actual.get(OsStr::new("SSH_ASKPASS")).unwrap(),
            "/external/askpass"
        );
        assert_eq!(
            actual.get(OsStr::new("SSH_ASKPASS_REQUIRE")).unwrap(),
            "prefer"
        );
        assert!(!actual.keys().any(|key| {
            key.as_encoded_bytes().starts_with(b"HOST_MANAGER_ASKPASS_")
                || key == "HOST_MANAGER_SSH_INTERNAL"
        }));
    }
}

#[test]
fn saved_password_selects_self_runner_without_exposing_or_hashing_password() {
    let temp = TempDir::new().unwrap();
    let mut config = config("final-alias");
    config.user = Some("root".into());
    config.port = Some(2222);
    config.password = Some("UNIQUE_SECRET_NOT_FOR_ENV_OR_ARGV".into());
    let id = Uuid::new_v4();
    let first = ssh_command(&config, id, temp.path(), &Environment::new()).unwrap();
    assert_eq!(
        first.get_program(),
        std::env::current_exe().unwrap().as_os_str()
    );
    assert_eq!(
        first.get_args().collect::<Vec<_>>(),
        [
            "--host-manager-ssh",
            "-l",
            "root",
            "-p",
            "2222",
            "--",
            "final-alias"
        ]
    );
    let metadata = environment(&first);
    assert_eq!(
        metadata
            .get(OsStr::new("HOST_MANAGER_SSH_INTERNAL"))
            .unwrap(),
        "run"
    );
    assert_eq!(
        metadata
            .get(OsStr::new("HOST_MANAGER_ASKPASS_DIR"))
            .unwrap(),
        temp.path().as_os_str()
    );
    assert_eq!(
        metadata.get(OsStr::new("HOST_MANAGER_ASKPASS_ID")).unwrap(),
        &OsString::from(id.to_string())
    );
    assert!(!metadata.contains_key(OsStr::new("HOST_MANAGER_ASKPASS_PID")));
    assert!(!metadata.contains_key(OsStr::new("SSH_ASKPASS")));
    let secret = config.password.as_ref().unwrap();
    assert!(!first.get_args().any(|argument| {
        argument
            .as_encoded_bytes()
            .windows(secret.len())
            .any(|part| part == secret.as_bytes())
    }));
    assert!(!metadata.values().any(|value| {
        value
            .as_encoded_bytes()
            .windows(secret.len())
            .any(|part| part == secret.as_bytes())
    }));
    config.password = Some("different password".into());
    let second = ssh_command(&config, id, temp.path(), &Environment::new()).unwrap();
    assert_eq!(
        metadata,
        environment(&second),
        "fingerprint must not reveal password changes"
    );
    config.host = "other-alias".into();
    let changed = ssh_command(&config, id, temp.path(), &Environment::new()).unwrap();
    assert_ne!(
        metadata.get(OsStr::new("HOST_MANAGER_ASKPASS_TARGET")),
        environment(&changed).get(OsStr::new("HOST_MANAGER_ASKPASS_TARGET"))
    );
}

#[test]
fn password_length_is_utf8_bytes_and_only_limits_autofill() {
    let mut config = config("alias");
    for password in ["a".repeat(1023), format!("{}a", "я".repeat(511))] {
        config.password = Some(password);
        assert!(command(&config).is_ok());
    }
    for password in ["a".repeat(1024), "я".repeat(512)] {
        config.password = Some(password);
        assert!(
            validate_config(&config).is_ok(),
            "storage must allow manual-only passwords"
        );
        assert!(command(&config).is_err());
    }
    config.password = Some("secret".into());
    assert!(
        ssh_command(
            &config,
            Uuid::nil(),
            Path::new("relative"),
            &Environment::new()
        )
        .is_err()
    );
}

#[test]
fn expanded_home_is_preserved_in_identity_arguments() {
    use std::os::unix::ffi::OsStringExt;
    let temp = TempDir::new().unwrap();
    // macOS rejects non-UTF-8 filenames; Linux also exercises them on disk.
    let home = temp.path().join(if cfg!(target_os = "linux") {
        OsString::from_vec(b"home-\xff".to_vec())
    } else {
        OsString::from("home-ключ")
    });
    fs::create_dir(&home).unwrap();
    let key = home.join("key");
    fs::write(&key, "isolated fixture").unwrap();
    let env = Environment::from([("HOME".into(), home.into_os_string())]);
    let mut config = config("alias");
    config.identity_file = Some("~/key".into());
    config.password = Some("saved".into());
    let command = ssh_command(&config, Uuid::nil(), temp.path(), &env).unwrap();
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [
            OsStr::new("--host-manager-ssh"),
            OsStr::new("-i"),
            key.as_os_str(),
            OsStr::new("--"),
            OsStr::new("alias")
        ]
    );
}
