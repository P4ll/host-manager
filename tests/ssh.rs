use std::{ffi::OsString, fs};

use host_manager::{
    model::SshConfig,
    ssh::{ssh_command, validate_config},
};
use tempfile::TempDir;

fn config(host: &str) -> SshConfig {
    SshConfig {
        host: host.into(),
        user: None,
        port: None,
        identity_file: None,
        password: None,
    }
}

fn args(config: &SshConfig) -> Vec<OsString> {
    let command = ssh_command(config).unwrap();
    assert_eq!(command.get_program(), "ssh");
    assert_eq!(
        command.get_envs().count(),
        0,
        "passwords must not be supplied through the environment"
    );
    command.get_args().map(OsString::from).collect()
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
    config.password = Some("SHOULD_NEVER_REACH_SSH".into());
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
        assert!(ssh_command(&config).is_err(), "accepted invalid host");
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
        assert!(ssh_command(&config).is_err(), "accepted invalid user");
    }
    let mut config = config("alias");
    config.password = Some("secret\n".into());
    let error = ssh_command(&config).err().unwrap().to_string();
    assert!(!error.contains("secret"));
}

#[test]
fn port_and_key_path_boundaries() {
    let mut config = config("alias");
    config.port = Some(0);
    assert!(ssh_command(&config).is_err());
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
        assert!(ssh_command(&config).is_err());
        assert!(validate_config(&config).is_err());
    }
}

#[test]
fn tilde_expands_home_without_reading_user_keys_or_changing_environment() {
    let home = std::path::PathBuf::from(
        std::env::var_os("HOME").expect("HOME is required for the tilde test"),
    )
    .canonicalize()
    .unwrap();
    let temp = TempDir::new().unwrap();
    let path = temp.path().canonicalize().unwrap().join("test identity");
    fs::write(&path, "isolated fixture").unwrap();
    // Climb to / so the only inspected file is the temporary fixture, not a user key.
    let expanded = format!(
        "~/{}{}",
        "../".repeat(home.components().count()),
        path.strip_prefix("/").unwrap().to_str().unwrap()
    );
    let mut config = config("alias");
    config.identity_file = Some(expanded);
    let arguments = args(&config);
    assert_eq!(arguments[0], "-i");
    let actual = std::path::Path::new(&arguments[1]);
    assert!(actual.is_absolute());
    assert_eq!(actual.canonicalize().unwrap(), path);
    assert_eq!(arguments[2], "--");
    assert_eq!(arguments[3], "alias");
}
