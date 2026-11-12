use std::{
    ffi::{OsStr, OsString},
    fs::OpenOptions,
    io::{self, IsTerminal, Write},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Result, anyhow, ensure};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    model::{SshConfig, validate_line},
    store::{self, Environment},
};

const INTERNAL: &str = "HOST_MANAGER_SSH_INTERNAL";
const DIRECTORY: &str = "HOST_MANAGER_ASKPASS_DIR";
const HOST_ID: &str = "HOST_MANAGER_ASKPASS_ID";
const TARGET: &str = "HOST_MANAGER_ASKPASS_TARGET";
const SSH_PID: &str = "HOST_MANAGER_ASKPASS_PID";
const RUNNER: &str = "--host-manager-ssh";
const PASSWORD_OPTIONS: [&str; 7] = [
    "PreferredAuthentications=password",
    "PasswordAuthentication=yes",
    "PubkeyAuthentication=no",
    "KbdInteractiveAuthentication=no",
    "NumberOfPasswordPrompts=1",
    "StrictHostKeyChecking=ask",
    "BatchMode=no",
];

fn identity_path(value: &str, home: Option<&OsStr>) -> Result<PathBuf> {
    validate_line(value)?;
    let path = if value == "~" || value.starts_with("~/") {
        let home = home
            .filter(|home| !home.is_empty())
            .ok_or_else(|| anyhow!("Не задана домашняя папка для SSH-ключа"))?;
        let mut path = PathBuf::from(home);
        if let Some(relative) = value.strip_prefix("~/") {
            path.push(relative);
        }
        path
    } else {
        PathBuf::from(value)
    };
    ensure!(
        path.is_absolute(),
        "Путь к SSH-ключу должен быть абсолютным либо начинаться с ~/"
    );
    let metadata = path
        .metadata()
        .map_err(|_| anyhow!("SSH-ключ недоступен"))?;
    ensure!(metadata.is_file(), "SSH-ключ должен быть обычным файлом");
    Ok(path)
}

fn validate_fields(config: &SshConfig) -> Result<()> {
    let host = &config.host;
    ensure!(
        !host.is_empty() && !host.starts_with('-'),
        "Некорректный адрес SSH"
    );
    ensure!(
        !host.chars().any(|ch| ch.is_whitespace() || ch.is_control())
            && !host.contains(['@', '/', '\\']),
        "Используйте адрес или SSH alias без пользователя, URL и пробелов"
    );
    if let Some(user) = &config.user {
        ensure!(
            !user.is_empty()
                && !user.starts_with('-')
                && !user.chars().any(|ch| ch.is_whitespace() || ch.is_control()),
            "Некорректное имя пользователя SSH"
        );
    }
    ensure!(config.port != Some(0), "Порт SSH должен быть от 1 до 65535");
    if let Some(password) = &config.password {
        validate_line(password)?;
    }
    Ok(())
}

pub fn validate_config(config: &SshConfig) -> Result<()> {
    validate_fields(config)?;
    if let Some(identity) = &config.identity_file {
        let home = std::env::var_os("HOME");
        identity_path(identity, home.as_deref())?;
    }
    Ok(())
}

fn saved_password(config: &SshConfig) -> Result<Option<&str>> {
    let password = config
        .password
        .as_deref()
        .filter(|password| !password.is_empty());
    if let Some(password) = password {
        validate_line(password)?;
        ensure!(
            password.len() <= 1023,
            "Пароль SSH превышает допустимую длину OpenSSH"
        );
    }
    Ok(password)
}

fn target_fingerprint(config: &SshConfig, identity: Option<&Path>) -> String {
    let mut hash = Sha256::new();
    for value in [
        Some(config.host.as_bytes()),
        config.user.as_deref().map(str::as_bytes),
        identity.map(|path| path.as_os_str().as_encoded_bytes()),
    ] {
        // Presence tags distinguish null from an explicitly empty value.
        hash.update([u8::from(value.is_some())]);
        if let Some(value) = value {
            hash.update(value);
        }
        hash.update([0]);
    }
    hash.update(config.port.unwrap_or(0).to_be_bytes());
    format!("{:x}", hash.finalize())
}

fn clean_command(program: &OsStr, env: &Environment) -> Command {
    let mut command = Command::new(program);
    command.env_clear().envs(env);
    for key in env.keys() {
        if key == INTERNAL || key.as_encoded_bytes().starts_with(b"HOST_MANAGER_ASKPASS_") {
            command.env_remove(key);
        }
    }
    command
}

pub fn ssh_command(
    config: &SshConfig,
    host_id: Uuid,
    pass_dir: &Path,
    env: &Environment,
) -> Result<Command> {
    validate_fields(config)?;
    let password_mode = saved_password(config)?.is_some();
    let identity = config
        .identity_file
        .as_deref()
        .map(|value| identity_path(value, env.get(OsStr::new("HOME")).map(OsString::as_os_str)))
        .transpose()?;
    let mut command = if password_mode {
        ensure!(pass_dir.is_absolute(), "Некорректная папка SSH askpass");
        let executable =
            std::env::current_exe().map_err(|_| anyhow!("Не удалось найти SSH askpass"))?;
        let mut command = clean_command(executable.as_os_str(), env);
        command
            .arg(RUNNER)
            .env(INTERNAL, "run")
            .env(DIRECTORY, pass_dir)
            .env(HOST_ID, host_id.to_string())
            .env(TARGET, target_fingerprint(config, identity.as_deref()));
        command
    } else {
        clean_command(OsStr::new("ssh"), env)
    };
    if let Some(user) = &config.user {
        command.arg("-l").arg(user);
    }
    if let Some(port) = config.port {
        command.arg("-p").arg(port.to_string());
    }
    if let Some(identity) = identity {
        command.arg("-i").arg(identity);
    }
    command.arg("--").arg(&config.host);
    Ok(command)
}

struct AskpassContext {
    directory: PathBuf,
    host_id: Uuid,
    target: String,
}

fn context(env: &Environment) -> Result<AskpassContext> {
    let invalid = || anyhow!("Некорректный контекст SSH askpass");
    let directory = PathBuf::from(env.get(OsStr::new(DIRECTORY)).ok_or_else(invalid)?);
    ensure!(directory.is_absolute(), "Некорректный контекст SSH askpass");
    let host_id = env
        .get(OsStr::new(HOST_ID))
        .and_then(|value| value.to_str())
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(invalid)?;
    let target = env
        .get(OsStr::new(TARGET))
        .and_then(|value| value.to_str())
        .ok_or_else(invalid)?;
    ensure!(
        target.len() == 64
            && target
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Некорректный контекст SSH askpass"
    );
    Ok(AskpassContext {
        directory,
        host_id,
        target: target.to_owned(),
    })
}

fn runner_target(args: &[OsString]) -> Result<String> {
    let mut index = 0;
    let mut config = SshConfig {
        host: String::new(),
        user: None,
        port: None,
        identity_file: None,
        password: None,
    };
    let mut identity = None;
    for option in ["-l", "-p", "-i"] {
        if args.get(index).is_some_and(|value| value == option) {
            let value = args
                .get(index + 1)
                .ok_or_else(|| anyhow!("Некорректные аргументы SSH askpass"))?;
            if option == "-i" {
                let path = Path::new(value);
                ensure!(
                    path.is_absolute() && path.is_file(),
                    "Некорректные аргументы SSH askpass"
                );
                identity = Some(path);
            } else {
                let value = value
                    .to_str()
                    .ok_or_else(|| anyhow!("Некорректные аргументы SSH askpass"))?;
                if option == "-l" {
                    config.user = Some(value.to_owned());
                } else {
                    let port: u16 = value
                        .parse()
                        .map_err(|_| anyhow!("Некорректные аргументы SSH askpass"))?;
                    ensure!(
                        port.to_string() == value,
                        "Некорректные аргументы SSH askpass"
                    );
                    config.port = Some(port);
                }
            }
            index += 2;
        }
    }
    ensure!(
        args.len() == index + 2 && args[index] == "--",
        "Некорректные аргументы SSH askpass"
    );
    config.host = args[index + 1]
        .to_str()
        .ok_or_else(|| anyhow!("Некорректные аргументы SSH askpass"))?
        .to_owned();
    validate_fields(&config)?;
    Ok(target_fingerprint(&config, identity))
}

fn runner_command(args: &[OsString], env: &Environment) -> Result<Command> {
    let context = context(env)?;
    ensure!(
        runner_target(args)? == context.target,
        "SSH askpass: параметры подключения изменились"
    );
    let mut command = Command::new("ssh");
    command.env_clear().envs(env);
    for option in PASSWORD_OPTIONS {
        command.arg("-o").arg(option);
    }
    command
        .args(args)
        .env(
            "SSH_ASKPASS",
            std::env::current_exe().map_err(|_| anyhow!("Не удалось найти SSH askpass"))?,
        )
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env(INTERNAL, "askpass")
        .env(SSH_PID, std::process::id().to_string())
        .env_remove("SSH_ASKPASS_PROMPT");
    Ok(command)
}

#[derive(Debug, PartialEq, Eq)]
enum PromptRoute {
    Password,
    Manual,
    Notification,
}

fn prompt_route(
    prompt: &str,
    hint: Option<&OsStr>,
    expected_pid: u32,
    parent_pid: u32,
) -> PromptRoute {
    if hint == Some(OsStr::new("none")) {
        return PromptRoute::Notification;
    }
    if hint.is_none()
        && expected_pid != 0
        && expected_pid == parent_pid
        && !prompt.chars().any(char::is_control)
        && prompt.strip_suffix("'s password: ").is_some_and(|prefix| {
            !prefix.chars().any(char::is_whitespace)
                && prefix
                    .rsplit_once('@')
                    .is_some_and(|(user, host)| !user.is_empty() && !host.is_empty())
        })
    {
        PromptRoute::Password
    } else {
        PromptRoute::Manual
    }
}

fn helper_password<'a>(
    catalog: &'a crate::model::Catalog,
    context: &AskpassContext,
    env: &Environment,
) -> Result<&'a str> {
    let mut hosts = catalog
        .hosts
        .iter()
        .filter(|host| host.id == context.host_id);
    let host = hosts
        .next()
        .ok_or_else(|| anyhow!("SSH askpass: запись недоступна"))?;
    ensure!(hosts.next().is_none(), "SSH askpass: неоднозначная запись");
    let config = host
        .ssh
        .as_ref()
        .ok_or_else(|| anyhow!("SSH askpass: доступ не настроен"))?;
    validate_fields(config)?;
    let identity = config
        .identity_file
        .as_deref()
        .map(|value| identity_path(value, env.get(OsStr::new("HOME")).map(OsString::as_os_str)))
        .transpose()?;
    ensure!(
        target_fingerprint(config, identity.as_deref()) == context.target,
        "SSH askpass: параметры подключения изменились"
    );
    saved_password(config)?.ok_or_else(|| anyhow!("SSH askpass: пароль недоступен"))
}

struct ManualTerminal {
    signal: signal_hook::SigId,
    interrupted: Arc<AtomicBool>,
    raw: bool,
}

impl ManualTerminal {
    fn new() -> Result<Self> {
        let interrupted = Arc::new(AtomicBool::new(false));
        let signal =
            signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&interrupted))?;
        let mut terminal = Self {
            signal,
            interrupted,
            raw: false,
        };
        terminal::enable_raw_mode()?;
        terminal.raw = true;
        Ok(terminal)
    }
}

impl Drop for ManualTerminal {
    fn drop(&mut self) {
        if self.raw {
            let _ = terminal::disable_raw_mode();
        }
        signal_hook::low_level::unregister(self.signal);
    }
}

fn display_prompt(tty: &mut impl Write, prompt: &str) -> io::Result<()> {
    for character in prompt.chars() {
        if character.is_control() {
            write!(tty, "{}", character.escape_default())?;
        } else {
            write!(tty, "{character}")?;
        }
    }
    tty.flush()
}

fn attach_terminal_input() -> Result<()> {
    if io::stdin().is_terminal() {
        return Ok(());
    }
    // ProxyJump gives the helper a pipe; Crossterm needs the real controlling TTY.
    let output = Command::new("/bin/ps")
        .args(["-o", "tty=", "-p"])
        .arg(std::process::id().to_string())
        .output()
        .map_err(|_| anyhow!("Не удалось определить терминал SSH askpass"))?;
    ensure!(
        output.status.success(),
        "Не удалось определить терминал SSH askpass"
    );
    let name = std::str::from_utf8(&output.stdout)
        .map_err(|_| anyhow!("Некорректный терминал SSH askpass"))?
        .trim();
    ensure!(
        !name.is_empty()
            && !name.starts_with('/')
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-')),
        "SSH askpass требует интерактивный терминал",
    );
    let input = OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new("/dev").join(name))
        .map_err(|_| anyhow!("Не удалось открыть терминал SSH askpass"))?;
    ensure!(
        input.is_terminal(),
        "SSH askpass требует интерактивный терминал"
    );
    let mut command =
        Command::new(std::env::current_exe().map_err(|_| anyhow!("Не удалось найти SSH askpass"))?);
    command.args(std::env::args_os().skip(1)).stdin(input);
    let _error = command.exec();
    Err(anyhow!("Не удалось подключить терминал SSH askpass"))
}

fn manual_response(prompt: &str, notification: bool) -> Result<Option<String>> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| anyhow!("SSH askpass требует интерактивный терминал"))?;
    if notification {
        display_prompt(&mut tty, prompt)?;
        writeln!(tty)?;
        return Ok(None);
    }
    attach_terminal_input()?;
    let terminal = ManualTerminal::new()?;
    display_prompt(&mut tty, prompt)?;
    let mut response = String::new();
    loop {
        ensure!(
            !terminal.interrupted.load(Ordering::Relaxed),
            "SSH askpass: ввод отменён"
        );
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Release {
                continue;
            }
            match key.code {
                KeyCode::Esc => return Err(anyhow!("SSH askpass: ввод отменён")),
                KeyCode::Char('c' | 'C' | 'd' | 'D')
                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    return Err(anyhow!("SSH askpass: ввод отменён"));
                }
                KeyCode::Enter => {
                    write!(tty, "\r\n")?;
                    return Ok(Some(response));
                }
                KeyCode::Backspace => {
                    response.pop();
                }
                KeyCode::Char(character)
                    if !character.is_control()
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    ensure!(
                        response.len() + character.len_utf8() <= 1023,
                        "SSH askpass: ответ слишком длинный",
                    );
                    response.push(character);
                }
                _ => {}
            }
        }
    }
}

fn askpass(args: &[OsString], env: &Environment) -> Result<ExitCode> {
    ensure!(args.len() == 1, "Некорректный вызов SSH askpass");
    let prompt = args[0]
        .to_str()
        .ok_or_else(|| anyhow!("Некорректный запрос SSH askpass"))?;
    let context = context(env)?;
    let expected_pid = env
        .get(OsStr::new(SSH_PID))
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid != 0)
        .ok_or_else(|| anyhow!("Некорректный контекст SSH askpass"))?;
    let route = prompt_route(
        prompt,
        env.get(OsStr::new("SSH_ASKPASS_PROMPT"))
            .map(OsString::as_os_str),
        expected_pid,
        std::os::unix::process::parent_id(),
    );
    if route == PromptRoute::Password {
        let catalog = store::load_catalog(&context.directory, env)
            .map_err(|_| anyhow!("SSH askpass: не удалось прочитать сохранённые данные"))?;
        let password = helper_password(&catalog, &context, env)?;
        let mut output = io::stdout().lock();
        output.write_all(password.as_bytes())?;
        output.write_all(b"\n")?;
        output.flush()?;
    } else if let Some(response) = manual_response(prompt, route == PromptRoute::Notification)? {
        let mut output = io::stdout().lock();
        output.write_all(response.as_bytes())?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(ExitCode::SUCCESS)
}

pub fn internal_command(args: &[OsString]) -> Option<Result<ExitCode>> {
    std::env::var_os(INTERNAL)?;
    let env: Environment = std::env::vars_os().collect();
    match env.get(OsStr::new(INTERNAL)) {
        Some(mode) if mode == "run" => Some((|| {
            ensure!(
                args.first().is_some_and(|arg| arg == RUNNER),
                "Некорректный вызов SSH askpass"
            );
            let mut command = runner_command(&args[1..], &env)?;
            let _error = command.exec();
            eprintln!("Не удалось запустить SSH");
            Ok(ExitCode::from(127))
        })()),
        Some(mode) if mode == "askpass" => Some(askpass(args, &env)),
        Some(_) => Some(Err(anyhow!("Некорректный вызов SSH askpass"))),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Billing, BillingPeriod, Catalog, Host};
    use rust_decimal::Decimal;

    fn config() -> SshConfig {
        SshConfig {
            host: "final-alias".into(),
            user: Some("root".into()),
            port: Some(2222),
            identity_file: None,
            password: Some("saved-secret".into()),
        }
    }

    fn metadata(command: &Command) -> Environment {
        command
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
            .collect()
    }

    #[test]
    fn only_initial_password_from_the_bound_parent_without_a_hint_can_autofill() {
        for prompt in [
            "root@final-alias's password: ",
            "юзер@2001:db8::1's password: ",
        ] {
            assert_eq!(prompt_route(prompt, None, 42, 42), PromptRoute::Password);
            assert_eq!(prompt_route(prompt, None, 42, 43), PromptRoute::Manual);
            for hint in ["confirm", "", "unknown"] {
                assert_eq!(
                    prompt_route(prompt, Some(OsStr::new(hint)), 42, 42),
                    PromptRoute::Manual
                );
            }
            assert_eq!(
                prompt_route(prompt, Some(OsStr::new("none")), 42, 42),
                PromptRoute::Notification
            );
        }
        for prompt in [
            "",
            "Password: ",
            "root's password: ",
            "@host's password: ",
            "root@'s password: ",
            "root@host's password:",
            "root@host's password: \n",
            "root@\u{1b}[31mhost's password: ",
            "root@host's old password: ",
            "root@host's new password: ",
            "Retype new password: ",
            "Enter passphrase for key '/key': ",
            "Verification code: ",
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
        ] {
            assert_eq!(prompt_route(prompt, None, 42, 42), PromptRoute::Manual);
        }
        assert_eq!(
            prompt_route("root@host's password: ", None, 0, 0),
            PromptRoute::Manual
        );
    }

    #[test]
    fn runner_binds_its_exec_pid_and_enforces_password_only_without_relaxing_host_keys() {
        let config = config();
        let built = ssh_command(
            &config,
            Uuid::nil(),
            Path::new("/test-store"),
            &Environment::new(),
        )
        .unwrap();
        let mut env = metadata(&built);
        env.insert("SSH_ASKPASS_PROMPT".into(), "confirm".into());
        env.insert("SSH_ASKPASS".into(), "/untrusted/helper".into());
        env.insert(SSH_PID.into(), "999999".into());
        let base: Vec<_> = built.get_args().skip(1).map(OsString::from).collect();
        let runner = runner_command(&base, &env).unwrap();
        assert_eq!(runner.get_program(), "ssh");
        let arguments: Vec<_> = runner.get_args().collect();
        for (pair, option) in arguments[..PASSWORD_OPTIONS.len() * 2]
            .chunks_exact(2)
            .zip(PASSWORD_OPTIONS)
        {
            assert_eq!(pair, [OsStr::new("-o"), OsStr::new(option)]);
        }
        assert_eq!(
            &arguments[PASSWORD_OPTIONS.len() * 2..],
            base.iter().map(OsString::as_os_str).collect::<Vec<_>>()
        );
        let actual = metadata(&runner);
        assert_eq!(
            actual.get(OsStr::new(SSH_PID)).unwrap(),
            &OsString::from(std::process::id().to_string())
        );
        assert_eq!(actual.get(OsStr::new(INTERNAL)).unwrap(), "askpass");
        assert_eq!(
            actual.get(OsStr::new("SSH_ASKPASS_REQUIRE")).unwrap(),
            "force"
        );
        assert_eq!(
            actual.get(OsStr::new("SSH_ASKPASS")).unwrap(),
            std::env::current_exe().unwrap().as_os_str()
        );
        assert!(!actual.contains_key(OsStr::new("SSH_ASKPASS_PROMPT")));
        assert!(!actual.values().any(|value| value == "saved-secret"));
    }

    #[test]
    fn runner_rejects_extra_options_commands_duplicates_and_changed_targets() {
        let config = config();
        let built = ssh_command(
            &config,
            Uuid::nil(),
            Path::new("/test-store"),
            &Environment::new(),
        )
        .unwrap();
        let env = metadata(&built);
        for arguments in [
            vec![],
            vec!["--"],
            vec!["-o", "StrictHostKeyChecking=no", "--", "final-alias"],
            vec!["--", "final-alias", "remote-command"],
            vec!["-l", "root", "-l", "other", "--", "final-alias"],
            vec!["-p", "2222", "-p", "2223", "--", "final-alias"],
            vec!["-l", "root", "-p", "65536", "--", "final-alias"],
            vec!["-l", "root", "-p", "02222", "--", "final-alias"],
            vec!["-l", "root", "-p", "0", "--", "final-alias"],
            vec!["-l", "root", "-p", "2222", "--", "other-alias"],
            vec!["-l", "other", "-p", "2222", "--", "final-alias"],
            vec!["-l", "root", "-p", "2223", "--", "final-alias"],
            vec!["-l", "root", "-p", "2222", "--", "-host"],
        ] {
            let arguments: Vec<OsString> = arguments.into_iter().map(OsString::from).collect();
            assert!(runner_command(&arguments, &env).is_err());
        }
        let base: Vec<_> = built.get_args().skip(1).map(OsString::from).collect();
        for key in [DIRECTORY, HOST_ID, TARGET] {
            let mut changed = env.clone();
            changed.remove(OsStr::new(key));
            assert!(runner_command(&base, &changed).is_err());
            changed.insert(key.into(), "SECRET_INVALID_METADATA".into());
            let error = runner_command(&base, &changed).err().unwrap().to_string();
            assert!(!error.contains("SECRET_INVALID_METADATA"));
        }
    }

    #[test]
    fn runner_hashes_the_lossless_expanded_identity_path() {
        use std::os::unix::ffi::OsStringExt;
        let temp = tempfile::TempDir::new().unwrap();
        // macOS rejects non-UTF-8 filenames; Linux also exercises them on disk.
        let home = temp.path().join(if cfg!(target_os = "linux") {
            OsString::from_vec(b"home-\xff".to_vec())
        } else {
            OsString::from("home-ключ")
        });
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join("key"), "isolated fixture").unwrap();
        let env = Environment::from([("HOME".into(), home.into_os_string())]);
        let mut config = config();
        config.identity_file = Some("~/key".into());
        let built = ssh_command(&config, Uuid::nil(), temp.path(), &env).unwrap();
        let arguments: Vec<_> = built.get_args().skip(1).map(OsString::from).collect();
        assert!(runner_command(&arguments, &metadata(&built)).is_ok());
        let routing = metadata(&built);
        let context = context(&routing).unwrap();
        let catalog = Catalog {
            version: 1,
            hosts: vec![host(config)],
        };
        assert_eq!(
            helper_password(&catalog, &context, &env).unwrap(),
            "saved-secret"
        );
        let other_key = temp.path().join("other-key");
        std::fs::write(&other_key, "isolated fixture").unwrap();
        let mut changed = arguments;
        let identity_index = changed.iter().position(|arg| arg == "-i").unwrap() + 1;
        changed[identity_index] = other_key.into_os_string();
        assert!(runner_command(&changed, &routing).is_err());
    }

    #[test]
    fn target_fingerprint_does_not_collapse_non_utf8_path_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let invalid = PathBuf::from(OsString::from_vec(b"/home-\xff/key".to_vec()));
        let replacement = PathBuf::from("/home-\u{fffd}/key");
        assert_ne!(
            target_fingerprint(&config(), Some(&invalid)),
            target_fingerprint(&config(), Some(&replacement)),
        );
    }

    fn host(config: SshConfig) -> Host {
        Host {
            id: Uuid::nil(),
            name: "test".into(),
            provider: "test".into(),
            panel_url: None,
            account_login: None,
            account_password: None,
            notes: String::new(),
            archived: true,
            ssh: Some(config),
            billing: Billing {
                amount: Decimal::ZERO,
                currency: "EUR".into(),
                period: BillingPeriod::Month,
                period_note: None,
                next_due: None,
            },
            payments: Vec::new(),
        }
    }

    #[test]
    fn password_lookup_allows_archived_uuid_but_fails_closed_on_missing_changed_or_duplicate_data()
    {
        let config = config();
        let context = AskpassContext {
            directory: PathBuf::from("/test-store"),
            host_id: Uuid::nil(),
            target: target_fingerprint(&config, None),
        };
        let env = Environment::new();
        let mut catalog = Catalog {
            version: 1,
            hosts: vec![host(config)],
        };
        assert_eq!(
            helper_password(&catalog, &context, &env).unwrap(),
            "saved-secret"
        );
        catalog.hosts[0].ssh.as_mut().unwrap().host = "changed".into();
        let error = helper_password(&catalog, &context, &env)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("saved-secret"));
        catalog.hosts[0].ssh = Some(self::config());
        catalog.hosts[0].ssh.as_mut().unwrap().password = Some("updated-secret".into());
        assert_eq!(
            helper_password(&catalog, &context, &env).unwrap(),
            "updated-secret"
        );
        for password in [
            None,
            Some(String::new()),
            Some("x".repeat(1024)),
            Some("secret\n".into()),
        ] {
            catalog.hosts[0].ssh.as_mut().unwrap().password = password;
            assert!(helper_password(&catalog, &context, &env).is_err());
        }
        catalog.hosts[0].ssh = None;
        assert!(helper_password(&catalog, &context, &env).is_err());
        catalog.hosts[0].ssh = Some(self::config());
        catalog.hosts.push(catalog.hosts[0].clone());
        assert!(helper_password(&catalog, &context, &env).is_err());
        catalog.hosts.clear();
        assert!(helper_password(&catalog, &context, &env).is_err());
    }

    #[test]
    fn manual_prompt_escapes_terminal_controls_without_writing_a_credential() {
        let mut output = Vec::new();
        display_prompt(&mut output, "Host\u{1b}[2J\r\nconfirm? ").unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Host\\u{1b}[2J\\r\\nconfirm? "
        );
    }
}
