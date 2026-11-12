use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail, ensure};
use host_manager::{app::App, model, ssh, store, terminal};
use rust_decimal::Decimal;
use uuid::Uuid;

const USAGE: &str = "Использование:\n  host-manager [--pass-dir PATH]\n  host-manager [--pass-dir PATH] connect NAME [--pass-dir PATH]\n  host-manager template FILE\n  host-manager [--pass-dir PATH] import FILE\n  host-manager --help\n  host-manager COMMAND --help\n\nБез подкоманды открывается TUI. connect подключается через системный SSH.\nСохранённый SSH-пароль включает password-only автовход через SSH_ASKPASS; без него используются обычные настройки OpenSSH.\ntemplate создаёт JSON-шаблон без перезаписи файла; import добавляет заполненные VPS в pass.\nШаблон и заполненный файл — открытый текст; удаляйте их вручную после импорта.\nПапка: --pass-dir, затем HOST_MANAGER_PASS_DIR, иначе host-manager в корне pass.\nИспользуйте -- для окончания разбора опций; имена и пути с пробелами заключайте в кавычки.";

struct Arguments {
    pass_dir: Option<PathBuf>,
    action: Action,
}

enum Action {
    Tui,
    Connect(String),
    Template(PathBuf),
    Import(PathBuf),
    Help,
}

fn parse_arguments(args: impl IntoIterator<Item = OsString>) -> Result<Arguments> {
    let mut args = args.into_iter();
    let mut pass_dir = None;
    let mut positional = Vec::new();
    let mut options = true;
    let mut help = false;
    while let Some(arg) = args.next() {
        if options && arg == "--" {
            options = false;
        } else if options && arg == "--pass-dir" {
            if pass_dir.is_some() {
                bail!("Флаг --pass-dir указан повторно");
            }
            let value = args.next().context("Для --pass-dir требуется путь")?;
            if value.is_empty() || value.as_encoded_bytes().starts_with(b"-") {
                bail!("Для --pass-dir требуется непустой путь (путь с дефисом начните с ./)");
            }
            pass_dir = Some(PathBuf::from(value));
        } else if options && (arg == "-h" || arg == "--help") {
            if help {
                bail!("Флаг справки указан повторно");
            }
            help = true;
        } else if options && arg.as_encoded_bytes().starts_with(b"-") {
            bail!("Неизвестная опция");
        } else {
            positional.push(arg);
        }
    }
    let action = match positional.as_slice() {
        [] if help => Action::Help,
        [] => Action::Tui,
        [command]
            if help && (command == "connect" || command == "template" || command == "import") =>
        {
            Action::Help
        }
        [command, name] if command == "connect" && !help => {
            let name = name.to_str().context("Имя VPS должно быть в UTF-8")?;
            if name.is_empty() || name.chars().any(char::is_control) {
                bail!("Имя VPS должно быть непустым и без управляющих символов");
            }
            Action::Connect(name.to_owned())
        }
        [command, path] if !help && (command == "template" || command == "import") => {
            ensure!(!path.is_empty(), "Путь файла не может быть пустым");
            if command == "template" {
                Action::Template(PathBuf::from(path))
            } else {
                Action::Import(PathBuf::from(path))
            }
        }
        _ => bail!("Неизвестная команда или неверное число аргументов"),
    };
    Ok(Arguments { pass_dir, action })
}

fn write_template(path: &Path) -> Result<()> {
    let catalog = model::Catalog {
        version: 1,
        hosts: vec![model::Host {
            id: Uuid::new_v4(),
            name: String::new(),
            provider: String::new(),
            panel_url: None,
            account_login: None,
            account_password: None,
            notes: String::new(),
            archived: false,
            ssh: Some(model::SshConfig {
                host: String::new(),
                user: None,
                port: None,
                identity_file: None,
                password: None,
            }),
            billing: model::Billing {
                amount: Decimal::ZERO,
                currency: "EUR".into(),
                period: model::BillingPeriod::Month,
                period_note: None,
                next_due: None,
            },
            payments: Vec::new(),
        }],
    };
    let mut bytes = serde_json::to_vec_pretty(&catalog).context("Не удалось подготовить шаблон")?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("Не удалось создать шаблон: файл уже существует или путь недоступен")?;
    file.write_all(&bytes)
        .context("Не удалось записать шаблон; созданный файл может быть неполным")?;
    println!("Шаблон создан. Заполните name, provider и ssh.host (или задайте ssh: null).");
    println!("Файл — открытый текст; после импорта удалите его вручную.");
    Ok(())
}

fn import_file(path: &Path, pass_dir: &Path, env: store::Environment) -> Result<()> {
    let bytes = fs::read(path).context("Не удалось прочитать файл импорта")?;
    let imported: model::Catalog = serde_json::from_slice(&bytes).map_err(|error| {
        anyhow!(
            "Некорректный JSON или формат файла импорта: строка {}, столбец {}",
            error.line(),
            error.column()
        )
    })?;
    drop(bytes);
    imported
        .validate()
        .context("Файл импорта не прошёл проверку")?;
    ensure!(!imported.hosts.is_empty(), "В файле импорта нет VPS");
    let mut store = store::PassStore::open(pass_dir, env)?;
    let mut catalog = store.load()?;
    let ids: HashSet<_> = catalog.hosts.iter().map(|host| host.id).collect();
    ensure!(
        !imported.hosts.iter().any(|host| ids.contains(&host.id)),
        "VPS с таким UUID уже есть в каталоге; импорт только добавляет записи, не заменяет их"
    );
    let count = imported.hosts.len();
    catalog.hosts.extend(imported.hosts);
    let outcome = store.save(&catalog)?;
    println!("Импортировано VPS: {count}. Исходный открытый файл не удалён.");
    if outcome == store::SaveOutcome::SavedWithPassWarning {
        eprintln!(
            "Данные сохранены, но pass/Git сообщил об ошибке; проверьте Git. Не повторяйте импорт."
        );
    }
    Ok(())
}

fn run(arguments: Arguments) -> Result<ExitCode> {
    if matches!(arguments.action, Action::Help) {
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    if let Action::Template(path) = &arguments.action {
        write_template(path)?;
        return Ok(ExitCode::SUCCESS);
    }
    let mut env = std::env::vars_os().collect::<store::Environment>();
    store::prepare_environment(&mut env);
    let pass_dir = store::resolve_pass_dir(arguments.pass_dir.as_deref(), &env)?;
    match arguments.action {
        Action::Tui => {
            store::check_dependencies(&env)?;
            let store = store::PassStore::open(&pass_dir, env)?;
            let mut app = App::new(store)?;
            terminal::run(&mut app)?;
            Ok(ExitCode::SUCCESS)
        }
        Action::Connect(name) => {
            let catalog = store::load_catalog(&pass_dir, &env)?;
            let host = model::find_connect_host(&catalog, &name)?;
            let config = host.ssh.as_ref().context("SSH-доступ не настроен")?;
            let mut command = ssh::ssh_command(config, host.id, &pass_dir, &env)?;
            drop(catalog);
            drop(env);
            drop(pass_dir);
            drop(name);
            use std::os::unix::process::CommandExt;
            let error = command.exec();
            eprintln!("host-manager: Не удалось запустить SSH: {error}");
            Ok(ExitCode::from(127))
        }
        Action::Import(path) => {
            import_file(&path, &pass_dir, env)?;
            Ok(ExitCode::SUCCESS)
        }
        Action::Help | Action::Template(_) => unreachable!(),
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if let Some(result) = ssh::internal_command(&args) {
        return match result {
            Ok(code) => code,
            Err(error) => {
                eprintln!("host-manager: {error:#}");
                ExitCode::FAILURE
            }
        };
    }
    let arguments = match parse_arguments(args) {
        Ok(arguments) => arguments,
        Err(error) => {
            eprintln!("host-manager: {error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(arguments) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("host-manager: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn parse(args: &[&str]) -> Result<Arguments> {
        parse_arguments(args.iter().map(|arg| OsString::from(*arg)))
    }

    #[test]
    fn accepts_global_paths_and_literal_names() {
        for args in [
            vec!["--pass-dir", "/tmp/pass", "connect", "prod eu"],
            vec!["connect", "prod eu", "--pass-dir", "/tmp/pass"],
        ] {
            let parsed = parse(&args).unwrap();
            assert_eq!(parsed.pass_dir, Some(PathBuf::from("/tmp/pass")));
            assert!(matches!(parsed.action, Action::Connect(name) if name == "prod eu"));
        }
        assert!(
            matches!(parse(&["connect", "--", "--help"]).unwrap().action, Action::Connect(name) if name == "--help")
        );
        assert!(matches!(parse(&["--"]).unwrap().action, Action::Tui));
    }

    #[test]
    fn rejects_invalid_arguments_without_leaking_them() {
        for args in [
            vec!["connect"],
            vec!["connect", ""],
            vec!["connect", "secret\nname"],
            vec!["connect", "name", "extra"],
            vec!["connect", "name", "--help"],
            vec!["--unknown"],
            vec!["unknown"],
            vec!["--pass-dir"],
            vec!["--pass-dir", ""],
            vec!["--pass-dir", "--help"],
            vec!["--pass-dir", "/one", "--pass-dir", "/two"],
        ] {
            assert!(parse(&args).is_err());
        }
        let error = parse_arguments([OsString::from("connect"), OsString::from_vec(vec![0xff])]);
        assert!(error.is_err());
        assert!(
            !parse(&["connect", "secret\nname"])
                .err()
                .unwrap()
                .to_string()
                .contains("secret")
        );
    }

    #[test]
    fn preserves_non_utf8_paths() {
        let path = OsString::from_vec(b"/tmp/\xff".to_vec());
        let parsed = parse_arguments([OsString::from("--pass-dir"), path.clone()]).unwrap();
        assert_eq!(parsed.pass_dir, Some(PathBuf::from(path.clone())));
        for command in ["template", "import"] {
            let parsed = parse_arguments([OsString::from(command), path.clone()]).unwrap();
            assert!(
                matches!(parsed.action, Action::Template(value) | Action::Import(value) if value == PathBuf::from(path.clone()))
            );
        }
        for args in [
            vec!["--help"],
            vec!["-h"],
            vec!["connect", "--help"],
            vec!["template", "--help"],
            vec!["import", "--help"],
        ] {
            assert!(matches!(parse(&args).unwrap().action, Action::Help));
        }
    }
}
