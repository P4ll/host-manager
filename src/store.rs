use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
};

use anyhow::{Result, anyhow, bail, ensure};
use sha2::{Digest, Sha256};

use crate::model::Catalog;

pub type Environment = BTreeMap<OsString, OsString>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveOutcome {
    Saved,
    SavedWithPassWarning,
}

struct Paths {
    root: PathBuf,
    dir: PathBuf,
    namespace: PathBuf,
}

pub struct PassStore {
    paths: Paths,
    env: Environment,
    _lock: File,
    baseline: Option<[u8; 32]>,
    writable: bool,
}

fn home(env: &Environment) -> Result<PathBuf> {
    env.get(OsStr::new("HOME"))
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("Не задан HOME для разрешения пути"))
}

fn absolute(path: &Path, env: &Environment) -> Result<PathBuf> {
    ensure!(
        !path.as_os_str().is_empty(),
        "Путь папки pass не может быть пустым"
    );
    ensure!(
        !path.components().any(|part| part == Component::ParentDir),
        "Компоненты .. в пути запрещены"
    );
    let mut parts = path.components();
    let expanded = if parts.next() == Some(Component::Normal(OsStr::new("~"))) {
        home(env)?.join(parts.as_path())
    } else {
        path.to_path_buf()
    };
    let expanded = if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir()
            .map_err(|_| anyhow!("Не удалось определить текущую папку"))?
            .join(expanded)
    };
    Ok(expanded.components().collect())
}

fn pass_root(env: &Environment) -> Result<PathBuf> {
    match env.get(OsStr::new("PASSWORD_STORE_DIR")) {
        Some(value) => absolute(Path::new(value), env),
        None => absolute(&home(env)?.join(".password-store"), env),
    }
}

pub fn resolve_pass_dir(explicit: Option<&Path>, env: &Environment) -> Result<PathBuf> {
    match explicit {
        Some(path) => absolute(path, env),
        None => match env.get(OsStr::new("HOST_MANAGER_PASS_DIR")) {
            Some(path) => absolute(Path::new(path), env),
            None => Ok(pass_root(env)?.join("host-manager")),
        },
    }
}

pub fn check_dependencies(env: &Environment) -> Result<()> {
    for (program, argument) in [
        ("pass", "--version"),
        ("gpg", "--version"),
        ("git", "--version"),
        ("ssh", "-V"),
    ] {
        let status = command(program, env)
            .arg(argument)
            .stdin(Stdio::null())
            .output()
            .map_err(|_| anyhow!("Не удалось запустить обязательную программу {program}"))?;
        ensure!(
            status.status.success(),
            "Обязательная программа {program} недоступна"
        );
    }
    Ok(())
}

pub fn prepare_environment(env: &mut Environment) {
    if let Ok(output) = command("tty", env).stdin(Stdio::inherit()).output() {
        if output.status.success() {
            let mut bytes = output.stdout;
            while matches!(bytes.last(), Some(b'\n' | b'\r')) {
                bytes.pop();
            }
            if !bytes.is_empty() {
                env.insert("GPG_TTY".into(), OsString::from_vec(bytes));
            }
        }
    }
}

fn command(program: &str, env: &Environment) -> Command {
    let mut command = Command::new(program);
    command.env_clear().envs(env);
    command
}

fn git(env: &Environment, dir: &Path) -> Command {
    let mut command = command("git", env);
    // Match pass's Git environment instead of inspecting a caller's unrelated index.
    for key in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_NAMESPACE",
        "GIT_INDEX_FILE",
        "GIT_INDEX_VERSION",
        "GIT_OBJECT_DIRECTORY",
        "GIT_COMMON_DIR",
    ] {
        command.env_remove(key);
    }
    command.arg("-C").arg(dir);
    command
}

fn file_state(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                !meta.file_type().is_symlink(),
                "Симлинк на файле каталога запрещён"
            );
            ensure!(meta.is_file(), "Запись каталога должна быть обычным файлом");
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => bail!("Не удалось проверить файл каталога"),
    }
}

fn check_directory_chain(root: &Path, dir: &Path) -> Result<PathBuf> {
    let relative = dir
        .strip_prefix(root)
        .map_err(|_| anyhow!("Папка должна находиться внутри корня pass"))?;
    ensure!(
        !relative.as_os_str().is_empty(),
        "Папка должна находиться строго внутри корня pass"
    );
    let mut current = root.to_path_buf();
    let mut existing = root.to_path_buf();
    let mut missing = false;
    for part in relative.components() {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                ensure!(
                    !meta.file_type().is_symlink(),
                    "Симлинки внутри пути pass запрещены"
                );
                ensure!(meta.is_dir(), "Компонент пути pass не является папкой");
                ensure!(!missing, "Путь папки pass изменился; повторите загрузку");
                existing = current.clone();
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing = true,
            Err(_) => bail!("Не удалось проверить папку pass"),
        }
    }
    Ok(existing)
}

impl Paths {
    fn open(pass_dir: &Path, env: &mut Environment) -> Result<Self> {
        let specified_root = pass_root(env)?;
        let root = fs::canonicalize(&specified_root)
            .map_err(|_| anyhow!("Корень pass не существует или недоступен"))?;
        ensure!(root.is_dir(), "Корень pass не является папкой");
        let chosen = absolute(pass_dir, env)?;
        let dir = match chosen.strip_prefix(&specified_root) {
            Ok(relative) => root.join(relative),
            Err(_) => chosen,
        };
        let existing = check_directory_chain(&root, &dir)?;
        let namespace = dir
            .strip_prefix(&root)
            .map_err(|_| anyhow!("Папка вне корня pass"))?
            .to_path_buf();
        env.insert("PASSWORD_STORE_DIR".into(), root.as_os_str().to_owned());
        env.insert(
            "GIT_CEILING_DIRECTORIES".into(),
            root.join("..").into_os_string(),
        );
        let repo = git(env, &existing)
            .args(["rev-parse", "--is-inside-work-tree"])
            .output()
            .map_err(|_| anyhow!("Не удалось запустить Git"))?;
        ensure!(
            repo.status.success() && repo.stdout == b"true\n",
            "Для папки pass требуется существующий Git-репозиторий"
        );
        if !env
            .get(OsStr::new("PASSWORD_STORE_KEY"))
            .is_some_and(|value| !value.is_empty())
        {
            let mut current = dir.as_path();
            loop {
                let recipients = current.join(".gpg-id");
                match fs::symlink_metadata(&recipients) {
                    Ok(meta) => {
                        ensure!(
                            meta.is_file() && !meta.file_type().is_symlink(),
                            "Некорректный файл recipients pass"
                        );
                        let bytes = fs::read(&recipients)
                            .map_err(|_| anyhow!("Не удалось прочитать recipients pass"))?;
                        ensure!(
                            bytes.iter().any(|byte| !byte.is_ascii_whitespace()),
                            "Файл recipients pass пуст"
                        );
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => bail!("Не удалось проверить recipients pass"),
                }
                ensure!(
                    current != root,
                    "Не настроены recipients pass: требуется .gpg-id или PASSWORD_STORE_KEY"
                );
                current = current
                    .parent()
                    .ok_or_else(|| anyhow!("Не настроены recipients pass"))?;
            }
        }
        let paths = Self {
            root,
            dir,
            namespace,
        };
        paths.check_files()?;
        Ok(paths)
    }

    fn check_files(&self) -> Result<()> {
        check_directory_chain(&self.root, &self.dir)?;
        file_state(&self.catalog())?;
        file_state(&self.pending())?;
        Ok(())
    }

    fn catalog(&self) -> PathBuf {
        self.dir.join("catalog.gpg")
    }
    fn pending(&self) -> PathBuf {
        self.dir.join("catalog.pending.gpg")
    }
    fn entry(&self, pending: bool) -> PathBuf {
        self.namespace.join(if pending {
            "catalog.pending"
        } else {
            "catalog"
        })
    }
}

fn ciphertext_hash(path: &Path) -> Result<Option<[u8; 32]>> {
    if !file_state(path)? {
        return Ok(None);
    }
    let mut file =
        File::open(path).map_err(|_| anyhow!("Не удалось открыть зашифрованный каталог"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 16384];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| anyhow!("Не удалось прочитать зашифрованный каталог"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(Some(hasher.finalize().into()))
}

fn read_output(paths: &Paths, env: &Environment, pending: bool) -> Result<Vec<u8>> {
    paths.check_files()?;
    let output = command("pass", env)
        .args(["show", "--"])
        .arg(paths.entry(pending))
        .output()
        .map_err(|_| anyhow!("Не удалось запустить pass для чтения"))?;
    ensure!(
        output.status.success(),
        "Не удалось расшифровать каталог через pass"
    );
    Ok(output.stdout)
}

fn read_entry(paths: &Paths, env: &Environment, pending: bool) -> Result<Catalog> {
    let bytes = read_output(paths, env, pending)?;
    let catalog: Catalog = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("Некорректный JSON или формат каталога; запись запрещена"))?;
    catalog
        .validate()
        .map_err(|_| anyhow!("Каталог не прошёл проверку; запись запрещена"))?;
    Ok(catalog)
}

fn read_catalog(paths: &Paths, env: &Environment) -> Result<(Catalog, Option<[u8; 32]>)> {
    paths.check_files()?;
    let before = ciphertext_hash(&paths.catalog())?;
    let catalog = if before.is_some() {
        read_entry(paths, env, false)?
    } else {
        ensure!(
            !file_state(&paths.pending())?,
            "Основной каталог отсутствует, но есть catalog.pending.gpg; требуется ручное восстановление через pass"
        );
        Catalog::default()
    };
    ensure!(
        before == ciphertext_hash(&paths.catalog())?,
        "Каталог изменён извне; повторите загрузку"
    );
    Ok((catalog, before))
}

pub fn load_catalog(pass_dir: &Path, env: &Environment) -> Result<Catalog> {
    let mut env = env.clone();
    let paths = Paths::open(pass_dir, &mut env)?;
    Ok(read_catalog(&paths, &env)?.0)
}

impl PassStore {
    pub fn open(pass_dir: &Path, mut env: Environment) -> Result<Self> {
        let paths = Paths::open(pass_dir, &mut env)?;
        let cache = match env.get(OsStr::new("XDG_CACHE_HOME")) {
            Some(value) if !value.is_empty() => absolute(Path::new(value), &env)?,
            _ => home(&env)?.join(".cache"),
        }
        .join("host-manager");
        fs::create_dir_all(&cache).map_err(|_| anyhow!("Не удалось создать папку блокировок"))?;
        let name = format!(
            "{:x}.lock",
            Sha256::digest(paths.dir.as_os_str().as_bytes())
        );
        let lock_path = cache.join(name);
        if let Ok(meta) = fs::symlink_metadata(&lock_path) {
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink(),
                "Некорректный файл блокировки"
            );
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(lock_path)
            .map_err(|_| anyhow!("Не удалось открыть файл блокировки"))?;
        lock.try_lock().map_err(|_| {
            anyhow!("Каталог уже открыт другим редактирующим экземпляром или блокировка недоступна")
        })?;
        Ok(Self {
            paths,
            env,
            _lock: lock,
            baseline: None,
            writable: false,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.paths.dir
    }

    pub fn environment(&self) -> &Environment {
        &self.env
    }

    pub fn load(&mut self) -> Result<Catalog> {
        self.writable = false;
        let (catalog, baseline) = read_catalog(&self.paths, &self.env)?;
        self.baseline = baseline;
        self.writable = true;
        Ok(catalog)
    }

    fn check_baseline(&self) -> Result<()> {
        self.paths.check_files()?;
        ensure!(
            ciphertext_hash(&self.paths.catalog())? == self.baseline,
            "Каталог изменён извне; повторите загрузку перед сохранением"
        );
        Ok(())
    }

    fn staged(&self) -> Result<bool> {
        let output = git(&self.env, &self.paths.dir)
            .args(["diff", "--cached", "--quiet", "--exit-code"])
            .output()
            .map_err(|_| anyhow!("Не удалось проверить индекс Git"))?;
        match output.status.code() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => bail!("Не удалось проверить индекс Git"),
        }
    }

    pub fn save(&mut self, catalog: &Catalog) -> Result<SaveOutcome> {
        ensure!(
            self.writable,
            "Запись заблокирована до успешной повторной загрузки каталога"
        );
        catalog
            .validate()
            .map_err(|_| anyhow!("Каталог не прошёл проверку; сохранение отменено"))?;
        self.check_baseline()?;
        ensure!(
            !file_state(&self.paths.pending())?,
            "Найдена запись восстановления {}; разберите её вручную через pass",
            self.paths.pending().display()
        );
        let existing = check_directory_chain(&self.paths.root, &self.paths.dir)?;
        let staged = git(&self.env, &existing)
            .args(["diff", "--cached", "--quiet", "--exit-code"])
            .output()
            .map_err(|_| anyhow!("Не удалось проверить индекс Git"))?;
        ensure!(
            staged.status.code() == Some(0),
            "Индекс Git содержит изменения или недоступен; сохранение отменено"
        );
        let bytes =
            serde_json::to_vec(catalog).map_err(|_| anyhow!("Не удалось сериализовать каталог"))?;
        let mut child = command("pass", &self.env)
            .args(["insert", "--multiline", "--force", "--"])
            .arg(self.paths.entry(true))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| anyhow!("Не удалось запустить pass для сохранения"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("Не удалось открыть ввод pass"))?;
        let output: Output = std::thread::scope(|scope| {
            let bytes = &bytes;
            let writer = scope.spawn(move || {
                let result = stdin.write_all(bytes);
                drop(stdin);
                result
            });
            let output = child.wait_with_output();
            // stdin must close in the writer before wait_with_output can observe EOF.
            let written = writer
                .join()
                .map_err(|_| anyhow!("Не удалось передать каталог в pass"))?;
            written.map_err(|_| {
                anyhow!("Не удалось передать каталог в pass; проверьте catalog.pending.gpg")
            })?;
            output.map_err(|_| anyhow!("Не удалось дождаться pass; проверьте catalog.pending.gpg"))
        })?;
        ensure!(
            output.status.success(),
            "pass не подтвердил запись; проверьте catalog.pending.gpg, основной каталог не заменён"
        );
        ensure!(
            read_output(&self.paths, &self.env, true)? == bytes,
            "Проверка catalog.pending.gpg не пройдена; основной каталог не заменён"
        );
        self.finalize(&bytes)
    }

    fn finalize(&mut self, bytes: &[u8]) -> Result<SaveOutcome> {
        ensure!(
            !self.staged()?,
            "Индекс Git содержит изменения; catalog.pending.gpg сохранён для восстановления"
        );
        self.check_baseline()?;
        self.writable = false;
        let moved = command("pass", &self.env)
            .args(["mv", "--force", "--"])
            .arg(self.paths.entry(true))
            .arg(self.paths.entry(false))
            .output();
        let baseline = (|| -> Result<[u8; 32]> {
            let before = ciphertext_hash(&self.paths.catalog())?
                .ok_or_else(|| anyhow!("Основной каталог отсутствует"))?;
            ensure!(
                read_output(&self.paths, &self.env, false)?.as_slice() == bytes,
                "Содержимое не совпало"
            );
            ensure!(
                ciphertext_hash(&self.paths.catalog())? == Some(before),
                "Каталог изменился во время проверки"
            );
            Ok(before)
        })()
        .map_err(|_| {
            anyhow!("Результат сохранения неопределён; повторная запись заблокирована до загрузки")
        })?;
        self.baseline = Some(baseline);
        self.writable = true;
        // pass can mask a failed Git hook with its final exit 0; a leftover index is also a warning.
        let warning =
            !moved.is_ok_and(|output| output.status.success()) || self.staged().unwrap_or(true);
        Ok(if warning {
            SaveOutcome::SavedWithPassWarning
        } else {
            SaveOutcome::Saved
        })
    }
}

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod test_common;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Payment;
    use chrono::{Days, Local};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn verified_move_with_rejecting_git_hook_is_saved_once_with_warning() {
        let fixture = test_common::Fixture::new();
        let mut store = PassStore::open(&fixture.dir, fixture.env.clone()).unwrap();
        let mut catalog = store.load().unwrap();
        catalog.hosts.push(test_common::sample_host());
        assert_eq!(store.save(&catalog).unwrap(), SaveOutcome::Saved);
        let today = Local::now().date_naive();
        let next_due = today.checked_add_days(Days::new(60)).unwrap();
        catalog.hosts[0].payments.push(Payment {
            paid_on: today,
            amount: rust_decimal::Decimal::new(450, 2),
            currency: "EUR".into(),
            next_due,
        });
        catalog.hosts[0].billing.next_due = Some(next_due);
        let bytes = serde_json::to_vec(&catalog).unwrap();
        let mut child = fixture
            .command("pass")
            .args([
                "insert",
                "--multiline",
                "--force",
                "--",
                "host-manager/catalog.pending",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        std::thread::scope(|scope| {
            let bytes = &bytes;
            let writer = scope.spawn(move || {
                input.write_all(&bytes).unwrap();
            });
            assert!(child.wait_with_output().unwrap().status.success());
            writer.join().unwrap();
        });
        assert!(read_entry(&store.paths, &store.env, true).unwrap() == catalog);
        let hook = fixture.root.join(".git/hooks/pre-commit");
        fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
        // Real pass 1.7.4 may exit 0 despite this hook; the remaining index exposes the warning.
        assert_eq!(
            store.finalize(&bytes).unwrap(),
            SaveOutcome::SavedWithPassWarning
        );
        let loaded = store.load().unwrap();
        assert!(loaded == catalog);
        assert_eq!(loaded.hosts[0].payments.len(), 1);
        assert_eq!(
            loaded.hosts[0].payments[0].amount,
            rust_decimal::Decimal::new(450, 2)
        );
        assert!(store.staged().unwrap());
        assert!(!fixture.dir.join("catalog.pending.gpg").exists());
    }

    #[test]
    fn unconfirmed_finalization_blocks_writes_until_successful_reload() {
        let fixture = test_common::Fixture::new();
        let mut store = PassStore::open(&fixture.dir, fixture.env.clone()).unwrap();
        let mut catalog = store.load().unwrap();
        catalog.hosts.push(test_common::sample_host());
        store.save(&catalog).unwrap();
        let before = fs::read(fixture.dir.join("catalog.gpg")).unwrap();
        catalog.hosts[0].notes = "unsaved change".into();
        assert!(
            store
                .finalize(&serde_json::to_vec(&catalog).unwrap())
                .is_err()
        );
        assert!(!store.writable);
        assert!(store.save(&catalog).is_err());
        assert_eq!(fs::read(fixture.dir.join("catalog.gpg")).unwrap(), before);
        let reloaded = store.load().unwrap();
        assert!(store.writable);
        assert!(reloaded.hosts[0].notes.is_empty());
    }
}
