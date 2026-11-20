use std::{
    collections::{BTreeMap, HashMap, HashSet},
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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{Builder, TempDir};
use uuid::Uuid;

use crate::model::Catalog;

#[path = "store_format.rs"]
mod format;

const LEGACY: &str = "catalog.gpg";
const PENDING: &str = "catalog.pending.gpg";
const INDEX: &str = "index.gpg";
const HOSTS: &str = "hosts";

type Hash = [u8; 32];

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    hosts: Vec<Entry>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: Uuid,
    name: String,
}

impl Entry {
    fn file(&self) -> PathBuf {
        Path::new(HOSTS).join(format!("{}.gpg", self.name))
    }
}

#[derive(Default)]
struct Snapshot {
    index: Option<Index>,
    files: BTreeMap<PathBuf, Option<Hash>>,
    hosts: HashMap<Uuid, Hash>,
}

impl Snapshot {
    fn check(&self, paths: &Paths) -> Result<()> {
        for (file, before) in &self.files {
            ensure!(
                paths.hash(file)? == *before,
                "Хранилище изменено извне; повторите загрузку перед сохранением"
            );
        }
        Ok(())
    }
}

pub type Environment = BTreeMap<OsString, OsString>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveOutcome {
    Saved,
    SavedWithPassWarning,
}

struct Paths {
    root: PathBuf,
    dir: PathBuf,
    repo_dir: PathBuf,
}

pub struct PassStore {
    paths: Paths,
    env: Environment,
    _lock: File,
    snapshot: Option<Snapshot>,
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
    command
        .args(["--literal-pathspecs", "--no-optional-locks", "-C"])
        .arg(dir);
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
        recipients(&root, &dir, env)?;
        let paths = Self {
            root,
            dir,
            repo_dir: existing,
        };
        for file in [INDEX, LEGACY, PENDING] {
            file_state(&paths.dir.join(file))?;
        }
        Ok(paths)
    }

    fn check_parent(&self, file: &Path) -> Result<PathBuf> {
        let parent = self.dir.join(file.parent().expect("relative entry path"));
        check_directory_chain(&self.root, &parent)?;
        Ok(parent)
    }

    fn hash(&self, file: &Path) -> Result<Option<Hash>> {
        self.check_parent(file)?;
        ciphertext_hash(&self.dir.join(file))
    }

    fn require_new_file(&self, file: &Path, env: &Environment) -> Result<()> {
        let status = git(env, &self.repo_dir)
            .args(["status", "--porcelain=v1", "--untracked-files=no", "--"])
            .arg(self.dir.join(file))
            .output()
            .map_err(|_| anyhow!("Не удалось проверить состояние каталога в Git"))?;
        ensure!(
            status.status.success() && status.stdout.is_empty(),
            "Файл хранилища отсутствует в рабочей копии; восстановите его из Git"
        );
        Ok(())
    }
}

fn recipients(root: &Path, mut dir: &Path, env: &Environment) -> Result<Option<PathBuf>> {
    if env
        .get(OsStr::new("PASSWORD_STORE_KEY"))
        .is_some_and(|v| !v.is_empty())
    {
        return Ok(None);
    }
    loop {
        let file = dir.join(".gpg-id");
        match fs::symlink_metadata(&file) {
            Ok(meta) => {
                ensure!(meta.is_file(), "Некорректный файл recipients pass");
                let bytes =
                    fs::read(&file).map_err(|_| anyhow!("Не удалось прочитать recipients pass"))?;
                ensure!(
                    bytes.iter().any(|byte| !byte.is_ascii_whitespace()),
                    "Файл recipients pass пуст"
                );
                return Ok(Some(file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => bail!("Не удалось проверить recipients pass"),
        }
        ensure!(
            dir != root,
            "Не настроены recipients pass: требуется .gpg-id или PASSWORD_STORE_KEY"
        );
        dir = dir
            .parent()
            .ok_or_else(|| anyhow!("Не настроены recipients pass"))?;
    }
}

fn digest(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
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

fn pass_show(env: &Environment, root: &Path, entry: &Path) -> Result<Vec<u8>> {
    let output = command("pass", env)
        .env("PASSWORD_STORE_DIR", root)
        .args(["show", "--"])
        .arg(entry)
        .output()
        .map_err(|_| anyhow!("Не удалось запустить pass для чтения"))?;
    ensure!(
        output.status.success(),
        "Не удалось расшифровать запись через pass"
    );
    Ok(output.stdout)
}

fn read_entry(paths: &Paths, env: &Environment, file: &Path) -> Result<Vec<u8>> {
    let entry = paths
        .dir
        .strip_prefix(&paths.root)
        .expect("known pass namespace")
        .join(file.with_extension(""));
    pass_show(env, &paths.root, &entry)
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name.chars().all(|c| c.is_alphanumeric() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

fn read_catalog(paths: &Paths, env: &Environment) -> Result<(Catalog, Snapshot)> {
    let mut snapshot = Snapshot::default();
    let index_path = Path::new(INDEX);
    let index_hash = paths.hash(index_path)?;
    snapshot.files.insert(index_path.into(), index_hash);
    let catalog = if index_hash.is_some() {
        let index: Index = serde_json::from_slice(&read_entry(paths, env, index_path)?)
            .map_err(|_| anyhow!("Некорректный индекс хранилища"))?;
        ensure!(index.version == 2, "Неизвестная версия индекса хранилища");
        let mut catalog = Catalog::default();
        let mut names = HashSet::with_capacity(index.hosts.len());
        for entry in &index.hosts {
            ensure!(
                safe_name(&entry.name) && names.insert(&entry.name),
                "Некорректный или повторяющийся путь в индексе хранилища"
            );
            let file = entry.file();
            let hash = paths.hash(&file)?;
            ensure!(
                hash.is_some(),
                "Запись VPS из индекса отсутствует; запись запрещена"
            );
            let host = format::decode(entry.id, &read_entry(paths, env, &file)?)?;
            snapshot
                .hosts
                .insert(entry.id, digest(&format::encode(&host)?));
            snapshot.files.insert(file, hash);
            catalog.hosts.push(host);
        }
        snapshot.index = Some(index);
        catalog
    } else {
        // A missing tracked index is damage, not a request to fall back to the old backup.
        paths.require_new_file(index_path, env)?;
        let legacy = Path::new(LEGACY);
        let before = paths.hash(legacy)?;
        snapshot.files.insert(legacy.into(), before);
        let pending = Path::new(PENDING);
        let pending_hash = paths.hash(pending)?;
        snapshot.files.insert(pending.into(), pending_hash);
        if before.is_some() {
            serde_json::from_slice(&read_entry(paths, env, legacy)?)
                .map_err(|_| anyhow!("Некорректный JSON или формат каталога; запись запрещена"))?
        } else {
            paths.require_new_file(legacy, env)?;
            ensure!(
                pending_hash.is_none(),
                "Основной каталог отсутствует, но есть catalog.pending.gpg; требуется ручное восстановление через pass"
            );
            Catalog::default()
        }
    };
    catalog
        .validate()
        .map_err(|_| anyhow!("Каталог не прошёл проверку; запись запрещена"))?;
    snapshot.check(paths)?;
    Ok((catalog, snapshot))
}

fn encrypt_entry(
    env: &Environment,
    tmp: &TempDir,
    recipients: Option<&Path>,
    name: &str,
    bytes: &[u8],
) -> Result<PathBuf> {
    for file in [".gpg-id", ".gpg-id.sig"] {
        let dest = tmp.path().join(file);
        if let Some(id) = recipients {
            let source = id.with_file_name(file);
            if file_state(&source)? {
                fs::copy(source, dest)
                    .map_err(|_| anyhow!("Не удалось подготовить recipients pass"))?;
                continue;
            }
        }
        if dest.exists() {
            fs::remove_file(dest).map_err(|_| anyhow!("Не удалось сменить recipients pass"))?;
        }
    }
    let mut child = command("pass", env)
        .env("PASSWORD_STORE_DIR", tmp.path())
        .args(["insert", "--multiline", "--force", "--", name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| anyhow!("Не удалось запустить pass для сохранения"))?;
    let mut stdin = child.stdin.take().expect("piped pass stdin");
    let output: Output = std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(bytes));
        let output = child.wait_with_output();
        writer
            .join()
            .map_err(|_| anyhow!("Не удалось передать запись в pass"))?
            .map_err(|_| anyhow!("Не удалось записать данные в pass"))?;
        output.map_err(|_| anyhow!("Не удалось дождаться pass"))
    })?;
    ensure!(
        output.status.success(),
        "pass не подтвердил шифрование записи"
    );
    let file = tmp.path().join(format!("{name}.gpg"));
    ensure!(
        file_state(&file)? && pass_show(env, tmp.path(), Path::new(name))? == bytes,
        "Сохранённая запись не прошла проверку расшифровки"
    );
    File::open(&file)
        .and_then(|file| file.sync_all())
        .map_err(|_| anyhow!("Не удалось сбросить зашифрованную запись на диск"))?;
    Ok(file)
}

fn entry_name(name: &str, id: Uuid, taken: &HashSet<String>) -> String {
    let mut base = String::new();
    for c in name.chars().flat_map(char::to_lowercase) {
        let c = if c.is_alphanumeric() { c } else { '-' };
        if base.len() + c.len_utf8() > 64 {
            break;
        }
        if c != '-' || (!base.is_empty() && !base.ends_with('-')) {
            base.push(c);
        }
    }
    let base = base.trim_end_matches('-');
    if base.is_empty() {
        id.to_string()
    } else if taken.contains(base) {
        format!("{base}-{}", id.simple())
    } else {
        base.to_owned()
    }
}

fn commit_entries(paths: &Paths, env: &Environment, files: &[PathBuf]) -> bool {
    let relative = |file: &PathBuf| paths.dir.join(file);
    let status = || {
        git(env, &paths.repo_dir)
            .args([
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignored=matching",
                "--no-renames",
                "-z",
                "--",
            ])
            .args(files.iter().map(relative))
            .output()
            .ok()
            .filter(|output| output.status.success())
    };
    if files.is_empty() || status().is_some_and(|output| output.stdout.is_empty()) {
        return true;
    }
    // -N makes new paths eligible for --only without staging their contents.
    let added = git(env, &paths.repo_dir)
        .args(["add", "--intent-to-add", "--"])
        .args(files.iter().map(relative))
        .output();
    if !added.is_ok_and(|output| output.status.success()) {
        return false;
    }
    let mut commit = git(env, &paths.repo_dir);
    commit.args(["commit", "--only", "-m", "Update host-manager entries"]);
    if git(env, &paths.repo_dir)
        .args(["config", "--bool", "--get", "pass.signcommits"])
        .output()
        .is_ok_and(|output| output.status.success() && output.stdout == b"true\n")
    {
        commit.arg("-S");
    }
    commit
        .arg("--")
        .args(files.iter().map(relative))
        .output()
        .is_ok_and(|output| output.status.success())
        && status().is_some_and(|output| output.stdout.is_empty())
}

fn publish(
    paths: &Paths,
    env: &Environment,
    before: &Snapshot,
    catalog: &Catalog,
) -> Result<Snapshot> {
    let by_id: HashMap<_, _> = before
        .index
        .iter()
        .flat_map(|index| &index.hosts)
        .map(|entry| (entry.id, entry))
        .collect();
    let mut taken: HashSet<_> = by_id.values().map(|entry| entry.name.clone()).collect();
    let mut index = Index {
        version: 2,
        hosts: Vec::with_capacity(catalog.hosts.len()),
    };
    let mut after = Snapshot::default();
    let mut writes = Vec::new();
    for host in &catalog.hosts {
        let entry = match by_id.get(&host.id) {
            Some(entry) => (*entry).clone(),
            None => {
                let name = entry_name(&host.name, host.id, &taken);
                ensure!(taken.insert(name.clone()), "Повторяющийся путь записи VPS");
                Entry { id: host.id, name }
            }
        };
        let bytes = format::encode(host)?;
        let hash = digest(&bytes);
        let file = entry.file();
        if before.hosts.get(&entry.id) == Some(&hash) {
            after.files.insert(file.clone(), before.files[&file]);
        } else {
            let prior = paths.hash(&file)?;
            if let Some(expected) = before.files.get(&file) {
                ensure!(prior == *expected, "Запись VPS изменена извне");
                writes.push((file, prior, bytes));
            } else if let Some(prior) = prior {
                // Reuse only an identical entry left before the index was published.
                ensure!(
                    format::decode(entry.id, &read_entry(paths, env, &file)?)? == *host,
                    "Путь записи VPS уже занят; существующая запись не изменена"
                );
                after.files.insert(file, Some(prior));
            } else {
                paths.require_new_file(&file, env)?;
                writes.push((file, None, bytes));
            }
        }
        after.hosts.insert(entry.id, hash);
        index.hosts.push(entry);
    }
    ensure!(
        by_id.keys().all(|id| after.hosts.contains_key(id)),
        "Удаление записей не поддерживается; архивируйте VPS"
    );
    let index_path = PathBuf::from(INDEX);
    if before.index.as_ref() != Some(&index) {
        let bytes =
            serde_json::to_vec(&index).map_err(|_| anyhow!("Не удалось сериализовать индекс"))?;
        writes.push((index_path, before.files[Path::new(INDEX)], bytes));
    } else {
        after
            .files
            .insert(index_path, before.files[Path::new(INDEX)]);
    }
    after.index = Some(index);
    if writes.is_empty() {
        return Ok(after);
    }
    fs::create_dir_all(&paths.dir).map_err(|_| anyhow!("Не удалось создать папку хранилища"))?;
    let tmp = Builder::new()
        .prefix(".host-manager-")
        .tempdir_in(&paths.dir)
        .map_err(|_| anyhow!("Не удалось создать временную папку хранилища"))?;
    // pass won't discover the parent repository when this directory is its store root.
    let mut prepared = Vec::with_capacity(writes.len());
    for (number, (file, prior, bytes)) in writes.into_iter().enumerate() {
        let parent = paths.check_parent(&file)?;
        let recipients = recipients(&paths.root, &parent, env)?;
        let source = encrypt_entry(
            env,
            &tmp,
            recipients.as_deref(),
            &number.to_string(),
            &bytes,
        )?;
        let hash = ciphertext_hash(&source)?.ok_or_else(|| anyhow!("Временная запись пропала"))?;
        prepared.push((file, prior, parent, source, hash));
    }
    before.check(paths)?;
    after.check(paths)?;
    if prepared
        .last()
        .is_some_and(|(file, ..)| file == Path::new(INDEX))
    {
        sync_directory(paths.dir.parent().expect("pass namespace inside root"))?;
    }
    for (file, prior, parent, source, hash) in prepared {
        ensure!(
            paths.hash(&file)? == prior,
            "Запись изменена извне; сохранение остановлено"
        );
        fs::create_dir_all(&parent).map_err(|_| anyhow!("Не удалось создать папку записей VPS"))?;
        if file == Path::new(INDEX) {
            // Persist the hosts directory entry before publishing its index.
            sync_directory(&parent)?;
        }
        let dest = paths.dir.join(&file);
        if prior.is_some() {
            fs::rename(&source, dest)
        } else {
            fs::hard_link(&source, dest)
        }
        .map_err(|_| anyhow!("Не удалось опубликовать запись; перечитайте хранилище"))?;
        sync_directory(&parent)?;
        after.files.insert(file, Some(hash));
    }
    after.check(paths)?;
    Ok(after)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| anyhow!("Не удалось сбросить изменения папки на диск; перечитайте хранилище"))
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
            snapshot: None,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.paths.dir
    }

    pub fn environment(&self) -> &Environment {
        &self.env
    }

    pub fn load(&mut self) -> Result<Catalog> {
        self.snapshot = None;
        let (catalog, snapshot) = read_catalog(&self.paths, &self.env)?;
        self.snapshot = Some(snapshot);
        Ok(catalog)
    }

    pub fn save(&mut self, catalog: &Catalog) -> Result<SaveOutcome> {
        let before = self.snapshot.as_ref().ok_or_else(|| {
            anyhow!("Запись заблокирована до успешной повторной загрузки каталога")
        })?;
        catalog
            .validate()
            .map_err(|_| anyhow!("Каталог не прошёл проверку; сохранение отменено"))?;
        before.check(&self.paths)?;
        ensure!(
            before
                .files
                .get(Path::new(PENDING))
                .is_none_or(Option::is_none),
            "Найдена запись восстановления catalog.pending.gpg; разберите её вручную через pass"
        );
        let staged = git(&self.env, &self.paths.repo_dir)
            .args(["diff", "--cached", "--quiet", "--exit-code"])
            .output()
            .map_err(|_| anyhow!("Не удалось проверить индекс Git"))?;
        ensure!(
            staged.status.code() == Some(0),
            "Индекс Git содержит изменения или недоступен; сохранение отменено"
        );
        // Once publication starts, a failure may have changed the working copy.
        let before = self.snapshot.take().expect("loaded snapshot");
        let after = publish(&self.paths, &self.env, &before, catalog)?;
        let files: Vec<_> = after.files.keys().cloned().collect();
        let committed = commit_entries(&self.paths, &self.env, &files);
        self.snapshot = Some(after);
        Ok(if committed {
            SaveOutcome::Saved
        } else {
            SaveOutcome::SavedWithPassWarning
        })
    }
}
