use std::{path::PathBuf, process::Command};

use anyhow::{Result, ensure};

use crate::model::{SshConfig, validate_line};

fn identity_path(value: &str) -> Result<PathBuf> {
    validate_line(value)?;
    let path = if value == "~" || value.starts_with("~/") {
        let home = std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .ok_or_else(|| anyhow::anyhow!("Не задана домашняя папка для SSH-ключа"))?;
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
        .map_err(|_| anyhow::anyhow!("SSH-ключ недоступен"))?;
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
        identity_path(identity)?;
    }
    Ok(())
}

pub fn ssh_command(config: &SshConfig) -> Result<Command> {
    validate_fields(config)?;
    let mut command = Command::new("ssh");
    if let Some(user) = &config.user {
        command.arg("-l").arg(user);
    }
    if let Some(port) = config.port {
        command.arg("-p").arg(port.to_string());
    }
    if let Some(identity) = &config.identity_file {
        command.arg("-i").arg(identity_path(identity)?);
    }
    command.arg("--").arg(&config.host);
    Ok(command)
}
