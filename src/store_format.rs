use std::io::Write;

use anyhow::{Result, anyhow, ensure};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::model::{Host, SshConfig};

pub(super) fn encode(host: &Host) -> Result<Vec<u8>> {
    let ssh = host.ssh.as_ref();
    let ssh_password = ssh.and_then(|ssh| ssh.password.as_deref());
    let (first, role, ssh_password, account_password) =
        match (ssh_password, host.account_password.as_deref()) {
            (Some(ssh), account) if !ssh.is_empty() => (ssh, "ssh", None, account),
            (ssh, Some(account)) => (account, "account", ssh, None),
            (ssh, None) => ("", "none", ssh, None),
        };

    let mut output = Vec::new();
    writeln!(
        output,
        "{first}\nname: {}\nprovider: {}",
        host.name, host.provider
    )?;
    if let Some(ssh) = ssh {
        writeln!(output, "host: {}", ssh.host)?;
        if let Some(user) = &ssh.user {
            writeln!(output, "username: {user}")?;
        }
        if let Some(port) = ssh.port {
            writeln!(output, "port: {port}")?;
        }
        if let Some(identity_file) = &ssh.identity_file {
            writeln!(output, "identity_file: {identity_file}")?;
        }
    }
    writeln!(output, "password_role: {role}")?;
    for (key, value) in [
        ("panel_url", host.panel_url.as_deref()),
        ("account_login", host.account_login.as_deref()),
        ("account_password", account_password),
        ("ssh_password", ssh_password),
    ] {
        if let Some(value) = value {
            writeln!(output, "{key}: {value}")?;
        }
    }
    writeln!(output, "archived: {}", host.archived)?;
    write_json(&mut output, "notes", &host.notes)?;
    write_json(&mut output, "billing", &host.billing)?;
    write_json(&mut output, "payments", &host.payments)?;
    Ok(output)
}

fn write_json(output: &mut Vec<u8>, key: &str, value: &impl Serialize) -> Result<()> {
    write!(output, "{key}: ")?;
    serde_json::to_writer(&mut *output, value)
        .map_err(|_| anyhow!("Не удалось записать данные VPS"))?;
    output.push(b'\n');
    Ok(())
}

#[derive(Default)]
struct Fields<'a> {
    name: Option<&'a str>,
    provider: Option<&'a str>,
    host: Option<&'a str>,
    username: Option<&'a str>,
    port: Option<&'a str>,
    identity_file: Option<&'a str>,
    panel_url: Option<&'a str>,
    account_login: Option<&'a str>,
    password_role: Option<&'a str>,
    ssh_password: Option<&'a str>,
    account_password: Option<&'a str>,
    archived: Option<&'a str>,
    notes: Option<&'a str>,
    billing: Option<&'a str>,
    payments: Option<&'a str>,
}

pub(super) fn decode(id: Uuid, bytes: &[u8]) -> Result<Host> {
    let mut lines = std::str::from_utf8(bytes)
        .map_err(|_| invalid_entry())?
        .split_terminator('\n');
    let first = lines.next().ok_or_else(invalid_entry)?;
    let mut fields = Fields::default();
    for line in lines {
        let (key, value) = line.split_once(": ").ok_or_else(invalid_entry)?;
        let field = match key {
            "name" => &mut fields.name,
            "provider" => &mut fields.provider,
            "host" => &mut fields.host,
            "username" => &mut fields.username,
            "port" => &mut fields.port,
            "identity_file" => &mut fields.identity_file,
            "panel_url" => &mut fields.panel_url,
            "account_login" => &mut fields.account_login,
            "password_role" => &mut fields.password_role,
            "ssh_password" => &mut fields.ssh_password,
            "account_password" => &mut fields.account_password,
            "archived" => &mut fields.archived,
            "notes" => &mut fields.notes,
            "billing" => &mut fields.billing,
            "payments" => &mut fields.payments,
            _ => return Err(invalid_entry()),
        };
        ensure!(field.replace(value).is_none(), invalid_entry());
    }

    let (ssh_password, account_password) = match (
        fields.password_role,
        fields.ssh_password,
        fields.account_password,
    ) {
        (Some("ssh"), None, account) if !first.is_empty() => (Some(first), account),
        (Some("account"), ssh @ (None | Some("")), None) => (ssh, Some(first)),
        (Some("none"), ssh @ (None | Some("")), None) if first.is_empty() => (ssh, None),
        _ => return Err(invalid_entry()),
    };
    let ssh = match (
        fields.host,
        fields.username,
        fields.port,
        fields.identity_file,
        ssh_password,
    ) {
        (Some(host), user, port, identity_file, password) => Some(SshConfig {
            host: host.to_owned(),
            user: user.map(str::to_owned),
            port: port
                .map(str::parse)
                .transpose()
                .map_err(|_| invalid_entry())?,
            identity_file: identity_file.map(str::to_owned),
            password: password.map(str::to_owned),
        }),
        (None, None, None, None, None) => None,
        _ => return Err(invalid_entry()),
    };
    Ok(Host {
        id,
        name: fields.name.ok_or_else(invalid_entry)?.to_owned(),
        provider: fields.provider.ok_or_else(invalid_entry)?.to_owned(),
        panel_url: fields.panel_url.map(str::to_owned),
        account_login: fields.account_login.map(str::to_owned),
        account_password: account_password.map(str::to_owned),
        notes: read_json(fields.notes)?,
        archived: fields
            .archived
            .ok_or_else(invalid_entry)?
            .parse()
            .map_err(|_| invalid_entry())?,
        ssh,
        billing: read_json(fields.billing)?,
        payments: read_json(fields.payments)?,
    })
}

fn read_json<T: DeserializeOwned>(value: Option<&str>) -> Result<T> {
    serde_json::from_str(value.ok_or_else(invalid_entry)?).map_err(|_| invalid_entry())
}

fn invalid_entry() -> anyhow::Error {
    anyhow!("Некорректный формат записи VPS")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Host {
        serde_json::from_str(
            r#"{
                "id":"8438ee2c-266c-4510-be3b-7ac2d50c97fe",
                "name":"узел: один", "provider":"example", "panel_url":"https://example.net/",
                "account_login":"", "account_password":"panel secret", "notes":"one\nname: two\n",
                "archived":true, "ssh":{"host":"2001:db8::1","user":"root","port":2200,
                "identity_file":"~/.ssh/example:key","password":" ssh: secret "},
                "billing":{"amount":"2.30","currency":"EUR","period":"other",
                "period_note":"two months","next_due":"2025-05-01"},
                "payments":[{"paid_on":"2025-03-01","amount":"2.30","currency":"EUR",
                "next_due":"2025-05-01"},{"paid_on":"2025-01-01","amount":"2.00",
                "currency":"EUR","next_due":"2025-03-01"}]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn pass_first_line_and_password_presence_round_trip() {
        let mut host = host();
        for (ssh, account, first) in [
            (Some(" ssh: secret "), Some("panel secret"), " ssh: secret "),
            (Some("ssh secret"), Some(""), "ssh secret"),
            (Some(""), Some("panel secret"), "panel secret"),
            (None, Some(""), ""),
            (Some(""), None, ""),
            (None, None, ""),
        ] {
            host.ssh.as_mut().unwrap().password = ssh.map(str::to_owned);
            host.account_password = account.map(str::to_owned);
            let bytes = encode(&host).unwrap();
            let text = std::str::from_utf8(&bytes).unwrap();
            assert_eq!(text.split_once('\n').unwrap().0, first);
            assert!(text.contains("\nhost: 2001:db8::1\nusername: root\nport: 2200\n"));
            if !first.is_empty() {
                assert_eq!(text.matches(first).count(), 1);
            }
            assert!(decode(host.id, &bytes).unwrap() == host);
            assert!(decode(host.id, text.strip_suffix('\n').unwrap().as_bytes()).unwrap() == host);
        }
    }

    #[test]
    fn rejects_malformed_entries_without_echoing_contents() {
        let host = host();
        let text = String::from_utf8(encode(&host).unwrap()).unwrap();
        for malformed in [
            text.replace("password_role: ssh", "password_role: account"),
            text.replace("port: 2200\n", "port: sensitive\n"),
            text.replace("name: узел: один\n", ""),
            format!("{text}name: sensitive\n"),
            format!("{text}sensitive: value\n"),
        ] {
            let error = decode(host.id, malformed.as_bytes()).err().unwrap();
            assert_eq!(format!("{error:#}"), "Некорректный формат записи VPS");
        }
        assert!(decode(host.id, b"\xff").is_err());
    }
}
