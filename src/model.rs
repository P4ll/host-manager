use std::collections::{BTreeMap, HashSet};

use anyhow::{Result, bail, ensure};
use chrono::{Local, NaiveDate};
use rust_decimal::{Decimal, RoundingStrategy};
use serde::{Deserialize, Deserializer, Serialize, de};
use uuid::Uuid;

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub version: u32,
    pub hosts: Vec<Host>,
}

impl Default for Catalog {
    fn default() -> Self {
        Self {
            version: 1,
            hosts: Vec::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub id: Uuid,
    pub name: String,
    pub provider: String,
    #[serde(deserialize_with = "required_option")]
    pub panel_url: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub account_login: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub account_password: Option<String>,
    pub notes: String,
    pub archived: bool,
    #[serde(deserialize_with = "required_option")]
    pub ssh: Option<SshConfig>,
    pub billing: Billing,
    pub payments: Vec<Payment>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SshConfig {
    pub host: String,
    #[serde(deserialize_with = "required_option")]
    pub user: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub port: Option<u16>,
    #[serde(deserialize_with = "required_option")]
    pub identity_file: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub password: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Billing {
    #[serde(
        serialize_with = "rust_decimal::serde::str::serialize",
        deserialize_with = "deserialize_amount"
    )]
    pub amount: Decimal,
    #[serde(deserialize_with = "deserialize_currency")]
    pub currency: String,
    pub period: BillingPeriod,
    #[serde(deserialize_with = "required_option")]
    pub period_note: Option<String>,
    #[serde(deserialize_with = "deserialize_optional_date")]
    pub next_due: Option<NaiveDate>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Payment {
    #[serde(deserialize_with = "deserialize_date")]
    pub paid_on: NaiveDate,
    #[serde(
        serialize_with = "rust_decimal::serde::str::serialize",
        deserialize_with = "deserialize_amount"
    )]
    pub amount: Decimal,
    #[serde(deserialize_with = "deserialize_currency")]
    pub currency: String,
    #[serde(deserialize_with = "deserialize_date")]
    pub next_due: NaiveDate,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BillingPeriod {
    Month,
    Quarter,
    HalfYear,
    Year,
    Other,
}

fn required_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

fn deserialize_amount<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Decimal, D::Error> {
    let value = String::deserialize(deserializer)?;
    parse_amount(&value).map_err(|_| de::Error::custom("Некорректная сумма"))
}

fn deserialize_currency<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    currency(&value).map_err(|_| de::Error::custom("Некорректная валюта"))
}

fn deserialize_date<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<NaiveDate, D::Error> {
    let value = String::deserialize(deserializer)?;
    parse_date(&value).map_err(|_| de::Error::custom("Некорректная дата"))
}

fn deserialize_optional_date<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<NaiveDate>, D::Error> {
    let value: Option<String> = required_option(deserializer)?;
    value
        .as_deref()
        .map(parse_date)
        .transpose()
        .map_err(|_| de::Error::custom("Некорректная дата"))
}

pub fn parse_amount(value: &str) -> Result<Decimal> {
    let mut separator = None;
    ensure!(!value.is_empty(), "Введите сумму");
    for (index, byte) in value.bytes().enumerate() {
        if byte == b'.' || byte == b',' {
            ensure!(
                separator.is_none() && index > 0 && index + 1 < value.len(),
                "Некорректная сумма"
            );
            separator = Some(index);
        } else {
            ensure!(
                byte.is_ascii_digit(),
                "Сумма должна быть неотрицательным десятичным числом"
            );
        }
    }
    if let Some(index) = separator {
        ensure!(
            value.len() - index - 1 <= 28,
            "В сумме допускается не более 28 дробных разрядов"
        );
    }
    let amount = if value.contains(',') {
        Decimal::from_str_exact(&value.replace(',', "."))
    } else {
        Decimal::from_str_exact(value)
    };
    amount.map_err(|_| anyhow::anyhow!("Сумма выходит за диапазон Decimal"))
}

pub fn parse_date(value: &str) -> Result<NaiveDate> {
    let date = NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Введите дату в формате ГГГГ-ММ-ДД"))?;
    ensure!(
        date.format("%Y-%m-%d").to_string() == value,
        "Введите дату в формате ГГГГ-ММ-ДД"
    );
    Ok(date)
}

pub fn currency(value: &str) -> Result<String> {
    ensure!(
        value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_alphabetic()),
        "Валюта должна содержать три латинские буквы"
    );
    Ok(value.to_ascii_uppercase())
}

pub fn validate_line(value: &str) -> Result<()> {
    ensure!(
        !value.chars().any(char::is_control),
        "Управляющие символы запрещены"
    );
    Ok(())
}

fn validate_amount(amount: Decimal) -> Result<()> {
    ensure!(
        !amount.is_sign_negative(),
        "Сумма не может быть отрицательной"
    );
    Ok(())
}

fn validate_currency(value: &str) -> Result<()> {
    ensure!(
        value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase()),
        "Валюта должна содержать три латинские буквы в верхнем регистре"
    );
    Ok(())
}

fn validate_payment_fields(payment: &Payment, today: NaiveDate) -> Result<()> {
    validate_amount(payment.amount)?;
    validate_currency(&payment.currency)?;
    ensure!(
        payment.paid_on <= today,
        "Дата оплаты не может быть в будущем"
    );
    ensure!(
        payment.next_due > payment.paid_on,
        "Следующая дата должна быть позже даты оплаты"
    );
    Ok(())
}

impl Catalog {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "Неизвестная версия каталога");
        let today = Local::now().date_naive();
        let mut ids = HashSet::with_capacity(self.hosts.len());
        for host in &self.hosts {
            ensure!(
                ids.insert(host.id),
                "В каталоге повторяется идентификатор VPS"
            );
            ensure!(!host.name.trim().is_empty(), "Введите имя VPS");
            ensure!(!host.provider.trim().is_empty(), "Введите провайдера");
            validate_line(&host.name)?;
            validate_line(&host.provider)?;
            for value in [&host.panel_url, &host.account_login, &host.account_password]
                .into_iter()
                .flatten()
            {
                validate_line(value)?;
            }
            ensure!(
                !host.notes.chars().any(|ch| ch.is_control() && ch != '\n'),
                "В заметках разрешены только текст и переносы строк"
            );
            if let Some(ssh) = &host.ssh {
                crate::ssh::validate_config(ssh)?;
            }
            validate_amount(host.billing.amount)?;
            validate_currency(&host.billing.currency)?;
            match (host.billing.period, host.billing.period_note.as_deref()) {
                (BillingPeriod::Other, Some(note)) if !note.trim().is_empty() => {
                    validate_line(note)?
                }
                (BillingPeriod::Other, _) => bail!("Для нестандартного периода введите описание"),
                (_, None) => (),
                (_, Some(_)) => {
                    bail!("Описание периода допустимо только для нестандартного тарифа")
                }
            }
            for payment in &host.payments {
                validate_payment_fields(payment, today)?;
            }
        }
        Ok(())
    }
}

pub fn validate_payment(host: &Host, payment: &Payment, today: NaiveDate) -> Result<()> {
    validate_payment_fields(payment, today)?;
    if let Some(previous) = host.billing.next_due {
        ensure!(
            payment.next_due > previous,
            "Следующая дата должна быть позже прежнего срока"
        );
    }
    Ok(())
}

pub fn find_connect_host<'a>(catalog: &'a Catalog, name: &str) -> Result<&'a Host> {
    let mut active = catalog
        .hosts
        .iter()
        .filter(|host| !host.archived && host.name == name);
    let Some(host) = active.next() else {
        if catalog
            .hosts
            .iter()
            .any(|host| host.archived && host.name == name)
        {
            bail!("VPS находится в архиве");
        }
        bail!("VPS не найден");
    };
    ensure!(
        active.next().is_none(),
        "Имя VPS неоднозначно; переименуйте записи в TUI"
    );
    ensure!(host.ssh.is_some(), "SSH-доступ не настроен");
    Ok(host)
}

pub fn sorted_hosts(catalog: &Catalog, archived: bool) -> Vec<&Host> {
    let mut hosts: Vec<_> = catalog
        .hosts
        .iter()
        .filter(|host| host.archived == archived)
        .collect();
    hosts.sort_by(|a, b| {
        a.billing
            .next_due
            .is_none()
            .cmp(&b.billing.next_due.is_none())
            .then_with(|| a.billing.next_due.cmp(&b.billing.next_due))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.id.cmp(&b.id))
    });
    hosts
}

pub fn due_status(host: &Host, today: NaiveDate) -> &'static str {
    if host.archived {
        return "В архиве";
    }
    match host
        .billing
        .next_due
        .map(|date| date.signed_duration_since(today).num_days())
    {
        None => "Срок не задан",
        Some(days) if days < 0 => "Просрочено",
        Some(0) => "Сегодня",
        Some(1..=7) => "Скоро",
        Some(_) => "Позже",
    }
}

#[derive(Default)]
pub struct Summary {
    pub monthly: BTreeMap<String, Decimal>,
    pub upcoming: BTreeMap<String, Decimal>,
    pub overdue: BTreeMap<String, Decimal>,
    pub excluded: usize,
}

fn add_amount(
    totals: &mut BTreeMap<String, Decimal>,
    currency: &str,
    amount: Decimal,
) -> Result<()> {
    if let Some(total) = totals.get_mut(currency) {
        *total = total
            .checked_add(amount)
            .ok_or_else(|| anyhow::anyhow!("Переполнение суммы сводки"))?;
    } else {
        totals.insert(currency.to_owned(), amount);
    }
    Ok(())
}

pub fn summary(catalog: &Catalog, today: NaiveDate) -> Result<Summary> {
    let mut result = Summary::default();
    for host in catalog.hosts.iter().filter(|host| !host.archived) {
        let billing = &host.billing;
        let months = match billing.period {
            BillingPeriod::Month => Some(1),
            BillingPeriod::Quarter => Some(3),
            BillingPeriod::HalfYear => Some(6),
            BillingPeriod::Year => Some(12),
            BillingPeriod::Other => None,
        };
        if let Some(months) = months {
            let amount = billing
                .amount
                .checked_div(Decimal::from(months))
                .ok_or_else(|| anyhow::anyhow!("Переполнение месячной оценки"))?;
            add_amount(&mut result.monthly, &billing.currency, amount)?;
        } else {
            result.excluded += 1;
        }
        if let Some(date) = billing.next_due {
            let days = date.signed_duration_since(today).num_days();
            if days < 0 {
                add_amount(&mut result.overdue, &billing.currency, billing.amount)?;
            } else if days <= 30 {
                add_amount(&mut result.upcoming, &billing.currency, billing.amount)?;
            }
        }
    }
    Ok(result)
}

pub fn money(amount: Decimal) -> String {
    format!(
        "{:.2}",
        amount.round_dp_with_strategy(2, RoundingStrategy::MidpointAwayFromZero)
    )
}
