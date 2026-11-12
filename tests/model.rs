use chrono::{Days, Local, NaiveDate};
use host_manager::model::{
    Billing, BillingPeriod, Catalog, Host, Payment, SshConfig, currency, due_status,
    find_connect_host, money, parse_amount, parse_date, sorted_hosts, summary, validate_line,
    validate_payment,
};
use rust_decimal::Decimal;
use uuid::Uuid;

fn today() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 11, 12).unwrap()
}

fn host(name: &str, amount: &str, currency: &str, period: BillingPeriod) -> Host {
    Host {
        id: Uuid::new_v4(),
        name: name.into(),
        provider: "Тестовый хостер".into(),
        panel_url: None,
        account_login: None,
        account_password: None,
        notes: "Заметки\nВторая строка".into(),
        archived: false,
        ssh: Some(SshConfig {
            host: "example-vps".into(),
            user: None,
            port: None,
            identity_file: None,
            password: None,
        }),
        billing: Billing {
            amount: parse_amount(amount).unwrap(),
            currency: currency.into(),
            period,
            period_note: (period == BillingPeriod::Other).then(|| "за произвольный период".into()),
            next_due: Some(today()),
        },
        payments: Vec::new(),
    }
}

#[test]
fn amounts_are_exact_and_never_round_input() {
    assert_eq!(
        parse_amount("0.10").unwrap() + parse_amount("0,20").unwrap(),
        parse_amount("0.30").unwrap()
    );
    assert_eq!(
        parse_amount("79228162514264337593543950335").unwrap(),
        Decimal::MAX
    );
    assert_eq!(
        parse_amount("0.1234567890123456789012345678")
            .unwrap()
            .scale(),
        28
    );
    for invalid in [
        "",
        "NaN",
        "Infinity",
        "-1",
        "-0",
        "+1",
        " 1",
        "1 ",
        "1e2",
        "1_000",
        "1 000",
        "1,000.00",
        "1.2.3",
        ".5",
        "5.",
        "0.12345678901234567890123456789",
        "1.00000000000000000000000000000",
        "79228162514264337593543950336",
        "79228162514264337593543950335.1",
    ] {
        assert!(
            parse_amount(invalid).is_err(),
            "accepted invalid amount: {invalid}"
        );
    }
    assert_eq!(money(parse_amount("1.005").unwrap()), "1.01");
    assert_eq!(money(parse_amount("1.004").unwrap()), "1.00");
    assert_eq!(money(Decimal::ZERO), "0.00");
    assert_eq!(money(-parse_amount("1.005").unwrap()), "-1.01");
}

#[test]
fn canonical_dates_currency_and_terminal_text() {
    assert_eq!(parse_date("2026-11-12").unwrap(), today());
    assert!(parse_date("2024-02-29").is_ok());
    for invalid in [
        "2026-2-01",
        "2026-02-1",
        "2026-02-29",
        "2026-11-12 ",
        " 2026-11-12",
        "2026-11-12T00:00:00",
        "12.11.2026",
    ] {
        assert!(parse_date(invalid).is_err());
    }
    assert_eq!(currency("eUr").unwrap(), "EUR");
    for invalid in ["EU", "EURO", "ЕUR", "U1D", " EUR", "€€€"] {
        assert!(currency(invalid).is_err());
    }
    assert!(validate_line("Обычный текст 🔐").is_ok());
    for invalid in ["a\nb", "a\rb", "a\tb", "\u{1b}[2J", "\0", "\u{85}"] {
        assert!(validate_line(invalid).is_err());
    }
}

#[test]
fn summaries_keep_currencies_periods_and_windows_separate() {
    let mut catalog = Catalog {
        version: 1,
        hosts: vec![
            host("monthly", "5", "EUR", BillingPeriod::Month),
            host("yearly", "60", "EUR", BillingPeriod::Year),
            host("rub", "100", "RUB", BillingPeriod::Month),
            host("quarter", "30", "USD", BillingPeriod::Quarter),
            host("half-year", "120", "USD", BillingPeriod::HalfYear),
            host("excluded", "700", "GBP", BillingPeriod::Other),
            host("archive", "999", "JPY", BillingPeriod::Month),
        ],
    };
    catalog.hosts[0].billing.next_due = Some(today() - Days::new(1));
    catalog.hosts[1].billing.next_due = Some(today() + Days::new(30));
    catalog.hosts[2].billing.next_due = Some(today() + Days::new(31));
    catalog.hosts[3].billing.next_due = None;
    catalog.hosts[6].archived = true;
    let totals = summary(&catalog, today()).unwrap();
    assert_eq!(money(totals.monthly["EUR"]), "10.00");
    assert_eq!(money(totals.monthly["RUB"]), "100.00");
    assert_eq!(money(totals.monthly["USD"]), "30.00");
    assert_eq!(totals.monthly.len(), 3);
    assert_eq!(totals.excluded, 1);
    assert_eq!(totals.overdue["EUR"], parse_amount("5").unwrap());
    assert_eq!(totals.overdue.len(), 1);
    assert_eq!(totals.upcoming["EUR"], parse_amount("60").unwrap());
    assert_eq!(totals.upcoming["USD"], parse_amount("120").unwrap());
    assert_eq!(totals.upcoming["GBP"], parse_amount("700").unwrap());
    assert!(!totals.upcoming.contains_key("RUB"));
    assert!(!totals.upcoming.contains_key("JPY"));
}

#[test]
fn summary_rounds_after_summing_and_reports_overflow() {
    let mut catalog = Catalog {
        version: 1,
        hosts: vec![
            host("a", "0.005", "EUR", BillingPeriod::Month),
            host("b", "0.005", "EUR", BillingPeriod::Month),
        ],
    };
    assert_eq!(
        money(summary(&catalog, today()).unwrap().monthly["EUR"]),
        "0.01"
    );
    catalog.hosts[0].billing.amount = Decimal::MAX;
    catalog.hosts[1].billing.amount = Decimal::MAX;
    assert!(summary(&catalog, today()).is_err());
    for entry in &mut catalog.hosts {
        entry.billing.period = BillingPeriod::Other;
        entry.billing.period_note = Some("custom".into());
    }
    assert!(
        summary(&catalog, today()).is_err(),
        "upcoming sum must also be checked"
    );
    for entry in &mut catalog.hosts {
        entry.billing.next_due = Some(today() - Days::new(1));
    }
    assert!(
        summary(&catalog, today()).is_err(),
        "overdue sum must also be checked"
    );
}

#[test]
fn due_boundaries_and_borrowed_sorting() {
    let mut entry = host("vps", "5", "EUR", BillingPeriod::Month);
    for (date, expected) in [
        (Some(today() - Days::new(1)), "Просрочено"),
        (Some(today()), "Сегодня"),
        (Some(today() + Days::new(1)), "Скоро"),
        (Some(today() + Days::new(7)), "Скоро"),
        (Some(today() + Days::new(8)), "Позже"),
        (None, "Срок не задан"),
    ] {
        entry.billing.next_due = date;
        assert_eq!(due_status(&entry, today()), expected);
    }
    let mut catalog = Catalog {
        version: 1,
        hosts: vec![
            host("z", "5", "EUR", BillingPeriod::Month),
            host("b", "5", "EUR", BillingPeriod::Month),
            host("a", "5", "EUR", BillingPeriod::Month),
            host("archive", "5", "EUR", BillingPeriod::Month),
            host("b", "5", "EUR", BillingPeriod::Month),
        ],
    };
    catalog.hosts[0].billing.next_due = None;
    catalog.hosts[3].archived = true;
    catalog.hosts[1].id = Uuid::from_u128(2);
    catalog.hosts[4].id = Uuid::from_u128(1);
    let sorted = sorted_hosts(&catalog, false);
    assert_eq!(
        sorted
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["a", "b", "b", "z"]
    );
    assert_eq!(sorted[1].id, Uuid::from_u128(1));
    assert!(std::ptr::eq(sorted[0], &catalog.hosts[2]));
    assert_eq!(sorted_hosts(&catalog, true).len(), 1);
}

#[test]
fn payment_requires_explicit_forward_date_and_keeps_original_tariff() {
    let entry = host("vps", "5", "EUR", BillingPeriod::Month);
    let payment = Payment {
        paid_on: today(),
        amount: parse_amount("4.50").unwrap(),
        currency: "USD".into(),
        next_due: today() + Days::new(30),
    };
    assert!(validate_payment(&entry, &payment, today()).is_ok());
    assert_eq!(entry.billing.amount, parse_amount("5").unwrap());
    for bad in [
        Payment {
            next_due: today(),
            ..payment.clone()
        },
        Payment {
            next_due: today() - Days::new(1),
            ..payment.clone()
        },
        Payment {
            paid_on: today() + Days::new(1),
            ..payment.clone()
        },
        Payment {
            amount: Decimal::NEGATIVE_ONE,
            ..payment.clone()
        },
        Payment {
            currency: "eur".into(),
            ..payment.clone()
        },
    ] {
        assert!(validate_payment(&entry, &bad, today()).is_err());
    }
    let mut entry = entry;
    entry.billing.next_due = Some(payment.next_due);
    assert!(validate_payment(&entry, &payment, today()).is_err());
    entry.billing.next_due = None;
    assert!(validate_payment(&entry, &payment, today()).is_ok());
}

#[test]
fn connect_selection_is_exact_active_unique_and_requires_ssh() {
    let mut catalog = Catalog {
        version: 1,
        hosts: vec![host("prod eu", "5", "EUR", BillingPeriod::Month)],
    };
    assert!(std::ptr::eq(
        find_connect_host(&catalog, "prod eu").unwrap(),
        &catalog.hosts[0]
    ));
    for name in ["prod", "Prod eu", "", "prod eu "] {
        assert!(find_connect_host(&catalog, name).is_err());
    }
    catalog.hosts[0].archived = true;
    assert_eq!(
        find_connect_host(&catalog, "prod eu")
            .err()
            .unwrap()
            .to_string(),
        "VPS находится в архиве"
    );
    catalog
        .hosts
        .push(host("prod eu", "5", "EUR", BillingPeriod::Month));
    assert_eq!(
        find_connect_host(&catalog, "prod eu").unwrap().id,
        catalog.hosts[1].id
    );
    catalog
        .hosts
        .push(host("prod eu", "5", "EUR", BillingPeriod::Month));
    assert_eq!(
        find_connect_host(&catalog, "prod eu")
            .err()
            .unwrap()
            .to_string(),
        "Имя VPS неоднозначно; переименуйте записи в TUI"
    );
    catalog.hosts.pop();
    catalog.hosts[1].ssh = None;
    assert_eq!(
        find_connect_host(&catalog, "prod eu")
            .err()
            .unwrap()
            .to_string(),
        "SSH-доступ не настроен"
    );
    assert_eq!(
        find_connect_host(&catalog, "unknown")
            .err()
            .unwrap()
            .to_string(),
        "VPS не найден"
    );
}

#[test]
fn strict_schema_requires_nullable_fields_and_rejects_unknown_data() {
    let ssh = r#"{"host":"alias","user":null,"port":null,"identity_file":null,"password":null}"#;
    let billing =
        r#"{"amount":"5.00","currency":"EUR","period":"month","period_note":null,"next_due":null}"#;
    let payment =
        r#"{"paid_on":"2026-11-01","amount":"5.00","currency":"EUR","next_due":"2026-12-01"}"#;
    let host = r#"{"id":"550e8400-e29b-41d4-a716-446655440000","name":"vps","provider":"provider","panel_url":null,"account_login":null,"account_password":null,"notes":"","archived":false,"ssh":null,"billing":{"amount":"5.00","currency":"EUR","period":"month","period_note":null,"next_due":null},"payments":[]}"#;
    let catalog = format!(r#"{{"version":1,"hosts":[{host}]}}"#);
    let parsed: Catalog = serde_json::from_str(&catalog).unwrap();
    assert!(parsed.validate().is_ok());
    assert!(
        serde_json::from_str::<Catalog>(&serde_json::to_string(&parsed).unwrap()).unwrap()
            == parsed
    );

    for field in [
        r#","user":null"#,
        r#","port":null"#,
        r#","identity_file":null"#,
        r#","password":null"#,
    ] {
        assert!(serde_json::from_str::<SshConfig>(&ssh.replace(field, "")).is_err());
    }
    for field in [
        r#","panel_url":null"#,
        r#","account_login":null"#,
        r#","account_password":null"#,
        r#","ssh":null"#,
    ] {
        assert!(serde_json::from_str::<Host>(&host.replace(field, "")).is_err());
    }
    for field in [r#","period_note":null"#, r#","next_due":null"#] {
        assert!(serde_json::from_str::<Billing>(&billing.replace(field, "")).is_err());
    }
    for invalid in [
        catalog.replace("\"version\":1", "\"version\":2"),
        catalog.replace("\"version\":1", "\"version\":1,\"new_field\":true"),
        catalog.replace("\"name\":\"vps\"", "\"name\":\"vps\",\"new_field\":true"),
        catalog.replace("\"period\":\"month\"", "\"period\":\"week\""),
        catalog.replace("\"amount\":\"5.00\"", "\"amount\":5.00"),
        catalog.replace("\"amount\":\"5.00\"", "\"amount\":\"-5.00\""),
        catalog.replace("\"next_due\":null", "\"next_due\":\"2026-2-01\""),
        catalog.replace("\"next_due\":null", "\"next_due\":\"2026-02-29\""),
        catalog.replace(
            "\"amount\":\"5.00\"",
            "\"amount\":\"0.12345678901234567890123456789\"",
        ),
        catalog.replace("\"currency\":\"EUR\"", "\"currency\":\"EURO\""),
    ] {
        assert!(
            serde_json::from_str::<Catalog>(&invalid)
                .map(|value| value.validate().is_err())
                .unwrap_or(true)
        );
    }
    assert!(
        serde_json::from_str::<SshConfig>(&ssh.replace("\"port\":null", "\"port\":65536")).is_err()
    );
    assert!(
        serde_json::from_str::<SshConfig>(&ssh.replace("\"port\":null", "\"port\":-1")).is_err()
    );
    assert!(
        serde_json::from_str::<SshConfig>(
            &ssh.replace("\"host\":\"alias\"", "\"host\":\"alias\",\"extra\":null")
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<Billing>(&billing.replace(
            "\"period\":\"month\"",
            "\"period\":\"month\",\"extra\":null"
        ))
        .is_err()
    );
    assert!(
        serde_json::from_str::<Payment>(
            &payment.replace("\"amount\":\"5.00\"", "\"amount\":\"5.00\",\"extra\":null")
        )
        .is_err()
    );
    assert!(serde_json::from_str::<Payment>(&payment.replace("2026-11-01", "2026-1-01")).is_err());
    assert!(serde_json::from_str::<Payment>(&payment.replace("2026-12-01", "2026-2-01")).is_err());
    assert!(
        serde_json::from_str::<Payment>(&payment.replace(",\"next_due\":\"2026-12-01\"", ""))
            .is_err()
    );
    assert_eq!(
        serde_json::from_str::<Billing>(&billing.replace("EUR", "eur"))
            .unwrap()
            .currency,
        "EUR"
    );
}

#[test]
fn catalog_validation_prevents_silent_invalid_mutations() {
    let mut catalog = Catalog {
        version: 1,
        hosts: vec![host("vps", "5", "EUR", BillingPeriod::Month)],
    };
    assert!(catalog.validate().is_ok());
    let original = catalog.hosts[0].clone();
    catalog.hosts.push(original.clone());
    assert!(catalog.validate().is_err());
    catalog.hosts[1].id = Uuid::new_v4();
    assert!(
        catalog.validate().is_ok(),
        "duplicate display names are allowed"
    );
    catalog.hosts.pop();
    let mut invalid = Vec::new();
    let mut changed = original.clone();
    changed.name = "  ".into();
    invalid.push(changed);
    let mut changed = original.clone();
    changed.provider.clear();
    invalid.push(changed);
    let mut changed = original.clone();
    changed.name = "bad\u{1b}[2J".into();
    invalid.push(changed);
    let mut changed = original.clone();
    changed.account_password = Some("secret\n".into());
    invalid.push(changed);
    let mut changed = original.clone();
    changed.notes = "bad\rtext".into();
    invalid.push(changed);
    let mut changed = original.clone();
    changed.billing.amount = Decimal::NEGATIVE_ONE;
    invalid.push(changed);
    let mut changed = original.clone();
    changed.billing.period = BillingPeriod::Other;
    invalid.push(changed);
    let mut changed = original.clone();
    changed.billing.period_note = Some("unexpected".into());
    invalid.push(changed);
    let mut changed = original.clone();
    changed.ssh.as_mut().unwrap().port = Some(0);
    invalid.push(changed);
    for entry in invalid {
        catalog.hosts[0] = entry;
        assert!(catalog.validate().is_err());
    }
    catalog.hosts[0] = original;
    let now = Local::now().date_naive();
    catalog.hosts[0].payments.push(Payment {
        paid_on: now + Days::new(1),
        amount: Decimal::ONE,
        currency: "EUR".into(),
        next_due: now + Days::new(30),
    });
    assert!(catalog.validate().is_err());
    catalog.hosts[0].payments[0].paid_on = now - Days::new(30);
    catalog.hosts[0].payments[0].next_due = now;
    catalog.hosts[0].billing.next_due = Some(now + Days::new(30));
    assert!(
        catalog.validate().is_ok(),
        "historical payments retain their own deadlines"
    );
}
