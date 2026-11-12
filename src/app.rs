use std::io::IsTerminal;

use anyhow::{Context, Result, bail};
use chrono::Local;
use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
};
use tui_textarea::TextArea;
use uuid::Uuid;

use crate::{
    model::{self, Billing, BillingPeriod, Catalog, Host, Payment, SshConfig},
    ssh,
    store::{PassStore, SaveOutcome},
};

pub enum Effect {
    Save,
    Reload,
    Ssh,
}

enum Mode {
    List,
    Search,
    Detail { reveal: bool, scroll: u16 },
    HostForm(Box<HostForm>),
    PaymentForm(Box<PaymentForm>),
    Confirm { id: Uuid, ssh: bool },
}

pub struct App {
    store: PassStore,
    catalog: Catalog,
    table: TableState,
    search: TextArea<'static>,
    archived: bool,
    mode: Mode,
    message: String,
    pub should_quit: bool,
}

impl App {
    pub fn new(mut store: PassStore) -> Result<Self> {
        let catalog = store.load()?;
        Ok(Self {
            store,
            catalog,
            table: TableState::default().with_selected(Some(0)),
            search: text_area("", false),
            archived: false,
            mode: Mode::List,
            message: String::new(),
            should_quit: false,
        })
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn set_message(&mut self, message: String) {
        self.message = message;
    }

    pub fn handle_paste(&mut self, text: &str) {
        let (field, multiline) = match &mut self.mode {
            Mode::HostForm(form) => (form.fields.get_mut(form.focus), form.focus == 5),
            Mode::PaymentForm(form) => (form.fields.get_mut(form.focus), false),
            Mode::Search => (Some(&mut self.search), false),
            _ => (None, false),
        };
        if text
            .chars()
            .any(|c| c.is_control() && !(multiline && c == '\n'))
        {
            self.message = "Вставка отклонена: недопустимые управляющие символы".into();
            return;
        }
        if let Some(field) = field {
            field.insert_str(text);
        }
    }

    pub fn handle_mouse(&mut self, event: MouseEvent) -> bool {
        let (focus, areas, count) = match &mut self.mode {
            Mode::HostForm(form) => (&mut form.focus, &form.field_areas, form.fields.len()),
            Mode::PaymentForm(form) => (&mut form.focus, &form.field_areas, form.fields.len()),
            _ => return false,
        };
        let previous = *focus;
        match event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some((_, index)) = areas
                    .iter()
                    .find(|(area, _)| area.contains((event.column, event.row).into()))
                {
                    *focus = *index;
                }
            }
            MouseEventKind::ScrollDown => *focus = (*focus + 1).min(count - 1),
            MouseEventKind::ScrollUp => *focus = focus.saturating_sub(1),
            _ => {}
        }
        *focus != previous
    }

    fn visible(&self) -> Vec<&Host> {
        let query = self.search.lines()[0].to_lowercase();
        model::sorted_hosts(&self.catalog, self.archived)
            .into_iter()
            .filter(|host| {
                query.is_empty()
                    || host.name.to_lowercase().contains(&query)
                    || host.provider.to_lowercase().contains(&query)
                    || host
                        .ssh
                        .as_ref()
                        .is_some_and(|s| s.host.to_lowercase().contains(&query))
            })
            .collect()
    }

    fn selected(&self) -> Option<&Host> {
        let index = self.table.selected()?;
        self.visible().get(index).copied()
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Result<Option<Effect>> {
        if key.kind != KeyEventKind::Press {
            return Ok(None);
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return Ok(None);
        }
        match &mut self.mode {
            Mode::HostForm(form) => {
                match form.key(key) {
                    FormAction::Save => return Ok(Some(Effect::Save)),
                    FormAction::Cancel => self.mode = Mode::List,
                    FormAction::None => {}
                }
                return Ok(None);
            }
            Mode::PaymentForm(form) => {
                match form.key(key) {
                    FormAction::Save => return Ok(Some(Effect::Save)),
                    FormAction::Cancel => self.mode = Mode::List,
                    FormAction::None => {}
                }
                return Ok(None);
            }
            Mode::Search => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                    self.mode = Mode::List;
                } else {
                    line_input(&mut self.search, key, false);
                    self.table.select(Some(0));
                }
                return Ok(None);
            }
            Mode::Confirm { ssh, .. } => {
                if key.code == KeyCode::Enter || key.code == KeyCode::Char('y') {
                    return Ok(Some(if *ssh { Effect::Ssh } else { Effect::Save }));
                }
                if matches!(key.code, KeyCode::Esc | KeyCode::Char('n')) {
                    self.mode = Mode::List;
                }
                return Ok(None);
            }
            Mode::Detail { reveal, scroll } => match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.mode = Mode::List;
                    return Ok(None);
                }
                KeyCode::Char('v') => {
                    *reveal = !*reveal;
                    return Ok(None);
                }
                KeyCode::PageDown | KeyCode::Down => {
                    *scroll = scroll.saturating_add(if key.code == KeyCode::Down { 1 } else { 10 });
                    return Ok(None);
                }
                KeyCode::PageUp | KeyCode::Up => {
                    *scroll = scroll.saturating_sub(if key.code == KeyCode::Up { 1 } else { 10 });
                    return Ok(None);
                }
                _ => {}
            },
            Mode::List => {}
        }
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('/') => self.mode = Mode::Search,
            KeyCode::Tab | KeyCode::BackTab => {
                self.archived = !self.archived;
                self.table.select(Some(0));
                self.mode = Mode::List;
            }
            KeyCode::Up | KeyCode::Down => {
                let len = self.visible().len();
                let selected = self.table.selected().unwrap_or(0);
                self.table.select(Some(if key.code == KeyCode::Up {
                    selected.saturating_sub(1)
                } else {
                    (selected + 1).min(len.saturating_sub(1))
                }));
            }
            KeyCode::Enter if self.selected().is_some() => {
                self.mode = Mode::Detail {
                    reveal: false,
                    scroll: 0,
                };
            }
            KeyCode::Char('a') => self.mode = Mode::HostForm(Box::new(HostForm::new(None))),
            KeyCode::Char('e') => {
                if let Some(host) = self.selected() {
                    self.mode = Mode::HostForm(Box::new(HostForm::new(Some(host))));
                }
            }
            KeyCode::Char('p') => {
                if let Some(host) = self.selected().filter(|h| !h.archived) {
                    self.mode = Mode::PaymentForm(Box::new(PaymentForm::new(host)));
                }
            }
            KeyCode::Char('x') => {
                if let Some(host) = self.selected() {
                    self.mode = Mode::Confirm {
                        id: host.id,
                        ssh: false,
                    };
                }
            }
            KeyCode::Char('s') => {
                if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
                    self.message = "SSH недоступен: требуется интерактивный терминал".into();
                } else if let Some(host) = self.selected() {
                    if host.ssh.is_none() {
                        self.message = "SSH-доступ не настроен".into();
                    } else {
                        self.mode = Mode::Confirm {
                            id: host.id,
                            ssh: true,
                        };
                    }
                }
            }
            KeyCode::Char('r') => return Ok(Some(Effect::Reload)),
            _ => {}
        }
        Ok(None)
    }

    pub fn perform(&mut self, effect: Effect) -> Result<()> {
        match effect {
            Effect::Reload => {
                if matches!(self.mode, Mode::HostForm(_) | Mode::PaymentForm(_)) {
                    bail!("Сначала явно отмените форму");
                }
                let loaded = self.store.load()?;
                self.catalog = loaded;
                self.mode = Mode::List;
                self.table.select(Some(0));
                self.message = "Каталог перечитан".into();
            }
            Effect::Ssh => {
                let Mode::Confirm { id, ssh: true } = self.mode else {
                    bail!("Сначала подтвердите подключение");
                };
                let config = self
                    .catalog
                    .hosts
                    .iter()
                    .find(|h| h.id == id)
                    .and_then(|h| h.ssh.as_ref())
                    .context("SSH-доступ не настроен")?;
                let status =
                    ssh::ssh_command(config, id, self.store.directory(), self.store.environment())?
                        .status()
                        .context("Не удалось запустить SSH")?;
                self.mode = Mode::List;
                self.message = match status.code() {
                    Some(code) => format!("SSH завершён: код {code}"),
                    None => "SSH завершён сигналом".into(),
                };
            }
            Effect::Save => self.save()?,
        }
        Ok(())
    }

    fn save(&mut self) -> Result<()> {
        let (id, replacement) = match &mut self.mode {
            Mode::HostForm(form) => {
                let result = form.build();
                match result {
                    Ok(mut host) => {
                        if let Some(original) = self.catalog.hosts.iter().find(|h| h.id == host.id)
                        {
                            host.payments = original.payments.clone();
                        }
                        (host.id, host)
                    }
                    Err((field, message)) => {
                        form.focus = field;
                        form.error = Some((field, message));
                        return Ok(());
                    }
                }
            }
            Mode::PaymentForm(form) => {
                let host = self
                    .catalog
                    .hosts
                    .iter()
                    .find(|h| h.id == form.id)
                    .context("Запись больше не существует")?;
                let payment = match form.build(host) {
                    Ok(payment) => payment,
                    Err((field, message)) => {
                        form.focus = field;
                        form.error = Some((field, message));
                        return Ok(());
                    }
                };
                let mut changed = host.clone();
                changed.billing.next_due = Some(payment.next_due);
                changed.payments.push(payment);
                (changed.id, changed)
            }
            Mode::Confirm { id, ssh: false } => {
                let host = self
                    .catalog
                    .hosts
                    .iter()
                    .find(|h| h.id == *id)
                    .context("Запись больше не существует")?;
                let mut changed = host.clone();
                changed.archived = !changed.archived;
                (changed.id, changed)
            }
            _ => bail!("Нет изменений для сохранения"),
        };
        let index = self.catalog.hosts.iter().position(|h| h.id == id);
        let old = if let Some(index) = index {
            Some(std::mem::replace(
                &mut self.catalog.hosts[index],
                replacement,
            ))
        } else {
            self.catalog.hosts.push(replacement);
            None
        };
        match self.store.save(&self.catalog) {
            Ok(outcome) => {
                self.mode = Mode::List;
                self.message = match outcome {
                    SaveOutcome::Saved => "Сохранено".into(),
                    SaveOutcome::SavedWithPassWarning => {
                        "Данные сохранены, но pass сообщил об ошибке; проверьте Git".into()
                    }
                };
                let selected = self.visible().iter().position(|h| h.id == id).unwrap_or(0);
                self.table.select(Some(selected));
                Ok(())
            }
            Err(error) => {
                if let Some(old) = old {
                    self.catalog.hosts[index.unwrap()] = old;
                } else {
                    self.catalog.hosts.pop();
                }
                Err(error)
            }
        }
    }

    pub fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let parts = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(2),
        ])
        .split(area);
        frame.render_widget(
            Paragraph::new(if self.archived {
                "Host Manager · Архив (услуги у хостера не отменены)"
            } else {
                "Host Manager · Активные VPS"
            })
            .style(Style::default().add_modifier(Modifier::BOLD)),
            parts[0],
        );
        let today = Local::now().date_naive();
        let summary = match model::summary(&self.catalog, today) {
            Ok(summary) => {
                let amounts =
                    |values: &std::collections::BTreeMap<String, rust_decimal::Decimal>| {
                        if values.is_empty() {
                            "—".into()
                        } else {
                            values
                                .iter()
                                .map(|(c, a)| format!("{} {c}", model::money(*a)))
                                .collect::<Vec<_>>()
                                .join(" · ")
                        }
                    };
                format!(
                    "В месяц: {}\nБлижайшие 30 дней: {}\nПросрочено: {}\nНе включены в месячную оценку: {}",
                    amounts(&summary.monthly),
                    amounts(&summary.upcoming),
                    amounts(&summary.overdue),
                    summary.excluded
                )
            }
            Err(_) => "Ошибка сводки: переполнение суммы".into(),
        };
        frame.render_widget(Paragraph::new(summary), parts[1]);
        self.search.set_block(
            Block::default()
                .borders(Borders::ALL)
                .title("Поиск: имя / провайдер / SSH"),
        );
        frame.render_widget(&self.search, parts[2]);
        let query = self.search.lines()[0].to_lowercase();
        let hosts: Vec<_> = model::sorted_hosts(&self.catalog, self.archived)
            .into_iter()
            .filter(|h| {
                query.is_empty()
                    || h.name.to_lowercase().contains(&query)
                    || h.provider.to_lowercase().contains(&query)
                    || h.ssh
                        .as_ref()
                        .is_some_and(|s| s.host.to_lowercase().contains(&query))
            })
            .collect();
        if hosts.is_empty() {
            frame.render_widget(
                Paragraph::new("Нет VPS · a — добавить").block(Block::bordered()),
                parts[3],
            );
        } else {
            let fixed_width = 21 + 12 + 14 + 4;
            let remaining = parts[3].width.saturating_sub(fixed_width);
            let name_width = (remaining / 2).max(3);
            let provider_width = remaining.saturating_sub(name_width).max(3);
            let rows = hosts.iter().map(|host| {
                Row::new(vec![
                    Cell::from(ellipsize(&host.name, name_width as usize)),
                    Cell::from(ellipsize(&host.provider, provider_width as usize)),
                    Cell::from(format!(
                        "{} {} / {}",
                        model::money(host.billing.amount),
                        host.billing.currency,
                        period_label(host.billing.period, host.billing.period_note.as_deref())
                    )),
                    Cell::from(
                        host.billing
                            .next_due
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| "—".into()),
                    ),
                    Cell::from(if host.archived {
                        "Архив"
                    } else {
                        model::due_status(host, today)
                    }),
                ])
            });
            let table = Table::new(
                rows,
                [
                    Constraint::Length(name_width),
                    Constraint::Length(provider_width),
                    Constraint::Length(21),
                    Constraint::Length(12),
                    Constraint::Length(14),
                ],
            )
            .header(
                Row::new(["Имя", "Провайдер", "Тариф / период", "Оплата", "Статус"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
            frame.render_stateful_widget(table, parts[3], &mut self.table);
        }
        frame.render_widget(Paragraph::new(self.message.as_str()), parts[4]);
        let help = match self.mode {
            Mode::Search => "Enter/Esc — вернуться · ввод — поиск",
            Mode::HostForm(_) | Mode::PaymentForm(_) => {
                "Клик/колесо/Tab — поля · Ctrl+S — сохранить · Esc — отмена"
            }
            Mode::Confirm { .. } => "Enter — подтвердить · Esc — отмена",
            Mode::Detail { .. } => {
                "v — показать/скрыть пароли · PgUp/PgDn — прокрутка · Esc — закрыть"
            }
            Mode::List => {
                if self.selected().is_some() {
                    "↑↓ выбор · Enter карточка · a новый · e править · p оплата · s SSH\nx архив · Tab актив/архив · / поиск · r перечитать · q выход"
                } else {
                    "a добавить · Tab актив/архив · / поиск · r перечитать · q выход"
                }
            }
        };
        frame.render_widget(Paragraph::new(help), parts[5]);
        match &mut self.mode {
            Mode::HostForm(form) => form.render(frame, modal(area)),
            Mode::PaymentForm(form) => form.render(frame, modal(area)),
            _ => {}
        }
        if let Mode::Detail { reveal, scroll } = self.mode {
            if let Some(host) = self.selected() {
                render_detail(frame, modal(area), host, reveal, scroll);
            }
        }
        if let Mode::Confirm { id, ssh } = self.mode {
            if let Some(host) = self.catalog.hosts.iter().find(|h| h.id == id) {
                let text = if ssh {
                    let config = host.ssh.as_ref().unwrap();
                    format!(
                        "Подключиться к {}?\nАдрес: {} · пользователь: {}\nВход: {}\nEnter — подключиться · Esc — отмена",
                        host.name,
                        config.host,
                        config.user.as_deref().unwrap_or("из OpenSSH config"),
                        if config
                            .password
                            .as_deref()
                            .is_some_and(|password| !password.is_empty())
                        {
                            "сохранённый пароль (password-only)"
                        } else {
                            "настройки OpenSSH / ssh-agent"
                        }
                    )
                } else {
                    format!(
                        "{} {}?\nЭто только учёт: услуга у хостера не отменяется.\nEnter — подтвердить · Esc — отмена",
                        if host.archived {
                            "Восстановить"
                        } else {
                            "Архивировать"
                        },
                        host.name
                    )
                };
                let popup = Rect::new(
                    area.x + 1,
                    area.y + area.height.saturating_sub(7) / 2,
                    area.width.saturating_sub(2),
                    area.height.min(7),
                );
                frame.render_widget(Clear, popup);
                frame.render_widget(
                    Paragraph::new(text)
                        .wrap(Wrap { trim: false })
                        .block(Block::bordered().title("Подтверждение")),
                    popup,
                );
            }
        }
    }
}

fn modal(area: Rect) -> Rect {
    Rect::new(
        area.x + 1,
        area.y + 1,
        area.width.saturating_sub(2),
        area.height.saturating_sub(3),
    )
}

fn ellipsize(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        value.to_owned()
    } else {
        value
            .chars()
            .take(width.saturating_sub(1))
            .chain(std::iter::once('…'))
            .collect()
    }
}

fn period_label(period: BillingPeriod, note: Option<&str>) -> &str {
    match period {
        BillingPeriod::Month => "мес",
        BillingPeriod::Quarter => "квартал",
        BillingPeriod::HalfYear => "полгода",
        BillingPeriod::Year => "год",
        BillingPeriod::Other => note.unwrap_or("другой"),
    }
}

fn render_detail(frame: &mut Frame, area: Rect, host: &Host, reveal: bool, scroll: u16) {
    fn secret(value: Option<&str>, reveal: bool) -> &str {
        if reveal {
            value.unwrap_or("—")
        } else if value.is_some() {
            "••••••••"
        } else {
            "—"
        }
    }
    let mut lines = vec![
        Line::from(vec![Span::raw("Имя: "), Span::raw(host.name.as_str())]),
        Line::from(vec![
            Span::raw("Провайдер: "),
            Span::raw(host.provider.as_str()),
        ]),
        Line::from(vec![
            Span::raw("Панель: "),
            Span::raw(host.panel_url.as_deref().unwrap_or("—")),
        ]),
        Line::from(vec![
            Span::raw("Логин панели: "),
            Span::raw(host.account_login.as_deref().unwrap_or("—")),
        ]),
        Line::from(vec![
            Span::raw("Пароль панели: "),
            Span::raw(secret(host.account_password.as_deref(), reveal)),
        ]),
    ];
    if let Some(ssh) = &host.ssh {
        lines.push(Line::from(format!(
            "SSH: {} · {} · порт {}",
            ssh.host,
            ssh.user.as_deref().unwrap_or("config"),
            ssh.port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "config".into())
        )));
        lines.push(Line::from(vec![
            Span::raw("Ключ: "),
            Span::raw(ssh.identity_file.as_deref().unwrap_or("из OpenSSH")),
        ]));
        lines.push(Line::from(vec![
            Span::raw("Пароль SSH (автовход): "),
            Span::raw(secret(ssh.password.as_deref(), reveal)),
        ]));
    } else {
        lines.push(Line::from("SSH-доступ не настроен"));
    }
    lines.push(Line::from(format!(
        "Тариф: {} {} / {}",
        model::money(host.billing.amount),
        host.billing.currency,
        period_label(host.billing.period, host.billing.period_note.as_deref())
    )));
    lines.push(Line::from(format!(
        "Следующая оплата: {}",
        host.billing
            .next_due
            .map(|d| d.to_string())
            .unwrap_or_else(|| "срок не задан".into())
    )));
    lines.push(Line::from("Заметки:"));
    lines.extend(host.notes.lines().map(Line::from));
    lines.push(Line::from("Журнал оплат:"));
    for payment in host.payments.iter().rev() {
        lines.push(Line::from(format!(
            "{} · {} {} · следующий срок {}",
            payment.paid_on,
            model::money(payment.amount),
            payment.currency,
            payment.next_due
        )));
    }
    if host.payments.is_empty() {
        lines.push(Line::from("Нет оплат"));
    }
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
            .block(Block::bordered().title("Карточка · v пароли · PgUp/PgDn · Esc закрыть")),
        area,
    );
}

fn text_area(value: &str, secret: bool) -> TextArea<'static> {
    let mut area = TextArea::new(value.split('\n').map(str::to_owned).collect());
    area.set_cursor_line_style(Style::default());
    area.set_tab_length(0);
    area.set_max_histories(0);
    if secret {
        area.set_mask_char('•');
    }
    area
}

fn line_input(area: &mut TextArea<'static>, key: KeyEvent, multiline: bool) {
    if let KeyCode::Char(c) = key.code {
        if c.is_control()
            || key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return;
        }
    }
    if !multiline && key.code == KeyCode::Enter {
        return;
    }
    // Keep cursor navigation, but reject character shortcuts that can insert hidden newlines.
    area.input(key);
}

enum FormAction {
    None,
    Save,
    Cancel,
}
type FieldError = (usize, String);

const HOST_LABELS: [&str; 16] = [
    "Сервер · Имя *",
    "Сервер · Провайдер *",
    "Сервер · URL панели",
    "Доступ · Логин панели",
    "Доступ · Пароль панели",
    "Сервер · Заметки (Enter — новая строка)",
    "Доступ · SSH host (пусто — SSH не задан)",
    "Доступ · SSH user",
    "Доступ · SSH port",
    "Доступ · Файл SSH-ключа (абсолютный путь или ~/)",
    "Доступ · Пароль SSH (автовход; пусто — ключи/agent)",
    "Оплата · Сумма *",
    "Оплата · Валюта *",
    "Оплата · Период (←/→)",
    "Оплата · Описание другого периода",
    "Оплата · Следующая дата YYYY-MM-DD",
];

struct HostForm {
    id: Uuid,
    editing: bool,
    archived: bool,
    fields: Vec<TextArea<'static>>,
    period: BillingPeriod,
    focus: usize,
    error: Option<FieldError>,
    field_areas: Vec<(Rect, usize)>,
}

impl HostForm {
    fn new(host: Option<&Host>) -> Self {
        let mut values = vec![String::new(); 16];
        values[11] = "0".into();
        values[12] = "EUR".into();
        let mut period = BillingPeriod::Month;
        if let Some(host) = host {
            values[0] = host.name.clone();
            values[1] = host.provider.clone();
            values[2] = host.panel_url.clone().unwrap_or_default();
            values[3] = host.account_login.clone().unwrap_or_default();
            values[4] = host.account_password.clone().unwrap_or_default();
            values[5] = host.notes.clone();
            if let Some(ssh) = &host.ssh {
                values[6] = ssh.host.clone();
                values[7] = ssh.user.clone().unwrap_or_default();
                values[8] = ssh.port.map(|p| p.to_string()).unwrap_or_default();
                values[9] = ssh.identity_file.clone().unwrap_or_default();
                values[10] = ssh.password.clone().unwrap_or_default();
            }
            values[11] = host.billing.amount.to_string();
            values[12] = host.billing.currency.clone();
            period = host.billing.period;
            values[14] = host.billing.period_note.clone().unwrap_or_default();
            values[15] = host
                .billing
                .next_due
                .map(|d| d.to_string())
                .unwrap_or_default();
        }
        let fields = values
            .into_iter()
            .enumerate()
            .map(|(i, value)| {
                let mut field = TextArea::new(value.split('\n').map(str::to_owned).collect());
                field.set_cursor_line_style(Style::default());
                field.set_max_histories(0);
                field.set_tab_length(0);
                if i == 4 || i == 10 {
                    field.set_mask_char('•');
                }
                field
            })
            .collect();
        Self {
            id: host.map(|h| h.id).unwrap_or_else(Uuid::new_v4),
            editing: host.is_some(),
            archived: host.is_some_and(|h| h.archived),
            fields,
            period,
            focus: 0,
            error: None,
            field_areas: Vec::new(),
        }
    }

    fn key(&mut self, key: KeyEvent) -> FormAction {
        let multiline = self.focus == 5;
        let action = form_navigation(key, &mut self.focus, 16, multiline);
        if !matches!(action, FormAction::None)
            || matches!(key.code, KeyCode::Tab | KeyCode::BackTab)
            || (key.code == KeyCode::Enter && !multiline)
        {
            return action;
        }
        if self.focus == 13 {
            let periods = [
                BillingPeriod::Month,
                BillingPeriod::Quarter,
                BillingPeriod::HalfYear,
                BillingPeriod::Year,
                BillingPeriod::Other,
            ];
            let index = periods.iter().position(|p| *p == self.period).unwrap();
            match key.code {
                KeyCode::Right | KeyCode::Char(' ') => self.period = periods[(index + 1) % 5],
                KeyCode::Left => self.period = periods[(index + 4) % 5],
                _ => {}
            }
        } else if let Some(field) = self.fields.get_mut(self.focus) {
            line_input(field, key, self.focus == 5);
        }
        FormAction::None
    }

    fn build(&self) -> std::result::Result<Host, FieldError> {
        let get = |i: usize| self.fields[i].lines()[0].as_str();
        let optional = |i: usize| {
            if get(i).is_empty() {
                None
            } else {
                Some(get(i).to_owned())
            }
        };
        for i in 0..16 {
            if i != 5 {
                model::validate_line(get(i))
                    .map_err(|_| (i, "Управляющие символы запрещены".into()))?;
            }
        }
        if get(0).trim().is_empty() {
            return Err((0, "Введите имя".into()));
        }
        if get(1).trim().is_empty() {
            return Err((1, "Введите провайдера".into()));
        }
        let notes = self.fields[5].lines().join("\n");
        if notes.chars().any(|c| c.is_control() && c != '\n') {
            return Err((
                5,
                "В заметках разрешены только текст и переносы строк".into(),
            ));
        }
        let ssh = if get(6).is_empty() {
            if (7..=10).any(|i| !get(i).is_empty()) {
                return Err((
                    6,
                    "Введите SSH host или очистите остальные реквизиты SSH".into(),
                ));
            }
            None
        } else {
            let port = if get(8).is_empty() {
                None
            } else {
                Some(
                    get(8)
                        .parse::<u16>()
                        .ok()
                        .filter(|p| *p != 0)
                        .ok_or_else(|| (8, "Порт должен быть от 1 до 65535".into()))?,
                )
            };
            let config = SshConfig {
                host: get(6).to_owned(),
                user: optional(7),
                port,
                identity_file: optional(9),
                password: optional(10),
            };
            ssh::validate_config(&config).map_err(|_| {
                (
                    6,
                    "Проверьте SSH host, user и существующий абсолютный путь ключа".into(),
                )
            })?;
            Some(config)
        };
        let amount = model::parse_amount(get(11))
            .map_err(|_| (11, "Введите неотрицательную точную десятичную сумму".into()))?;
        let currency =
            model::currency(get(12)).map_err(|_| (12, "Валюта: три ASCII-буквы".into()))?;
        let period_note = if self.period == BillingPeriod::Other {
            if get(14).trim().is_empty() {
                return Err((14, "Опишите период".into()));
            }
            optional(14)
        } else {
            None
        };
        let next_due = if get(15).is_empty() {
            None
        } else {
            Some(
                model::parse_date(get(15))
                    .map_err(|_| (15, "Дата должна быть YYYY-MM-DD".into()))?,
            )
        };
        Ok(Host {
            id: self.id,
            name: get(0).to_owned(),
            provider: get(1).to_owned(),
            panel_url: optional(2),
            account_login: optional(3),
            account_password: optional(4),
            notes,
            archived: self.archived,
            ssh,
            billing: Billing {
                amount,
                currency,
                period: self.period,
                period_note,
                next_due,
            },
            payments: Vec::new(),
        })
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        self.fields[13] = text_area(period_label(self.period, None), false);
        render_form(
            frame,
            area,
            if self.editing {
                "Изменить VPS"
            } else {
                "Добавить VPS"
            },
            &mut self.fields,
            &HOST_LABELS,
            self.focus,
            self.error.as_ref(),
            &mut self.field_areas,
        );
    }
}

struct PaymentForm {
    id: Uuid,
    fields: Vec<TextArea<'static>>,
    focus: usize,
    error: Option<FieldError>,
    field_areas: Vec<(Rect, usize)>,
}

impl PaymentForm {
    fn new(host: &Host) -> Self {
        Self {
            id: host.id,
            fields: vec![
                text_area(&host.billing.amount.to_string(), false),
                text_area(&host.billing.currency, false),
                text_area(&Local::now().date_naive().to_string(), false),
                text_area("", false),
            ],
            focus: 0,
            error: None,
            field_areas: Vec::new(),
        }
    }

    fn key(&mut self, key: KeyEvent) -> FormAction {
        let action = form_navigation(key, &mut self.focus, 4, false);
        if matches!(action, FormAction::None)
            && !matches!(key.code, KeyCode::Tab | KeyCode::BackTab | KeyCode::Enter)
        {
            if let Some(field) = self.fields.get_mut(self.focus) {
                line_input(field, key, false);
            }
        }
        action
    }

    fn build(&self, host: &Host) -> std::result::Result<Payment, FieldError> {
        let get = |i: usize| self.fields[i].lines()[0].as_str();
        let payment = Payment {
            amount: model::parse_amount(get(0)).map_err(|_| (0, "Некорректная сумма".into()))?,
            currency: model::currency(get(1)).map_err(|_| (1, "Валюта: три ASCII-буквы".into()))?,
            paid_on: model::parse_date(get(2))
                .map_err(|_| (2, "Дата должна быть YYYY-MM-DD".into()))?,
            next_due: model::parse_date(get(3))
                .map_err(|_| (3, "Явно введите следующую дату YYYY-MM-DD".into()))?,
        };
        if payment.paid_on > Local::now().date_naive() {
            return Err((2, "Дата оплаты не может быть в будущем".into()));
        }
        model::validate_payment(host, &payment, Local::now().date_naive()).map_err(|_| {
            (
                3,
                "Новый срок должен быть позже даты оплаты и прежнего срока".into(),
            )
        })?;
        Ok(payment)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        render_form(
            frame,
            area,
            "Оплачено · тариф не изменяется",
            &mut self.fields,
            &[
                "Фактическая сумма *",
                "Валюта *",
                "Дата оплаты YYYY-MM-DD *",
                "Следующая дата YYYY-MM-DD *",
            ],
            self.focus,
            self.error.as_ref(),
            &mut self.field_areas,
        );
    }
}

fn form_navigation(key: KeyEvent, focus: &mut usize, count: usize, multiline: bool) -> FormAction {
    if key.code == KeyCode::Esc {
        return FormAction::Cancel;
    }
    if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return FormAction::Save;
    }
    match key.code {
        KeyCode::Tab => *focus = (*focus + 1) % (count + 2),
        KeyCode::BackTab => *focus = (*focus + count + 1) % (count + 2),
        KeyCode::Enter if *focus == count => return FormAction::Save,
        KeyCode::Enter if *focus == count + 1 => return FormAction::Cancel,
        KeyCode::Enter if !multiline => *focus = (*focus + 1).min(count + 1),
        _ => {}
    }
    FormAction::None
}

fn render_form(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    fields: &mut [TextArea<'static>],
    labels: &[&str],
    focus: usize,
    error: Option<&FieldError>,
    field_areas: &mut Vec<(Rect, usize)>,
) {
    field_areas.clear();
    frame.render_widget(Clear, area);
    frame.render_widget(Block::bordered().title(title), area);
    let inner = Rect::new(
        area.x + 1,
        area.y + 1,
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    );
    let field_count = fields.len();
    let capacity = (inner.height.saturating_sub(3) / 3).max(1) as usize;
    let first = focus
        .saturating_sub(capacity - 1)
        .min(field_count.saturating_sub(capacity));
    let visible = capacity.min(field_count - first);
    for (slot, index) in (first..first + visible).enumerate() {
        let rect = Rect::new(
            inner.x,
            inner.y + slot as u16 * 3,
            inner.width,
            3.min(inner.height),
        );
        field_areas.push((rect.intersection(inner), index));
        let label = if let Some((field, message)) = error.filter(|(field, _)| *field == index) {
            let _ = field;
            format!("{} · {}", labels[index], message)
        } else {
            labels[index].to_owned()
        };
        fields[index].set_block(
            Block::bordered()
                .title(label)
                .border_style(if index == focus {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                }),
        );
        frame.render_widget(&fields[index], rect);
    }
    let buttons = Rect::new(
        inner.x,
        inner.y + inner.height.saturating_sub(2),
        inner.width,
        inner.height.min(2),
    );
    let style = |active| {
        if active {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        }
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("[ Сохранить ]", style(focus == field_count)),
                Span::raw("   "),
                Span::styled("[ Отмена ]", style(focus == field_count + 1)),
            ]),
            Line::from(format!(
                "Поле {}/{} · Tab/Shift+Tab · Ctrl+S",
                (focus + 1).min(field_count),
                field_count
            )),
        ]),
        buttons,
    );
}
