mod common;

use chrono::{Days, Local};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use host_manager::{
    app::{App, Effect},
    model,
    store::PassStore,
};
use ratatui::{Terminal, backend::TestBackend};
use rust_decimal::Decimal;

fn key(app: &mut App, code: KeyCode) {
    if let Some(effect) = app
        .handle_key(KeyEvent::new(code, KeyModifiers::NONE))
        .unwrap()
    {
        app.perform(effect).unwrap();
    }
}

fn input(app: &mut App, value: &str) {
    for ch in value.chars() {
        key(app, KeyCode::Char(ch));
    }
}

fn replace(app: &mut App, value: &str) {
    key(app, KeyCode::Home);
    for _ in 0..80 {
        key(app, KeyCode::Delete);
    }
    input(app, value);
}

fn save(app: &mut App) {
    let effect = app
        .handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL))
        .unwrap()
        .expect("save effect");
    assert!(matches!(effect, Effect::Save));
    app.perform(effect).unwrap();
}

fn screen(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn real_forms_payment_cancel_archive_and_restart() {
    let fixture = common::Fixture::new();
    let mut app = App::new(PassStore::open(&fixture.dir, fixture.env.clone()).unwrap()).unwrap();
    assert!(screen(&mut app, 80, 24).contains("Нет VPS"));
    key(&mut app, KeyCode::Char('a'));
    input(&mut app, "Сервер ёж");
    key(&mut app, KeyCode::Tab);
    input(&mut app, "Хостер");
    for _ in 0..3 {
        key(&mut app, KeyCode::Tab);
    }
    input(&mut app, "PRIVATE-PANEL-PASSWORD");
    assert!(!screen(&mut app, 80, 24).contains("PRIVATE-PANEL-PASSWORD"));
    assert!(screen(&mut app, 80, 24).contains("Сохранить"));
    for _ in 0..7 {
        key(&mut app, KeyCode::Tab);
    }
    replace(&mut app, "5.00");
    for _ in 0..4 {
        key(&mut app, KeyCode::Tab);
    }
    let today = Local::now().date_naive();
    input(&mut app, &today.to_string());
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.catalog().hosts.len(), 1);
    assert_eq!(app.catalog().hosts[0].name, "Сервер ёж");
    assert_eq!(app.catalog().hosts[0].billing.amount, Decimal::new(500, 2));
    assert!(screen(&mut app, 80, 24).contains("Сегодня"));
    key(&mut app, KeyCode::Enter);
    assert!(!screen(&mut app, 120, 40).contains("PRIVATE-PANEL-PASSWORD"));
    key(&mut app, KeyCode::Char('v'));
    assert!(screen(&mut app, 120, 40).contains("PRIVATE-PANEL-PASSWORD"));
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Enter);
    assert!(!screen(&mut app, 120, 40).contains("PRIVATE-PANEL-PASSWORD"));
    key(&mut app, KeyCode::Esc);
    let before = common::ciphertexts(&fixture.dir);
    key(&mut app, KeyCode::Char('p'));
    replace(&mut app, "4.50");
    key(&mut app, KeyCode::Esc);
    assert_eq!(common::ciphertexts(&fixture.dir), before);
    key(&mut app, KeyCode::Char('p'));
    replace(&mut app, "4.50");
    for _ in 0..3 {
        key(&mut app, KeyCode::Tab);
    }
    save(&mut app);
    assert_eq!(
        app.catalog().hosts[0].payments.len(),
        0,
        "explicit next date is mandatory"
    );
    let next = today.checked_add_days(Days::new(30)).unwrap();
    input(&mut app, &next.to_string());
    save(&mut app);
    assert_eq!(app.catalog().hosts[0].payments.len(), 1);
    assert_eq!(
        app.catalog().hosts[0].payments[0].amount,
        Decimal::new(450, 2)
    );
    assert_eq!(app.catalog().hosts[0].billing.amount, Decimal::new(500, 2));
    key(&mut app, KeyCode::Char('e'));
    replace(&mut app, "Сервер после оплаты");
    save(&mut app);
    assert_eq!(
        app.catalog().hosts[0].payments.len(),
        1,
        "editing preserves history"
    );
    key(&mut app, KeyCode::Char('/'));
    input(&mut app, "нет такого");
    key(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 80, 24).contains("Нет VPS"));
    key(&mut app, KeyCode::Char('/'));
    replace(&mut app, "Хостер");
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Char('x'));
    key(&mut app, KeyCode::Enter);
    assert!(app.catalog().hosts[0].archived);
    assert!(
        model::summary(app.catalog(), today)
            .unwrap()
            .monthly
            .is_empty()
    );
    key(&mut app, KeyCode::Tab);
    assert!(!screen(&mut app, 80, 24).contains("Нет VPS"));
    drop(app);
    let app = App::new(PassStore::open(&fixture.dir, fixture.env.clone()).unwrap()).unwrap();
    let host = &app.catalog().hosts[0];
    assert_eq!(host.billing.next_due, Some(next));
    assert_eq!(host.payments.len(), 1);
    assert_eq!(host.payments[0].amount, Decimal::new(450, 2));
    assert_eq!(
        host.account_password.as_deref(),
        Some("PRIVATE-PANEL-PASSWORD")
    );
}

#[test]
fn pasted_commands_and_newlines_do_not_escape_fields() {
    let fixture = common::Fixture::new();
    let mut app = App::new(PassStore::open(&fixture.dir, fixture.env.clone()).unwrap()).unwrap();
    app.handle_paste("a");
    assert!(screen(&mut app, 80, 24).contains("Нет VPS"));
    key(&mut app, KeyCode::Char('a'));
    app.handle_paste("bad\nname");
    input(&mut app, "Имя");
    key(&mut app, KeyCode::Tab);
    input(&mut app, "Провайдер");
    save(&mut app);
    assert_eq!(app.catalog().hosts[0].name, "Имя");
    key(&mut app, KeyCode::Char('e'));
    for _ in 0..17 {
        key(&mut app, KeyCode::Tab);
    }
    assert!(screen(&mut app, 80, 24).contains("Отмена"));
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.catalog().hosts.len(), 1);
}

fn field_position(app: &mut App, width: u16, height: u16, label: &str) -> (u16, u16) {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    let buffer = terminal.backend().buffer();
    let row = (0..height)
        .find(|row| {
            (0..width)
                .map(|column| buffer[(column, *row)].symbol())
                .collect::<String>()
                .contains(label)
        })
        .expect("field label is visible");
    (3, row + 1)
}

fn mouse(app: &mut App, kind: MouseEventKind, (column, row): (u16, u16)) -> bool {
    app.handle_mouse(MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    })
}

#[test]
fn mouse_focus_and_wheel_edit_the_clicked_fields_after_scrolling_and_resize() {
    let fixture = common::Fixture::new();
    let mut app = App::new(PassStore::open(&fixture.dir, fixture.env.clone()).unwrap()).unwrap();
    let click = MouseEventKind::Down(MouseButton::Left);
    let today = Local::now().date_naive();
    let due = today.checked_add_days(Days::new(30)).unwrap();
    let next = today.checked_add_days(Days::new(60)).unwrap();
    assert!(!mouse(&mut app, click, (3, 6)));
    for (width, height) in [(80, 24), (120, 40)] {
        key(&mut app, KeyCode::Char('a'));
        let position = field_position(&mut app, width, height, "Провайдер");
        assert!(!mouse(
            &mut app,
            MouseEventKind::Down(MouseButton::Right),
            position
        ));
        assert!(mouse(&mut app, click, position));
        assert!(!mouse(&mut app, click, (0, 0)));
        input(&mut app, "Мышиный хостер");
        let position = field_position(&mut app, width, height, "Сервер · Имя");
        assert!(mouse(&mut app, click, position));
        let name = format!("Мышь {width}");
        input(&mut app, &name);
        let position = field_position(&mut app, width, height, "Пароль панели");
        assert!(mouse(&mut app, click, position));
        input(&mut app, "MOUSE-SECRET");
        assert!(!screen(&mut app, width, height).contains("MOUSE-SECRET"));
        for _ in 0..16 {
            mouse(&mut app, MouseEventKind::ScrollDown, position);
            screen(&mut app, width, height);
        }
        let position = field_position(&mut app, width, height, "Следующая дата");
        mouse(&mut app, click, position);
        input(&mut app, &due.to_string());
        let position = field_position(&mut app, width, height, "Валюта");
        assert!(mouse(&mut app, click, position));
        replace(&mut app, "rub");
        let position = field_position(&mut app, width, height, "Сумма");
        assert!(mouse(&mut app, click, position));
        replace(&mut app, "5.25");
        mouse(&mut app, MouseEventKind::ScrollUp, position);
        // Recompute hit regions on resize; old row positions must not select another field.
        let position = field_position(&mut app, 120, 40, "Провайдер");
        assert!(mouse(&mut app, click, position));
        replace(&mut app, "Хостер после resize");
        save(&mut app);
        let host = app
            .catalog()
            .hosts
            .iter()
            .find(|host| host.name == name)
            .unwrap();
        assert_eq!(host.provider, "Хостер после resize");
        assert_eq!(host.billing.amount, Decimal::new(525, 2));
        assert_eq!(host.billing.currency, "RUB");
        assert_eq!(host.billing.next_due, Some(due));
        assert_eq!(host.account_password.as_deref(), Some("MOUSE-SECRET"));

        key(&mut app, KeyCode::Char('p'));
        let position = field_position(&mut app, width, height, "Следующая дата");
        assert!(mouse(&mut app, click, position));
        input(&mut app, &next.to_string());
        let position = field_position(&mut app, width, height, "Фактическая сумма");
        assert!(mouse(&mut app, click, position));
        replace(&mut app, "4.50");
        let position = field_position(&mut app, width, height, "Валюта");
        assert!(mouse(&mut app, click, position));
        replace(&mut app, "USD");
        save(&mut app);
        let host = app
            .catalog()
            .hosts
            .iter()
            .find(|host| host.name == name)
            .unwrap();
        assert_eq!(host.billing.amount, Decimal::new(525, 2));
        assert_eq!(host.payments[0].amount, Decimal::new(450, 2));
        assert_eq!(host.payments[0].currency, "USD");
        assert_eq!(host.billing.next_due, Some(next));
        assert!(!mouse(&mut app, click, position));
    }
}
