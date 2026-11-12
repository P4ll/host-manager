use std::{
    io::{self, IsTerminal, Stdout},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use chrono::Local;
use crossterm::{
    cursor::Show,
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
        Event,
    },
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use signal_hook::consts::SIGINT;

use crate::app::App;

pub struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalSession {
    pub fn new() -> Result<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            bail!("TUI требует интерактивный терминал; используйте host-manager connect NAME");
        }
        let terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        let mut session = Self { terminal };
        terminal::enable_raw_mode()?;
        execute!(
            session.terminal.backend_mut(),
            EnterAlternateScreen,
            EnableBracketedPaste,
            EnableMouseCapture
        )?;
        session.terminal.clear()?;
        Ok(session)
    }

    pub fn with_external_terminal<T>(&mut self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.terminal.show_cursor()?;
        execute!(
            self.terminal.backend_mut(),
            DisableBracketedPaste,
            DisableMouseCapture,
            LeaveAlternateScreen
        )?;
        terminal::disable_raw_mode()?;
        let result = f();
        terminal::enable_raw_mode().context("Не удалось восстановить raw mode")?;
        execute!(
            self.terminal.backend_mut(),
            EnterAlternateScreen,
            EnableBracketedPaste,
            EnableMouseCapture
        )
        .context("Не удалось восстановить экран терминала")?;
        self.terminal
            .clear()
            .context("Не удалось восстановить буфер терминала")?;
        result
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            DisableBracketedPaste,
            DisableMouseCapture,
            LeaveAlternateScreen,
            Show
        );
    }
}

pub fn run(app: &mut App) -> Result<()> {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            DisableBracketedPaste,
            DisableMouseCapture,
            LeaveAlternateScreen,
            Show
        );
        original_hook(info);
    }));
    let interrupted = Arc::new(AtomicBool::new(false));
    let signal = signal_hook::flag::register(SIGINT, Arc::clone(&interrupted))?;
    let result = event_loop(app, &interrupted);
    signal_hook::low_level::unregister(signal);
    result
}

fn event_loop(app: &mut App, interrupted: &AtomicBool) -> Result<()> {
    let mut terminal = TerminalSession::new()?;
    let mut dirty = true;
    let mut date = Local::now().date_naive();
    while !app.should_quit && !interrupted.load(Ordering::Relaxed) {
        let today = Local::now().date_naive();
        if today != date {
            date = today;
            dirty = true;
        }
        if dirty {
            terminal.terminal.draw(|frame| app.render(frame))?;
            dirty = false;
        }
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) => {
                match app.handle_key(key) {
                    Ok(Some(effect)) => {
                        let result = terminal.with_external_terminal(|| Ok(app.perform(effect)))?;
                        interrupted.store(false, Ordering::Relaxed);
                        if let Err(error) = result {
                            app.set_message(format!("{error:#}"));
                        }
                    }
                    Ok(None) => {}
                    Err(error) => app.set_message(format!("{error:#}")),
                }
                dirty = true;
            }
            Event::Paste(text) => {
                app.handle_paste(&text);
                dirty = true;
            }
            Event::Mouse(event) => dirty |= app.handle_mouse(event),
            Event::Resize(_, _) => dirty = true,
            _ => {}
        }
    }
    Ok(())
}
