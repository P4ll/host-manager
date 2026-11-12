# host-manager

[Russian documentation](docs/README.ru.md)

A terminal app for keeping track of your VPS: where they're hosted, what they cost, when payment is due, and how to log in.

It keeps the catalog in your existing [pass](https://www.passwordstore.org/) store and uses OpenSSH for connections. Server details, credentials, and payment history are encrypted together. There is no separate database or set of keys to manage.

The interface is currently in Russian. The app runs on macOS and Linux.

## Install

You'll need `pass`, GPG, Git, and OpenSSH in your PATH, plus Rust stable 1.91 or newer to build. Your password-store must already have encryption recipients configured and be in a Git repository. host-manager won't initialize it or change your keys, Git settings, or shell configuration.

From the project directory:

```sh
cargo +stable install --path . --locked
```

Cargo installs the binary in `~/.cargo/bin` by default. With that directory in your PATH, you can run it from anywhere:

```sh
host-manager
```

To run from source instead:

```sh
cargo +stable run
cargo +stable run -- connect example-vps
```

### Updating

Update your local source code, close any running TUI, and reinstall:

```sh
cargo +stable install --path . --locked --force
```

This replaces the binary, not your data in pass. There is no automatic updater. Using `+stable` also leaves your default Rust toolchain alone.

## Choose a pass directory

The default is `host-manager` inside your password-store: usually `~/.password-store/host-manager`, or `$PASSWORD_STORE_DIR/host-manager` if you've set a different root.

To choose another directory for one command:

```sh
host-manager --pass-dir "$HOME/.password-store/infrastructure"
```

For regular use, set `HOST_MANAGER_PASS_DIR` in your shell:

```sh
export HOST_MANAGER_PASS_DIR="$HOME/.password-store/infrastructure"
host-manager
```

`--pass-dir` takes precedence over the environment variable and works before or after the subcommand's arguments. Both take a filesystem path, not a pass entry name. An explicitly empty value is an error.

The directory must be strictly inside the pass root. Paths containing `..` or symlinks within the selected path are rejected. A missing directory is created on the first save; neighboring pass entries are left alone. Encryption recipients follow normal pass rules, including a nested `.gpg-id`. There's no additional configuration file.

For a separate password-store, set its root too:

```sh
PASSWORD_STORE_DIR=/path/to/store host-manager --pass-dir /path/to/store/host-manager
```

## In the TUI

The main screen lists your servers and shows costs by currency. Search matches the server name, provider, or SSH host. Open a server to see its credentials, notes, and payment history.

| Key | Action |
| --- | --- |
| `↑↓` | Select a server |
| `Enter` | Open its details |
| `/` | Search; `Enter` or `Esc` finishes the query |
| `a` / `e` | Add / edit |
| `p` | Record a payment |
| `s` | Connect over SSH, after confirmation |
| `x` | Archive or restore, after confirmation |
| `Tab` / `Shift+Tab` | Switch between active and archived servers |
| `r` | Reload the catalog |
| `q` / `Ctrl+C` | Quit |

In a form, use `Tab` and `Shift+Tab` to move between fields and buttons, or click a field. The mouse wheel moves between fields and brings hidden ones into view on smaller terminals, including 80×24. Use `←→` to change the billing period, `Ctrl+S` or the Save button to save, and `Esc` to cancel. Notes can span multiple lines.

In the details view, `v` shows or hides passwords and `PageUp`/`PageDown` scrolls. Closing the view hides passwords again. Panel URLs are text only; the app doesn't open a browser or copy credentials to the clipboard.

### Costs and payments

Enter amounts with a decimal point or one decimal comma, without thousands separators. Currency codes are three ASCII letters, and dates use `YYYY-MM-DD`.

Recording a payment adds a history entry and updates the next due date; it doesn't change the pricing plan. You must enter the next due date yourself. It has to be later than both the payment date and the old due date. Canceling the form writes nothing.

The monthly estimate divides each plan amount by 1, 3, 6, or 12 for monthly, quarterly, half-yearly, or yearly billing. Other periods are shown as excluded from the estimate. Upcoming payments count one due date per active VPS in the next 30 days, including today; overdue amounts are shown separately. Currencies aren't combined or converted. Amounts use checked Decimal arithmetic and are rounded to two places for display after summation.

Archiving keeps the server's credentials and history but removes it from cost summaries. It does **not** cancel anything with the hosting provider.

## Connect without opening the TUI

```sh
host-manager connect example-vps
host-manager connect "prod eu"
```

The name must match exactly, including case, and identify one active server. Archived entries aren't connected to. Duplicate display names are allowed in the catalog, but you'll need to rename them if more than one active entry matches.

This opens an SSH session without another application-level confirmation. `connect` hands over the terminal to SSH, so its exit status and signals go straight back to your shell. It doesn't write to the catalog and works while the TUI is open.

Use an address or SSH alias for the host, not `user@host` or a URL. Whitespace and a leading `-` are rejected. Leave user and port unset to use your OpenSSH config. A saved identity path must be an absolute path or start with `~/` and point to an existing regular file; the private key itself is never imported.

If `ssh.password` is empty or `null`, SSH uses your usual config, keys, and agent. If you've saved a password, both `connect` and the TUI use [SSH_ASKPASS](https://man.openbsd.org/ssh#SSH_ASKPASS_REQUIRE) to supply it. This is a password-only connection with one attempt: public-key and keyboard-interactive authentication are disabled for that connection. Clear the saved password to use keys, an agent, or keyboard-interactive/2FA instead. Saved passwords longer than 1,023 UTF-8 bytes cannot be used with askpass.

The password is read from pass by a helper bound to that SSH process and server entry. It isn't put in arguments, environment variables, or temporary files. Other prompts, including host-key confirmation and password changes, stay manual; a jump host does not receive the destination's saved password. The helper may need GPG/pinentry to unlock the catalog again.

Manual jump-host prompts also use the system `/bin/ps` utility to find the controlling terminal.

Host-key checking stays enabled in saved-password mode: a new key needs your confirmation, and a changed key is rejected. The app doesn't enable agent forwarding. Extra SSH options and remote commands aren't accepted after the server name; `--` ends application option parsing.

When you connect from the TUI, it releases the terminal and resumes when SSH exits. The same happens for pass/pinentry prompts. Raw mode and mouse capture are disabled while those programs run, and mouse capture is also disabled on exit.

## Import from a file

If you'd rather fill in server details in an editor, start with a template:

```sh
host-manager template vps.json
# Fill in vps.json in your editor, then:
host-manager import vps.json
```

The template is UTF-8 JSON with one server and a generated UUID. Creating it doesn't need pass or a configured store. The file gets `0600` permissions, and the command refuses to overwrite an existing file or symlink.

Fill in these fields:

- `name` and `provider`.
- `billing.amount`, as a string such as `"5.00"`, and `billing.currency`.
- `billing.next_due`, as a date such as `"2026-12-01"`, or `null` if you don't know it yet.
- `ssh.host`, or replace the whole SSH object with `"ssh": null` if you don't need it.

Keep all the keys in the document. Optional credentials can stay `null`; notes are a string and an empty payment history is `[]`. Billing `period` accepts `month`, `quarter`, `half_year`, `year`, or `other`. For `other`, fill in `period_note`; otherwise leave it `null`.

Leave `version` and the generated `id` alone. To import several servers at once, create separate templates and combine their server objects in one `hosts` array, keeping a different UUID for each.

Import only adds entries. It doesn't replace existing servers or their history. The whole file is checked before anything is saved; unknown fields, invalid dates or amounts, an empty list, or an existing UUID will stop the import. Importing the same file again is therefore an error, not an update.

Close the editing TUI before importing. Imports use the same lock and save checks as the TUI. You can choose another pass directory as usual:

```sh
host-manager --pass-dir "$HOME/.password-store/infrastructure" import vps.json
```

**The completed JSON file is not encrypted.** That includes any passwords and financial details you put in it. Keep it out of your password-store and Git repositories, and delete it yourself after a confirmed import. The app doesn't print its contents or remove the source file. File permissions aren't a substitute for encryption.

## Storage and recovery

The catalog is version 1 JSON stored as `<directory>/catalog.gpg`. A bad decryption, unsupported version, unknown field, or invalid value is an error, never an empty catalog to overwrite.

Saves go through `catalog.pending.gpg` first: pass encrypts it, the app checks its decrypted contents, then pass moves it over the main catalog and the app checks the result. Before writing, it checks that the original ciphertext hasn't changed and that Git has no staged changes. pass makes the commits; host-manager doesn't push or pull.

If you see a warning that the data was saved but pass/Git reported an error, check Git. **Don't record the payment or import the file again.** A failed Git hook can leave changes staged even when the catalog was saved successfully.

If a save result is uncertain, check the catalog and pending entry before retrying. Further writes are blocked until a successful reload.

### A pending file was left behind

With `catalog.pending.gpg` present, the main catalog stays readable but new saves are blocked. Don't just delete pending: compare the entries using pass and decide which version to keep. Pending without a main catalog also needs manual recovery; it isn't treated as a new empty store.

Once you've resolved it, cancel any unfinished form and press `r` to reload.

### Another process is editing the catalog

Only one editing instance can open a directory at a time. Its OS lock lives at `${XDG_CACHE_HOME:-~/.cache}/host-manager/<sha256-of-path>.lock` and is released automatically after a crash. Read-only `connect` doesn't take this lock.

Don't edit the catalog through pass or Git while the app is saving. The hash checks catch external changes, but they aren't a transaction shared with other programs. Git conflicts need to be resolved manually.

### What encryption does and doesn't cover

There are no plaintext catalog files, separate database, or unencrypted cache. The import file described above is the exception: you create it explicitly and need to delete it yourself. Decrypted data is present in memory and on screens you open; the app doesn't promise to wipe memory securely.

Filenames, `.gpg-id`, and Git metadata remain visible. Older encrypted versions stay in Git history. Backups and key rotation are handled outside the app with pass/GPG.

## Development

```sh
cargo +stable test --locked
cargo +stable build --release --locked
./target/release/host-manager
```

The tests use real pass, GPG, and Git with temporary stores and keys, not your personal password-store. They cover billing calculations, storage failures and conflicts, imports, SSH arguments, CLI behavior, and forms rendered with Ratatui's TestBackend. Missing system tools fail the tests rather than silently skipping the checks.

The password-login integration test also needs Docker and `expect`. Start Docker first, then run:

```sh
cargo +stable test --locked --test askpass real_password_sessions -- --ignored --nocapture
```

It creates a disposable loopback OpenSSH server and a test account inside a container, then removes them. It checks password login, key-based login without a saved password, host-key rejection, a wrong password, and jump-host isolation. The default test run leaves this Docker-dependent test ignored.

Live terminal, pinentry, and loopback SSH checks have been run on macOS. Linux hasn't been checked interactively.

If Cargo can't find `rustc` because the Rust proxies aren't in PATH, you can use the installed toolchain directly for a command:

```sh
PATH="$(dirname "$(rustup which --toolchain stable rustc)"):$PATH" \
  rustup run stable cargo build --release --locked
```
