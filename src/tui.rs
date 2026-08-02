use std::{
    collections::BTreeSet,
    io::{self, IsTerminal},
    time::Duration,
};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use unicode_width::UnicodeWidthStr;

use crate::{
    cli::{CommonOptions, build_removal_plan},
    model::{InstallationRecord, ManagerKind, Snapshot},
    output::{self, SortField, SortOrder},
    removal, scanner,
    state::StateStore,
};

const SORT_FIELDS: [SortField; 7] = [
    SortField::Name,
    SortField::Manager,
    SortField::Environment,
    SortField::Version,
    SortField::Size,
    SortField::KnownSince,
    SortField::Findings,
];
pub(crate) fn run(
    snapshot: Snapshot,
    common_options: CommonOptions,
    mut store: Option<StateStore>,
    default_sort: SortField,
    default_order: SortOrder,
) -> Result<u8> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        anyhow::bail!("TUI requires an interactive terminal; use `pkgscope list` for piped output");
    }
    let _restore = RestoreTerminal;
    let mut terminal = start_terminal()?;
    let mut app = App::new(snapshot, default_sort, default_order);
    loop {
        terminal.draw(|frame| draw(frame, &mut app))?;
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            break;
        }
        if app.searching {
            handle_search_key(&mut app, key);
            continue;
        }
        match app.screen {
            Screen::List => match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
                KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
                KeyCode::Home | KeyCode::Char('g') => app.selection = 0,
                KeyCode::End | KeyCode::Char('G') => {
                    app.selection = app.visible_ids().len().saturating_sub(1)
                }
                KeyCode::Left => app.cycle_sort(-1),
                KeyCode::Right => app.cycle_sort(1),
                KeyCode::Char('s') => {
                    app.order = if app.order == SortOrder::Asc {
                        SortOrder::Desc
                    } else {
                        SortOrder::Asc
                    };
                    app.status = format!(
                        "Direction: {}",
                        if app.order == SortOrder::Asc {
                            "↑ ASCENDING"
                        } else {
                            "↓ DESCENDING"
                        }
                    );
                }
                KeyCode::Enter => {
                    if app.selected_record().is_some() {
                        app.screen = Screen::Detail;
                        app.detail_scroll = 0;
                    }
                }
                KeyCode::Char(' ') => app.toggle_selected(),
                KeyCode::Char('/') => {
                    app.searching = true;
                    app.status =
                        "Search package, command, manager, environment, path, or finding".into();
                }
                KeyCode::Char('x') => {
                    app.query.clear();
                    app.selection = 0;
                    app.status = "Search cleared".into();
                }
                KeyCode::Char('?') => {
                    app.help_from = Screen::List;
                    app.screen = Screen::Help;
                }
                KeyCode::Char('r') => {
                    suspend_terminal()?;
                    eprintln!("Rescanning supported manager instances…");
                    let mut snapshot = scanner::scan(&crate::cli::scan_options(&common_options));
                    if crate::process::cancel_requested() {
                        eprintln!("Rescan cancelled.");
                        crate::process::clear_cancel();
                        break;
                    }
                    if let Some(store) = store.as_mut()
                        && let Err(error) = store.save(&mut snapshot)
                    {
                        eprintln!(
                            "warning: snapshot could not be saved: {}",
                            crate::sanitize::terminal_text(&format!("{error:#}"))
                        );
                    }
                    crate::cli::filter_snapshot(&mut snapshot, &common_options);
                    resume_terminal()?;
                    terminal.clear()?;
                    app.snapshot = snapshot;
                    app.selection = 0;
                    app.status = "Rescan complete".into();
                }
                _ => {}
            },
            Screen::Detail => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => app.screen = Screen::List,
                KeyCode::Up | KeyCode::Char('k') => {
                    app.detail_scroll = app.detail_scroll.saturating_sub(1)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    app.detail_scroll = app.detail_scroll.saturating_add(1)
                }
                KeyCode::PageUp => app.detail_scroll = app.detail_scroll.saturating_sub(10),
                KeyCode::PageDown => app.detail_scroll = app.detail_scroll.saturating_add(10),
                KeyCode::Home | KeyCode::Char('g') => app.detail_scroll = 0,
                KeyCode::End | KeyCode::Char('G') => app.detail_scroll = u16::MAX,
                KeyCode::Char('u') => {
                    app.confirm_input.clear();
                    app.confirm_error = None;
                    app.screen = Screen::ConfirmUninstall;
                }
                KeyCode::Char('?') => {
                    app.help_from = Screen::Detail;
                    app.screen = Screen::Help;
                }
                _ => {}
            },
            Screen::Help => match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => app.screen = app.help_from,
                _ => {}
            },
            Screen::ConfirmUninstall => match key.code {
                KeyCode::Esc => {
                    app.confirm_input.clear();
                    app.confirm_error = None;
                    app.screen = Screen::Detail;
                }
                KeyCode::Backspace => {
                    app.confirm_input.pop();
                    app.confirm_error = None;
                }
                KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.confirm_input.push(ch);
                    app.confirm_error = None;
                }
                KeyCode::Enter => {
                    let Some(record) = app.selected_record().cloned() else {
                        app.confirm_error = Some("The selected installation disappeared.".into());
                        continue;
                    };
                    if app.confirm_input != record.identity.name {
                        app.confirm_error = Some(format!(
                            "Confirmation does not match {:?}; nothing was executed.",
                            record.identity.name
                        ));
                        continue;
                    }
                    let plan = match build_removal_plan(&app.snapshot, &record) {
                        Ok(plan) => plan,
                        Err(error) => {
                            app.confirm_error = Some(format!("Removal unavailable: {error}"));
                            continue;
                        }
                    };
                    let Some(manager_kind) = output::manager_for(&app.snapshot, &record)
                        .map(|instance| instance.manager)
                    else {
                        app.confirm_error = Some("The owning manager instance disappeared.".into());
                        continue;
                    };
                    suspend_terminal()?;
                    eprintln!(
                        "Revalidating {} before uninstall…",
                        crate::sanitize::terminal_text(&record.identity.name)
                    );
                    let result = perform_uninstall(&record, &plan, manager_kind, &common_options);
                    resume_terminal()?;
                    terminal.clear()?;
                    match result {
                        Ok((mut snapshot, command_summary)) => {
                            if let Some(store) = store.as_mut()
                                && let Err(error) = store.save(&mut snapshot)
                            {
                                app.status = format!(
                                    "Uninstalled, but snapshot save failed: {}",
                                    crate::sanitize::terminal_text(&format!("{error:#}"))
                                );
                            } else {
                                app.status = format!("Uninstalled: {command_summary}");
                            }
                            crate::cli::filter_snapshot(&mut snapshot, &common_options);
                            app.snapshot = snapshot;
                            app.selection =
                                app.selection.min(app.visible_ids().len().saturating_sub(1));
                            app.confirm_input.clear();
                            app.confirm_error = None;
                            app.screen = Screen::List;
                        }
                        Err(error) => {
                            app.confirm_input.clear();
                            app.confirm_error =
                                Some(crate::sanitize::terminal_text(&format!("{error:#}")));
                        }
                    }
                }
                _ => {}
            },
        }
    }
    let code = if app.snapshot.partial { 3 } else { 0 };
    Ok(code)
}

type TuiTerminal = Terminal<CrosstermBackend<io::Stdout>>;

fn start_terminal() -> Result<TuiTerminal> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn suspend_terminal() -> Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

fn resume_terminal() -> Result<()> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    Ok(())
}

struct RestoreTerminal;

impl Drop for RestoreTerminal {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    List,
    Detail,
    Help,
    ConfirmUninstall,
}

struct App {
    snapshot: Snapshot,
    screen: Screen,
    selection: usize,
    selected: BTreeSet<String>,
    sort_index: usize,
    order: SortOrder,
    query: String,
    searching: bool,
    detail_scroll: u16,
    help_from: Screen,
    confirm_input: String,
    confirm_error: Option<String>,
    status: String,
}

impl App {
    fn new(snapshot: Snapshot, default_sort: SortField, default_order: SortOrder) -> Self {
        let sort_index = SORT_FIELDS
            .iter()
            .position(|field| *field == default_sort)
            .unwrap_or(0);
        Self {
            snapshot,
            screen: Screen::List,
            selection: 0,
            selected: BTreeSet::new(),
            sort_index,
            order: default_order,
            query: String::new(),
            searching: false,
            detail_scroll: 0,
            help_from: Screen::List,
            confirm_input: String::new(),
            confirm_error: None,
            status: String::new(),
        }
    }

    fn visible_ids(&self) -> Vec<String> {
        let query = self.query.to_ascii_lowercase();
        let mut records: Vec<_> = self
            .snapshot
            .installations
            .iter()
            .filter(|record| query.is_empty() || self.matches_query(record, &query))
            .collect();
        output::sort_records(
            &mut records,
            SORT_FIELDS[self.sort_index],
            self.order,
            &self.snapshot,
        );
        records
            .into_iter()
            .map(|record| record.id.clone())
            .collect()
    }

    fn matches_query(&self, record: &InstallationRecord, query: &str) -> bool {
        let base = format!(
            "{} {} {} {} {}",
            record.identity.name,
            record.identity.ecosystem,
            record.environment,
            record.paths.install_root.as_deref().unwrap_or_default(),
            output::manager_for(&self.snapshot, record)
                .map(|instance| instance.manager.to_string())
                .unwrap_or_default()
        )
        .to_ascii_lowercase();
        base.contains(query)
            || self.snapshot.commands.iter().any(|command| {
                command.owner_installation_id == record.id
                    && (command.name.to_ascii_lowercase().contains(query)
                        || command.path.to_ascii_lowercase().contains(query))
            })
            || self.snapshot.findings.iter().any(|finding| {
                finding.installation_ids.contains(&record.id)
                    && finding.code.to_ascii_lowercase().contains(query)
            })
    }

    fn selected_record(&self) -> Option<&InstallationRecord> {
        let id = self.visible_ids().get(self.selection)?.clone();
        self.snapshot
            .installations
            .iter()
            .find(|record| record.id == id)
    }

    fn move_selection(&mut self, offset: isize) {
        let max = self.visible_ids().len().saturating_sub(1);
        self.selection = self.selection.saturating_add_signed(offset).min(max);
    }

    fn cycle_sort(&mut self, offset: isize) {
        self.sort_index = self
            .sort_index
            .saturating_add_signed(offset)
            .min(SORT_FIELDS.len() - 1);
        self.status = format!(
            "Sort: {} {}",
            sort_field_label(SORT_FIELDS[self.sort_index]),
            if self.order == SortOrder::Asc {
                "ASCENDING"
            } else {
                "DESCENDING"
            }
        );
    }

    fn toggle_selected(&mut self) {
        let Some(id) = self.visible_ids().get(self.selection).cloned() else {
            return;
        };
        if !self.selected.remove(&id) {
            self.selected.insert(id);
        }
    }
}

fn handle_search_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.searching = false;
            app.query.clear();
            app.selection = 0;
            app.status = "Search cleared".into();
        }
        KeyCode::Enter => {
            app.searching = false;
            app.selection = 0;
            app.status = format!("Search: {}", app.query);
        }
        KeyCode::Backspace => {
            app.query.pop();
            app.selection = 0;
        }
        KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.query.push(ch);
            app.selection = 0;
        }
        _ => {}
    }
}

fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App) {
    let area = frame.area();
    if area.width < 58 || area.height < 12 {
        frame.render_widget(
            Paragraph::new("Terminal too small\nResize to at least 58 × 12, or press q and use `pkgscope list`.")
                .block(Block::default().borders(Borders::ALL).title("pkgscope"))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    let background = match app.screen {
        Screen::Help => app.help_from,
        Screen::ConfirmUninstall => Screen::Detail,
        screen => screen,
    };
    match background {
        Screen::Detail => draw_detail(frame, app, area),
        _ => draw_list(frame, app, area),
    }
    if app.screen == Screen::Help {
        draw_help(frame, app.help_from, centered(area, 72, 22));
    } else if app.screen == Screen::ConfirmUninstall {
        draw_uninstall_confirmation(frame, app, centered(area, 78, 24));
    }
}

fn draw_list(frame: &mut ratatui::Frame<'_>, app: &mut App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);
    let scope = if !app.snapshot.scope.requested_managers.is_empty() {
        format!(
            "Managers: {}",
            app.snapshot
                .scope
                .requested_managers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    } else if app.snapshot.scope.environment_mode == crate::model::EnvironmentMode::Deep {
        "Deep scan".into()
    } else {
        "Current environment".into()
    };
    let partial = if app.snapshot.partial {
        format!("  PARTIAL: {}", app.snapshot.errors.len())
    } else {
        String::new()
    };
    let known_size = app
        .snapshot
        .installations
        .iter()
        .filter_map(|record| record.sizes.owned_allocated_bytes)
        .fold(0_u64, u64::saturating_add);
    let unknown_sizes = app
        .snapshot
        .installations
        .iter()
        .filter(|record| record.sizes.owned_allocated_bytes.is_none())
        .count();
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    "pkgscope",
                    if output::color_enabled() {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().add_modifier(Modifier::BOLD)
                    },
                ),
                Span::raw(format!("  {scope}{partial}")),
            ]),
            Line::from(vec![
                Span::styled(" TOTAL ", summary_label_style()),
                Span::styled(
                    format!(" {} PACKAGES ", app.snapshot.installations.len()),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw("  •  "),
                Span::styled(
                    format!(" {} OWNED SIZE ", output::size_label(Some(known_size))),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(if unknown_sizes == 0 {
                    String::new()
                } else {
                    format!("  ({unknown_sizes} size unknown)")
                }),
            ]),
        ]),
        layout[0],
    );
    let ids = app.visible_ids();
    app.selection = app.selection.min(ids.len().saturating_sub(1));
    let width = usize::from(area.width.saturating_sub(3));
    let show_env = width >= 92;
    let show_size = width >= 70;
    let show_installed = width >= 92;
    let name_width = width.saturating_sub(if show_env { 76 } else { 47 }).max(14);
    let mut items = Vec::with_capacity(ids.len() + 1);
    items.push(ListItem::new(sort_header_line(
        app,
        name_width,
        show_env,
        show_size,
        show_installed,
    )));
    for id in ids {
        let Some(record) = app
            .snapshot
            .installations
            .iter()
            .find(|record| record.id == id)
        else {
            continue;
        };
        let manager = output::manager_for(&app.snapshot, record)
            .map(|instance| instance.manager.to_string())
            .unwrap_or_else(|| "Unknown".into());
        let findings = output::finding_codes(&app.snapshot, record);
        let marker = if app.selected.contains(&record.id) {
            "● "
        } else {
            "  "
        };
        let name = format!("{marker}{}", record.identity.name);
        let size = show_size.then(|| output::size_label(record.sizes.owned_allocated_bytes));
        let installed = show_installed.then(|| output::install_date_label(record));
        items.push(ListItem::new(row_cells(RowCells {
            name: &name,
            manager: &manager,
            environment: show_env.then_some(record.environment.as_str()),
            version: record.version.value.as_deref().unwrap_or("Unknown"),
            size: size.as_deref(),
            installed: installed.as_deref(),
            findings: &findings,
            name_width,
        })));
    }
    let mut state = ListState::default().with_selected(Some(app.selection + 1));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().borders(Borders::TOP | Borders::BOTTOM))
            .highlight_symbol("▶ ")
            .highlight_style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)),
        layout[1],
        &mut state,
    );
    let (direction_arrow, direction_name) = match app.order {
        SortOrder::Asc => ("↑", "ASCENDING"),
        SortOrder::Desc => ("↓", "DESCENDING"),
    };
    let status = format!(
        "  search={}  {}",
        if app.query.is_empty() {
            "none"
        } else {
            &app.query
        },
        app.status
    );
    let keys = if app.searching {
        format!("/{}▌  Enter apply  Esc clear", app.query)
    } else {
        "↑↓ Move  ←→ Sort column  s Toggle Asc/Desc  Enter Detail  Space Select  / Search  r Rescan  ? Help  q Quit".into()
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    format!(
                        " SORT: {} {direction_arrow} {direction_name} ",
                        sort_field_label(SORT_FIELDS[app.sort_index])
                    ),
                    sort_highlight_style(),
                ),
                Span::raw(output::truncate(&status, width)),
            ]),
            Line::raw(output::truncate(&keys, width)),
        ]),
        layout[2],
    );
}

fn sort_header_line(
    app: &App,
    name_width: usize,
    show_environment: bool,
    show_size: bool,
    show_installed: bool,
) -> Line<'static> {
    let mut columns = vec![
        ("NAME", name_width, SortField::Name),
        ("MANAGER", 10, SortField::Manager),
    ];
    if show_environment {
        columns.push(("ENV", 13, SortField::Environment));
    }
    columns.push(("VERSION", 12, SortField::Version));
    if show_size {
        columns.push(("SIZE", 10, SortField::Size));
    }
    if show_installed {
        columns.push(("INSTALLED", 12, SortField::KnownSince));
    }
    columns.push(("FINDINGS", 10, SortField::Findings));
    let active = SORT_FIELDS[app.sort_index];
    let arrow = if app.order == SortOrder::Asc {
        "↑"
    } else {
        "↓"
    };
    let count = columns.len();
    let spans = columns
        .into_iter()
        .enumerate()
        .flat_map(|(index, (label, width, field))| {
            let label = if field == active {
                format!("{label} {arrow}")
            } else {
                label.into()
            };
            let padding = width.saturating_sub(UnicodeWidthStr::width(label.as_str()));
            let mut spans = vec![Span::styled(
                label,
                if field == active {
                    sort_highlight_style()
                } else {
                    Style::default().add_modifier(Modifier::BOLD)
                },
            )];
            spans.push(Span::raw(
                " ".repeat(padding + usize::from(index + 1 < count)),
            ));
            spans
        })
        .collect::<Vec<_>>();
    Line::from(spans)
}

fn sort_highlight_style() -> Style {
    let style = Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED);
    if output::color_enabled() {
        style.fg(Color::Cyan)
    } else {
        style
    }
}

fn sort_field_label(field: SortField) -> &'static str {
    match field {
        SortField::Name => "NAME",
        SortField::Manager => "MANAGER",
        SortField::Environment => "ENVIRONMENT",
        SortField::Version => "VERSION",
        SortField::Size => "SIZE",
        SortField::KnownSince => "INSTALLED",
        SortField::Findings => "FINDINGS",
    }
}

struct RowCells<'a> {
    name: &'a str,
    manager: &'a str,
    environment: Option<&'a str>,
    version: &'a str,
    size: Option<&'a str>,
    installed: Option<&'a str>,
    findings: &'a str,
    name_width: usize,
}

fn row_cells(row: RowCells<'_>) -> Line<'static> {
    let visible_name = output::truncate(row.name, row.name_width);
    let name_padding = row
        .name_width
        .saturating_sub(UnicodeWidthStr::width(visible_name.as_str()));
    let mut spans = vec![Span::styled(visible_name, Style::default())];
    spans.push(Span::raw(format!("{} ", " ".repeat(name_padding))));
    let mut columns = vec![cell(row.manager, 10)];
    if let Some(environment) = row.environment {
        columns.push(cell(environment, 13));
    }
    columns.push(cell(row.version, 12));
    if let Some(size) = row.size {
        columns.push(cell(size, 10));
    }
    if let Some(installed) = row.installed {
        columns.push(cell(installed, 12));
    }
    columns.push(cell(row.findings, 10));
    spans.push(Span::raw(columns.join(" ")));
    Line::from(spans)
}

fn cell(value: &str, width: usize) -> String {
    let value = output::truncate(value, width);
    format!(
        "{value}{}",
        " ".repeat(width.saturating_sub(UnicodeWidthStr::width(value.as_str())))
    )
}

fn summary_label_style() -> Style {
    let style = Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED);
    if output::color_enabled() {
        style.fg(Color::Cyan)
    } else {
        style
    }
}

fn section_heading(title: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" {title} "), summary_label_style()),
        Span::raw(" "),
    ])
}

fn important_line(label: &str, value: &str) -> Line<'static> {
    let label_style = if output::color_enabled() {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::BOLD)
    };
    Line::from(vec![
        Span::styled(format!("  {label:<27} :  "), label_style),
        Span::raw(value.to_owned()),
    ])
}

fn detail_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label}: "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(value.to_owned()),
    ])
}

fn install_date_detail(record: &InstallationRecord) -> String {
    let candidates = [
        (
            "manager-reported current-version install time",
            record.dates.current_version_installed_at.as_ref(),
        ),
        (
            "manager-reported install event",
            record.dates.manager_install_event_at.as_ref(),
        ),
        (
            "filesystem date; estimated",
            record.dates.filesystem_created_at.as_ref(),
        ),
        (
            "first seen by pkgscope; not an install record",
            record.dates.first_seen_at.as_ref(),
        ),
    ];
    candidates
        .into_iter()
        .find_map(|(meaning, field)| {
            let field = field?;
            let value = field.value?;
            Some(format!(
                "{}  —  {} [{}]",
                value.format("%Y-%m-%d %H:%M UTC"),
                meaning,
                field.source
            ))
        })
        .unwrap_or_else(|| "Unknown — this package manager did not retain a usable date".into())
}

fn draw_detail(frame: &mut ratatui::Frame<'_>, app: &mut App, area: Rect) {
    let Some(record) = app.selected_record() else {
        return;
    };
    let mut lines = vec![section_heading("IMPORTANT")];
    let description = output::metadata_text(record, "description")
        .unwrap_or("No description was provided by the installed package metadata.");
    let homepage = output::metadata_text(record, "homepage").unwrap_or("Not reported");
    lines.extend([
        important_line("DESCRIPTION", description),
        important_line("HOMEPAGE", homepage),
        important_line("INSTALLED / DOWNLOAD DATE", &install_date_detail(record)),
        important_line(
            "SIZE",
            &format!(
                "{}  ({:?} confidence)",
                output::size_label(record.sizes.owned_allocated_bytes),
                record.sizes.confidence
            ),
        ),
    ]);
    match build_removal_plan(&app.snapshot, record) {
        Ok(plan) => lines.push(important_line(
            "UNINSTALL COMMAND",
            &std::iter::once(plan.action.executable.as_str())
                .chain(plan.action.argv.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" "),
        )),
        Err(error) => lines.push(important_line(
            "UNINSTALL COMMAND",
            &format!("Unavailable: {error}"),
        )),
    }
    lines.extend([
        Line::raw(""),
        Line::styled(
            " u  REVIEW AND UNINSTALL ",
            Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED),
        ),
        Line::raw(""),
    ]);
    for section in 0..5 {
        lines.push(section_heading(
            [
                "MORE DETAILS",
                "COMMANDS",
                "EVIDENCE & FINDINGS",
                "DEPENDENCIES",
                "UNINSTALL SAFETY",
            ][section],
        ));
        match section {
            0 => {
                let description_source =
                    output::metadata_text(record, "description_source").unwrap_or("not reported");
                lines.extend([
                    detail_line("Description source", description_source),
                    Line::raw(format!(
                        "Repository: {}",
                        output::metadata_text(record, "repository").unwrap_or("Not reported")
                    )),
                    Line::raw(format!(
                        "License: {}",
                        output::metadata_text(record, "license").unwrap_or("Not reported")
                    )),
                    Line::raw(format!(
                        "Manager: {}",
                        output::manager_for(&app.snapshot, record)
                            .map(|instance| format!(
                                "{} @ {}",
                                instance.manager, instance.executable_path
                            ))
                            .unwrap_or_else(|| "Unknown".into())
                    )),
                    Line::raw(format!(
                        "Version: {}",
                        record.version.value.as_deref().unwrap_or("Unknown")
                    )),
                    Line::raw(format!(
                        "Source: {:?}{}",
                        record.identity.source_kind,
                        record
                            .identity
                            .source_ref
                            .as_deref()
                            .map(|source| format!(" ({source})"))
                            .unwrap_or_default()
                    )),
                    Line::raw(format!(
                        "Architecture: {}",
                        record.architecture.value.as_deref().unwrap_or("Unknown")
                    )),
                    Line::raw(format!("Environment: {}", record.environment)),
                    Line::raw(format!(
                        "Install root: {}",
                        record.paths.install_root.as_deref().unwrap_or("Unknown")
                    )),
                    Line::raw(format!(
                        "Known since: {}",
                        record
                            .dates
                            .first_seen_at
                            .as_ref()
                            .and_then(|value| value.value)
                            .map(|date| date.format("%Y-%m-%d %H:%M UTC").to_string())
                            .unwrap_or_else(|| "Unknown (no saved observation)".into())
                    )),
                ]);
                let command_names = app
                    .snapshot
                    .commands
                    .iter()
                    .filter(|command| command.owner_installation_id == record.id)
                    .map(|command| command.name.as_str())
                    .collect::<Vec<_>>();
                lines.push(Line::raw(format!(
                    "Provides commands: {}",
                    if command_names.is_empty() {
                        "None reported".into()
                    } else {
                        command_names.join(", ")
                    }
                )));
            }
            1 => {
                for command in app
                    .snapshot
                    .commands
                    .iter()
                    .filter(|command| command.owner_installation_id == record.id)
                {
                    lines.push(Line::raw(format!(
                        "{} -> {} [{:?}, PATH rank {}]",
                        command.name,
                        command.path,
                        command.exposure_state,
                        command
                            .path_rank
                            .map(|rank| rank.to_string())
                            .unwrap_or_else(|| "none".into())
                    )));
                }
                if record.command_ids.is_empty() {
                    lines.push(Line::raw("No exposed commands reported."));
                }
            }
            2 => {
                lines.push(Line::raw(format!(
                    "Version: source={}, confidence={:?}",
                    record.version.source, record.version.confidence
                )));
                lines.push(Line::raw(format!(
                    "Architecture: source={}, confidence={:?}",
                    record.architecture.source, record.architecture.confidence
                )));
                lines.push(Line::raw(format!(
                    "Size: method={}, confidence={:?}",
                    record.sizes.method, record.sizes.confidence
                )));
                for finding in app
                    .snapshot
                    .findings
                    .iter()
                    .filter(|finding| finding.installation_ids.contains(&record.id))
                {
                    lines.push(Line::raw(format!(
                        "[{}] {} ({:?}): {}{}",
                        output::severity_label(finding.severity),
                        finding.code,
                        finding.confidence,
                        finding.explanation,
                        if finding.evidence_refs.is_empty() {
                            String::new()
                        } else {
                            format!(" [evidence: {}]", finding.evidence_refs.join(", "))
                        }
                    )));
                }
            }
            3 => {
                if let Some(dependencies) = record.metadata.get("dependencies") {
                    lines.push(Line::raw(crate::sanitize::terminal_text(&format!(
                        "Managed dependencies: {dependencies}"
                    ))));
                } else {
                    lines.push(Line::raw(
                        "No dependency detail reported for this record by the scanner.",
                    ));
                }
            }
            _ => match build_removal_plan(&app.snapshot, record) {
                Ok(plan) => {
                    lines.push(Line::raw(format!("Executable: {}", plan.action.executable)));
                    for (index, argument) in plan.action.argv.iter().enumerate() {
                        lines.push(Line::raw(format!("argv[{index}]: {argument}")));
                    }
                    lines.push(Line::raw(format!(
                        "Managed dependents: {}",
                        if plan.managed_dependents.is_empty() {
                            "none reported".into()
                        } else {
                            plan.managed_dependents.join(", ")
                        }
                    )));
                    for warning in plan.warnings {
                        lines.push(Line::raw(format!("Warning: {warning}")));
                    }
                    lines.push(Line::styled(
                        "Press u to confirm uninstall. The package name must be typed exactly.",
                        Style::default().add_modifier(Modifier::BOLD),
                    ));
                }
                Err(error) => lines.push(Line::raw(format!("Uninstall unavailable: {error}"))),
            },
        }
        lines.push(Line::raw(""));
    }
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(2)])
        .split(area);
    let visible_height = usize::from(layout[0].height.saturating_sub(2));
    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} — all details ", record.identity.name)),
        )
        .wrap(Wrap { trim: false });
    let rendered_height = paragraph.line_count(layout[0].width.saturating_sub(2));
    let max_scroll = rendered_height
        .saturating_sub(visible_height)
        .min(u16::MAX as usize) as u16;
    let scroll = app.detail_scroll.min(max_scroll);
    frame.render_widget(paragraph.scroll((scroll, 0)), layout[0]);
    frame.render_widget(
        Paragraph::new(format!(
            "↑↓/jk Scroll  PgUp/PgDn  Home/End  u Uninstall  Esc Back  {}/{}",
            scroll.saturating_add(1),
            max_scroll.saturating_add(1)
        )),
        layout[1],
    );
    app.detail_scroll = scroll;
}

fn draw_help(frame: &mut ratatui::Frame<'_>, from: Screen, area: Rect) {
    frame.render_widget(Clear, area);
    let text = if from == Screen::Detail {
        "↑/↓ or j/k  Scroll all package details\nPgUp/PgDn  Scroll by page\nHome/End  First/last detail\nu  Open typed uninstall confirmation\nEsc / q  Back to list\nCtrl+C  Quit\n\nThe detail page contains overview, commands, evidence, dependencies, and the exact manager action in one vertical view. Uninstall requires the exact package name, then performs a fresh identity and ownership check before execution.\nPress Esc, Enter, or q to close help."
    } else {
        "↑/k, ↓/j  Move\nHome/g, End/G  First/last\n←/→  Change highlighted sort column\ns  Toggle ↑ ASCENDING / ↓ DESCENDING\nEnter  Open all package details\nSpace  Select\n/  Search (Enter applies, Esc clears)\nx  Clear search\nr  Rescan now\n?  Help\nq / Ctrl+C  Quit\n\nA fresh scan runs every time the TUI starts. Uninstall is available only from package details and requires typed confirmation plus fresh revalidation.\nPress Esc, Enter, or q to close help."
    };
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title(" Help "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_uninstall_confirmation(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    frame.render_widget(Clear, area);
    let text = app.selected_record().map_or_else(
        || "No installation selected.".into(),
        |record| match build_removal_plan(&app.snapshot, record) {
            Ok(plan) => {
                let command = std::iter::once(plan.action.executable.as_str())
                    .chain(plan.action.argv.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join("  ");
                format!(
                    "UNINSTALL CONFIRMATION\n\nTarget: {} {}\nStable ID: {}\nCommand (direct argv, no shell):\n{}\n\nManaged dependents: {}\nWarnings: {}\nRollback: not promised\n\nType the exact package name to enable execution:\n> {}▌\n{}\n\nEnter Execute    Esc Cancel",
                    plan.target_name,
                    plan.target_version.as_deref().unwrap_or("Unknown"),
                    plan.installation_id,
                    command,
                    if plan.managed_dependents.is_empty() { "none reported".into() } else { plan.managed_dependents.join(", ") },
                    if plan.warnings.is_empty() { "none".into() } else { plan.warnings.join("; ") },
                    app.confirm_input,
                    app.confirm_error.as_deref().unwrap_or("Nothing has been executed."),
                )
            }
            Err(error) => format!(
                "Uninstall unavailable: {error}\n\nNothing has been executed. Press Esc to return."
            ),
        },
    );
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Confirm uninstall "),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn perform_uninstall(
    expected_record: &InstallationRecord,
    expected_plan: &crate::model::RemovalPlan,
    manager_kind: ManagerKind,
    common_options: &CommonOptions,
) -> Result<(Snapshot, String)> {
    let mut verification_options = crate::cli::scan_options(common_options);
    let expected_manager = expected_record.manager_instance_id.clone();
    verification_options.managers = vec![manager_kind];
    verification_options.all_environments = true;
    let fresh = scanner::scan(&verification_options);
    if !fresh
        .manager_instances
        .iter()
        .any(|instance| instance.id == expected_manager)
    {
        anyhow::bail!("the owning manager instance disappeared; nothing was executed");
    }
    let verified = removal::revalidate(expected_record, expected_plan, &fresh)?;
    eprintln!(
        "Executing {} {}",
        crate::sanitize::terminal_text(&verified.plan.action.executable),
        crate::sanitize::terminal_text(&verified.plan.action.argv.join(" "))
    );
    let output = removal::execute(&verified, &verification_options)?;
    let stdout = crate::process::redact_diagnostic(&output.stdout_text());
    let stderr = crate::process::redact_diagnostic(&output.stderr_text());
    if !stdout.is_empty() {
        eprintln!("{stdout}");
    }
    if !stderr.is_empty() {
        eprintln!("{stderr}");
    }
    eprintln!("Uninstall command succeeded. Rescanning…");
    let snapshot = scanner::scan(&crate::cli::scan_options(common_options));
    let still_present = snapshot
        .installations
        .iter()
        .any(|record| record.id == expected_record.id);
    Ok((
        snapshot,
        if still_present {
            format!(
                "{} completed, but the installation is still reported",
                expected_record.identity.name
            )
        } else {
            expected_record.identity.name.clone()
        },
    ))
}

fn centered(area: Rect, max_width: u16, max_height: u16) -> Rect {
    let width = area.width.min(max_width);
    let height = area.height.min(max_height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}
