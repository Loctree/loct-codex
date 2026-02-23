use crate::bash::extract_bash_command;
use crate::git_info::get_git_repo_root;
use crate::parse_command::parse_command;
use codex_protocol::parse_command::ParsedCommand;
use codex_utils_string::take_bytes_at_char_boundary;
use loctree::analyzer::search::run_search;
use loctree::args::ParsedArgs;
use loctree::snapshot::Snapshot;
use loctree::snapshot::run_init_with_options;
use loctree::types::Mode;
use serde_json::Value;
use serde_json::json;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

const LOCTREE_ENV_FLAG: &str = "CODEX_LOCTREE_AUGMENT";
const MAX_CONTEXT_BYTES: usize = 32 * 1024;
const MIN_PATTERN_LEN: usize = 3;
const FIND_LIMIT: usize = 50;
const LOCTREE_FIND_HEADER: &str = "---- LOCTREE FIND ----";
const LOCTREE_SLICE_HEADER: &str = "---- LOCTREE SLICE ----";
const LOCTREE_IMPACT_HEADER: &str = "---- LOCTREE IMPACT ----";
const LOCTREE_FOCUS_HEADER: &str = "---- LOCTREE FOCUS ----";

struct Section {
    title: &'static str,
    body: String,
}

struct SnapshotContext {
    root: PathBuf,
    snapshot: Snapshot,
}

#[derive(Debug, Clone, Copy)]
struct LoctreeContextStats {
    bytes: usize,
    find: usize,
    slice: usize,
    impact: usize,
    focus: usize,
}

impl LoctreeContextStats {
    fn total_sections(self) -> usize {
        self.find + self.slice + self.impact + self.focus
    }
}

impl SnapshotContext {
    fn load(start: &Path) -> Option<Self> {
        let start_dir = if start.is_dir() {
            start
        } else {
            start.parent().unwrap_or(start)
        };
        let root = find_project_root(start_dir);
        let snapshot = load_snapshot(&root)?;
        Some(Self { root, snapshot })
    }

    fn project_display(&self) -> String {
        self.root.display().to_string()
    }
}

fn find_project_root(start_dir: &Path) -> PathBuf {
    Snapshot::find_loctree_root(start_dir)
        .or_else(|| get_git_repo_root(start_dir))
        .unwrap_or_else(|| start_dir.to_path_buf())
}

fn load_snapshot(root: &Path) -> Option<Snapshot> {
    let mut snapshot = match Snapshot::load(root) {
        Ok(snapshot) => Some(snapshot),
        Err(err) => {
            tracing::debug!(
                root = %root.display(),
                error = %err,
                "Failed to load loctree snapshot"
            );
            None
        }
    };

    let needs_scan = match snapshot.as_ref() {
        Some(existing) => is_snapshot_stale(existing, root),
        None => true,
    };

    if needs_scan && run_scan(root) {
        snapshot = match Snapshot::load(root) {
            Ok(snapshot) => Some(snapshot),
            Err(err) => {
                tracing::warn!(
                    root = %root.display(),
                    error = %err,
                    "Loctree scan completed but snapshot reload failed"
                );
                snapshot
            }
        };
    }

    snapshot
}

fn is_snapshot_stale(snapshot: &Snapshot, project: &Path) -> bool {
    let Some(snapshot_commit) = snapshot.metadata.git_commit.as_ref() else {
        return false;
    };
    let Some(current_commit) = get_git_head(project) else {
        return false;
    };

    let is_same =
        current_commit.starts_with(snapshot_commit) || snapshot_commit.starts_with(&current_commit);
    !is_same
}

fn get_git_head(project: &Path) -> Option<String> {
    let output = match Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(project)
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            tracing::debug!(
                project = %project.display(),
                error = %err,
                "Failed to run git rev-parse HEAD"
            );
            return None;
        }
    };
    if !output.status.success() {
        tracing::debug!(
            project = %project.display(),
            status = ?output.status,
            "git rev-parse HEAD returned non-zero status"
        );
        return None;
    }
    let hash = match String::from_utf8(output.stdout) {
        Ok(hash) => hash,
        Err(err) => {
            tracing::debug!(
                project = %project.display(),
                error = %err,
                "git rev-parse HEAD output was not valid UTF-8"
            );
            return None;
        }
    };
    let hash = hash.trim();
    if hash.is_empty() {
        None
    } else {
        Some(hash.to_string())
    }
}

fn run_scan(project: &Path) -> bool {
    run_scan_in_process(project)
}

fn run_scan_in_process(project: &Path) -> bool {
    if let Err(err) = std::fs::create_dir_all(project.join(".loctree")) {
        tracing::warn!(
            project = %project.display(),
            error = %err,
            "Failed to create loctree directory before scan"
        );
        return false;
    }

    let parsed = ParsedArgs {
        mode: Mode::Init,
        root_list: vec![project.to_path_buf()],
        ..Default::default()
    };

    match run_init_with_options(&[project.to_path_buf()], &parsed, true) {
        Ok(_) => true,
        Err(err) => {
            tracing::warn!(
                project = %project.display(),
                error = %err,
                "Loctree scan failed"
            );
            false
        }
    }
}

pub(crate) async fn loctree_context_for_grep(pattern: &str, search_path: &Path) -> Option<String> {
    if !env_flag_enabled() {
        return None;
    }

    let pattern = pattern.to_string();
    let search_path = search_path.to_path_buf();
    let pattern_log = pattern.clone();
    let search_path_log = search_path.clone();
    match tokio::task::spawn_blocking(move || loctree_context_for_grep_sync(&pattern, &search_path))
        .await
    {
        Ok(context) => {
            log_loctree_observability(
                "grep_files",
                Some(pattern_log.as_str()),
                Some(search_path_log.as_path()),
                context.as_deref(),
            );
            context
        }
        Err(err) => {
            tracing::warn!(
                pattern = %pattern_log,
                path = %search_path_log.display(),
                error = %err,
                "loctree grep context task failed"
            );
            None
        }
    }
}

pub(crate) async fn loctree_context_for_read(file_path: &Path) -> Option<String> {
    if !env_flag_enabled() {
        return None;
    }

    let file_path = file_path.to_path_buf();
    let file_path_log = file_path.clone();
    match tokio::task::spawn_blocking(move || loctree_context_for_read_sync(&file_path)).await {
        Ok(context) => {
            log_loctree_observability(
                "read_file",
                None,
                Some(file_path_log.as_path()),
                context.as_deref(),
            );
            context
        }
        Err(err) => {
            tracing::warn!(
                path = %file_path_log.display(),
                error = %err,
                "loctree read context task failed"
            );
            None
        }
    }
}

pub(crate) async fn loctree_context_for_exec(cwd: &Path, command: &[String]) -> Option<String> {
    if !env_flag_enabled() {
        return None;
    }

    let cwd = cwd.to_path_buf();
    let command = command.to_vec();
    let cwd_log = cwd.clone();
    let command_log = command.clone();
    let command_joined = command_log.join(" ");
    match tokio::task::spawn_blocking(move || loctree_context_for_exec_sync(&cwd, &command)).await {
        Ok(context) => {
            log_loctree_observability(
                "exec_command",
                Some(command_joined.as_str()),
                Some(cwd_log.as_path()),
                context.as_deref(),
            );
            context
        }
        Err(err) => {
            tracing::warn!(
                cwd = %cwd_log.display(),
                command = ?command_log,
                error = %err,
                "loctree exec context task failed"
            );
            None
        }
    }
}

pub(crate) fn append_loctree_context(mut content: String, context: Option<String>) -> String {
    let Some(context) = context else {
        return content;
    };
    let context = context.trim_end();
    if context.is_empty() {
        return content;
    }

    if !content.ends_with('\n') {
        content.push('\n');
    }
    content.push('\n');
    content.push_str(context);
    content
}

pub(crate) fn inject_loctree_context_json(content: String, context: Option<String>) -> String {
    let Some(context) = context else {
        return content;
    };
    let context = context.trim_end();
    if context.is_empty() {
        return content;
    }

    let Ok(mut value) = serde_json::from_str::<Value>(&content) else {
        return append_loctree_context(content, Some(context.to_string()));
    };

    let Some(object) = value.as_object_mut() else {
        return append_loctree_context(content, Some(context.to_string()));
    };

    object.insert(
        "loctree_context".to_string(),
        Value::String(context.to_string()),
    );
    serde_json::to_string(&value).unwrap_or(content)
}

fn loctree_context_for_grep_sync(pattern: &str, search_path: &Path) -> Option<String> {
    let ctx = SnapshotContext::load(search_path)?;
    let mut sections = Vec::new();

    if let Some(query) = normalize_pattern(pattern)
        && let Some(result) = loctree_find(&ctx, &query, FIND_LIMIT)
    {
        sections.push(Section {
            title: "FIND",
            body: result,
        });
    }

    if search_path.is_file() {
        sections.extend(loctree_sections_for_file(&ctx, search_path));
    } else if search_path.is_dir() {
        sections.extend(loctree_sections_for_dir(&ctx, search_path));
    }

    format_sections(sections)
}

fn loctree_context_for_read_sync(file_path: &Path) -> Option<String> {
    let ctx = SnapshotContext::load(file_path)?;
    let sections = loctree_sections_for_file(&ctx, file_path);
    format_sections(sections)
}

fn loctree_context_for_exec_sync(cwd: &Path, command: &[String]) -> Option<String> {
    let parsed = parse_command(command);
    let mut sections = Vec::new();

    for parsed_cmd in parsed {
        match parsed_cmd {
            ParsedCommand::Read { path, .. } => {
                let resolved = if path.is_absolute() {
                    path
                } else {
                    cwd.join(&path)
                };
                if let Some(ctx) = SnapshotContext::load(&resolved) {
                    sections.extend(loctree_sections_for_file(&ctx, &resolved));
                } else {
                    tracing::debug!(
                        path = %resolved.display(),
                        "Skipping loctree read context because snapshot is unavailable"
                    );
                }
            }
            ParsedCommand::Search { query, path, .. } => {
                let Some(query) = query.as_deref().and_then(normalize_pattern) else {
                    continue;
                };
                let Some(ctx) = SnapshotContext::load(cwd) else {
                    tracing::debug!(
                        cwd = %cwd.display(),
                        "Skipping loctree search context because snapshot is unavailable"
                    );
                    continue;
                };

                if let Some(result) = loctree_find(&ctx, &query, FIND_LIMIT) {
                    sections.push(Section {
                        title: "FIND",
                        body: result,
                    });
                }

                if let Some(path) = path {
                    let resolved = cwd.join(path);
                    sections.extend(loctree_sections_for_path(&ctx, &resolved));
                }
            }
            _ => {}
        }
    }

    if !sections.iter().any(|section| section.title == "SLICE")
        && let Some(fallback) = loctree_sections_for_shell_read_fallback(cwd, command)
    {
        sections.extend(fallback);
    }

    format_sections(sections)
}

fn env_flag_enabled() -> bool {
    match std::env::var(LOCTREE_ENV_FLAG) {
        Ok(value) => {
            let value = value.trim().to_ascii_lowercase();
            if value.is_empty() {
                return false;
            }
            !matches!(value.as_str(), "0" | "false" | "off" | "no")
        }
        Err(_) => true,
    }
}

fn loctree_context_stats(context: Option<&str>) -> Option<LoctreeContextStats> {
    let context = context.map(str::trim_end)?;
    if context.is_empty() {
        return None;
    }

    let find = context.match_indices(LOCTREE_FIND_HEADER).count();
    let slice = context.match_indices(LOCTREE_SLICE_HEADER).count();
    let impact = context.match_indices(LOCTREE_IMPACT_HEADER).count();
    let focus = context.match_indices(LOCTREE_FOCUS_HEADER).count();

    Some(LoctreeContextStats {
        bytes: context.len(),
        find,
        slice,
        impact,
        focus,
    })
}

fn log_loctree_observability(
    operation: &str,
    subject: Option<&str>,
    path: Option<&Path>,
    context: Option<&str>,
) {
    match loctree_context_stats(context) {
        Some(stats) => {
            if let Some(path) = path {
                tracing::info!(
                    operation,
                    subject = subject.unwrap_or(""),
                    path = %path.display(),
                    bytes = stats.bytes,
                    sections = stats.total_sections(),
                    find = stats.find,
                    slice = stats.slice,
                    impact = stats.impact,
                    focus = stats.focus,
                    "Loctree augmentation applied"
                );
            } else {
                tracing::info!(
                    operation,
                    subject = subject.unwrap_or(""),
                    bytes = stats.bytes,
                    sections = stats.total_sections(),
                    find = stats.find,
                    slice = stats.slice,
                    impact = stats.impact,
                    focus = stats.focus,
                    "Loctree augmentation applied"
                );
            }
        }
        None => {
            if let Some(path) = path {
                tracing::info!(
                    operation,
                    subject = subject.unwrap_or(""),
                    path = %path.display(),
                    "Loctree augmentation skipped (no context)"
                );
            } else {
                tracing::info!(
                    operation,
                    subject = subject.unwrap_or(""),
                    "Loctree augmentation skipped (no context)"
                );
            }
        }
    }
}

fn normalize_pattern(pattern: &str) -> Option<String> {
    let trimmed = pattern.trim();
    if trimmed.len() < MIN_PATTERN_LEN {
        return None;
    }

    if trimmed.chars().any(char::is_whitespace) {
        let tokens: Vec<&str> = trimmed
            .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
            .filter(|token| token.len() >= MIN_PATTERN_LEN)
            .take(5)
            .collect();
        if tokens.is_empty() {
            return None;
        }
        return Some(tokens.join("|"));
    }

    Some(trimmed.to_string())
}

fn loctree_sections_for_path(ctx: &SnapshotContext, path: &Path) -> Vec<Section> {
    if path.is_file() {
        return loctree_sections_for_file(ctx, path);
    }
    if path.is_dir() {
        return loctree_sections_for_dir(ctx, path);
    }
    Vec::new()
}

fn loctree_sections_for_file(ctx: &SnapshotContext, file_path: &Path) -> Vec<Section> {
    let mut sections = Vec::new();

    if let Some(result) = loctree_slice(ctx, file_path) {
        sections.push(Section {
            title: "SLICE",
            body: result,
        });
    }

    if let Some(result) = loctree_impact(ctx, file_path) {
        sections.push(Section {
            title: "IMPACT",
            body: result,
        });
    }

    sections
}

fn loctree_sections_for_dir(ctx: &SnapshotContext, dir_path: &Path) -> Vec<Section> {
    let Some(directory) = directory_in_project(&ctx.root, dir_path) else {
        return Vec::new();
    };
    if directory == "." {
        return Vec::new();
    }

    let mut sections = Vec::new();
    if let Some(result) = loctree_focus(ctx, &directory) {
        sections.push(Section {
            title: "FOCUS",
            body: result,
        });
    }

    sections
}

fn loctree_sections_for_shell_read_fallback(
    cwd: &Path,
    command: &[String],
) -> Option<Vec<Section>> {
    let (_, script) = extract_bash_command(command)?;
    let tokens = shlex::split(script)?;
    let (head, tail) = tokens.split_first()?;

    let path = match head.as_str() {
        "cat" | "bat" | "batcat" => first_non_flag_operand(tail)?,
        _ => return None,
    };

    let candidate = PathBuf::from(path);
    let resolved = if candidate.is_absolute() {
        candidate
    } else {
        cwd.join(candidate)
    };
    let ctx = SnapshotContext::load(&resolved)?;
    let sections = loctree_sections_for_file(&ctx, &resolved);
    if sections.is_empty() {
        None
    } else {
        Some(sections)
    }
}

fn first_non_flag_operand(tokens: &[String]) -> Option<&str> {
    let mut iter = tokens.iter();
    while let Some(token) = iter.next() {
        if token == "--" {
            return iter.next().map(String::as_str);
        }
        if !token.starts_with('-') {
            return Some(token.as_str());
        }
    }
    None
}

fn loctree_find(ctx: &SnapshotContext, query: &str, limit: usize) -> Option<String> {
    let search_results = run_search(query, &ctx.snapshot.files);

    let symbol_matches: Vec<_> = search_results
        .symbol_matches
        .files
        .iter()
        .flat_map(|file_match| {
            file_match.matches.iter().map(move |matched| {
                let symbol = matched
                    .context
                    .split_whitespace()
                    .last()
                    .unwrap_or(&matched.context);
                json!({
                    "file": file_match.file,
                    "symbol": symbol,
                    "kind": if matched.is_definition { "definition" } else { "usage" },
                    "line": matched.line,
                    "context": matched.context,
                })
            })
        })
        .take(limit)
        .collect();

    let remaining = limit.saturating_sub(symbol_matches.len());
    let param_matches: Vec<_> = search_results
        .param_matches
        .iter()
        .take(remaining)
        .map(|pm| {
            json!({
                "file": pm.file,
                "function": pm.function,
                "param": pm.param_name,
                "type": pm.param_type,
                "line": pm.line,
            })
        })
        .collect();

    let semantic_matches: Vec<_> = search_results
        .semantic_matches
        .iter()
        .take(20)
        .map(|sm| {
            json!({
                "symbol": sm.symbol,
                "file": sm.file,
                "score": sm.score,
            })
        })
        .collect();

    let result = json!({
        "query": query,
        "project": ctx.project_display(),
        "symbol_matches": {
            "count": symbol_matches.len(),
            "matches": symbol_matches,
        },
        "param_matches": {
            "count": param_matches.len(),
            "matches": param_matches,
        },
        "semantic_matches": {
            "count": semantic_matches.len(),
            "matches": semantic_matches,
        },
        "dead_status": {
            "is_exported": search_results.dead_status.is_exported,
            "is_dead": search_results.dead_status.is_dead,
        },
    });

    Some(format_json(result))
}

fn loctree_slice(ctx: &SnapshotContext, file_path: &Path) -> Option<String> {
    let target_path = resolve_file_in_snapshot(ctx, file_path)?;
    let target = ctx
        .snapshot
        .files
        .iter()
        .find(|file| file.path == target_path)?;

    let mut files = vec![json!({
        "path": target.path,
        "layer": "core",
        "loc": target.loc,
        "language": target.language,
    })];

    let deps: Vec<_> = ctx
        .snapshot
        .edges
        .iter()
        .filter(|edge| edge.from == target.path)
        .collect();

    for edge in &deps {
        if let Some(dep) = ctx.snapshot.files.iter().find(|file| file.path == edge.to) {
            files.push(json!({
                "path": dep.path,
                "layer": "dependency",
                "loc": dep.loc,
                "import_type": edge.label,
            }));
        }
    }

    let consumers: Vec<_> = ctx
        .snapshot
        .edges
        .iter()
        .filter(|edge| edge.to == target.path)
        .collect();

    for edge in &consumers {
        if let Some(consumer) = ctx
            .snapshot
            .files
            .iter()
            .find(|file| file.path == edge.from)
        {
            files.push(json!({
                "path": consumer.path,
                "layer": "consumer",
                "loc": consumer.loc,
            }));
        }
    }

    let target_display = best_effort_file_path(&ctx.root, file_path);
    let result = json!({
        "target": target_display,
        "project": ctx.project_display(),
        "core_loc": target.loc,
        "dependencies": deps.len(),
        "consumers": consumers.len(),
        "files": files,
    });

    Some(format_json(result))
}

fn loctree_impact(ctx: &SnapshotContext, file_path: &Path) -> Option<String> {
    let target_path = resolve_file_in_snapshot(ctx, file_path)?;

    let direct: Vec<_> = ctx
        .snapshot
        .edges
        .iter()
        .filter(|edge| edge.to == target_path)
        .map(|edge| edge.from.clone())
        .collect();

    let mut visited: HashSet<String> = direct.iter().cloned().collect();
    let mut queue: VecDeque<String> = direct.iter().cloned().collect();
    let mut transitive = Vec::new();

    while let Some(file) = queue.pop_front() {
        for edge in &ctx.snapshot.edges {
            if edge.to == file && !visited.contains(&edge.from) {
                visited.insert(edge.from.clone());
                queue.push_back(edge.from.clone());
                transitive.push(edge.from.clone());
            }
        }
    }

    let risk = if direct.is_empty() {
        "none"
    } else if direct.len() > 10 || !transitive.is_empty() {
        "high"
    } else if direct.len() > 3 {
        "medium"
    } else {
        "low"
    };

    let target_display = best_effort_file_path(&ctx.root, file_path);
    let result = json!({
        "file": target_display,
        "project": ctx.project_display(),
        "risk_level": risk,
        "direct_consumers": {
            "count": direct.len(),
            "files": direct.iter().take(20).collect::<Vec<_>>(),
        },
        "transitive_consumers": {
            "count": transitive.len(),
            "files": transitive.iter().take(10).collect::<Vec<_>>(),
        },
        "safe_to_delete": direct.is_empty(),
    });

    Some(format_json(result))
}

fn loctree_focus(ctx: &SnapshotContext, directory: &str) -> Option<String> {
    let directory = normalize_snapshot_str(directory);
    let directory = directory.trim_end_matches('/');
    if directory.is_empty() {
        return None;
    }

    let dir_prefix = format!("{directory}/");
    let files_in_dir: Vec<_> = ctx
        .snapshot
        .files
        .iter()
        .filter(|file| file.path.starts_with(&dir_prefix) || file.path == directory)
        .collect();

    if files_in_dir.is_empty() {
        let result = json!({
            "directory": directory,
            "project": ctx.project_display(),
            "error": "No files found in this directory. Check the path.",
        });
        return Some(format_json(result));
    }

    let total_loc: usize = files_in_dir.iter().map(|file| file.loc).sum();
    let total_exports: usize = files_in_dir.iter().map(|file| file.exports.len()).sum();

    let internal_edges = ctx
        .snapshot
        .edges
        .iter()
        .filter(|edge| {
            (edge.from.starts_with(&dir_prefix) || edge.from == directory)
                && (edge.to.starts_with(&dir_prefix) || edge.to == directory)
        })
        .count();

    let external_dependencies: Vec<_> = ctx
        .snapshot
        .edges
        .iter()
        .filter(|edge| {
            (edge.from.starts_with(&dir_prefix) || edge.from == directory)
                && !edge.to.starts_with(&dir_prefix)
        })
        .map(|edge| edge.to.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let external_consumers: Vec<_> = ctx
        .snapshot
        .edges
        .iter()
        .filter(|edge| {
            !edge.from.starts_with(&dir_prefix)
                && (edge.to.starts_with(&dir_prefix) || edge.to == directory)
        })
        .map(|edge| edge.from.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let result = json!({
        "directory": directory,
        "project": ctx.project_display(),
        "summary": {
            "files": files_in_dir.len(),
            "total_loc": total_loc,
            "total_exports": total_exports,
            "internal_edges": internal_edges,
        },
        "files": files_in_dir
            .iter()
            .map(|file| {
                json!({
                    "path": file.path,
                    "loc": file.loc,
                    "language": file.language,
                    "exports": file.exports.len(),
                })
            })
            .collect::<Vec<_>>(),
        "external_dependencies": external_dependencies.iter().take(20).collect::<Vec<_>>(),
        "external_consumers": external_consumers.iter().take(20).collect::<Vec<_>>(),
    });

    Some(format_json(result))
}

fn resolve_file_in_snapshot(ctx: &SnapshotContext, file_path: &Path) -> Option<String> {
    let root = canonicalize_path(&ctx.root);
    let absolute_path = if file_path.is_absolute() {
        canonicalize_path(file_path)
    } else {
        file_path.to_path_buf()
    };

    if absolute_path.is_absolute() && !absolute_path.starts_with(&root) {
        return None;
    }

    let candidate = if absolute_path.is_absolute() {
        absolute_path
            .strip_prefix(&root)
            .map(normalize_snapshot_path)
            .unwrap_or_else(|_| normalize_snapshot_path(&absolute_path))
    } else {
        normalize_snapshot_path(file_path)
    };

    if candidate.is_empty() {
        return None;
    }

    if let Some(file) = ctx
        .snapshot
        .files
        .iter()
        .find(|file| file.path == candidate)
    {
        return Some(file.path.clone());
    }

    let mut suffix_matches: Vec<_> = ctx
        .snapshot
        .files
        .iter()
        .filter(|file| file.path.ends_with(&candidate))
        .collect();

    if suffix_matches.is_empty() {
        return None;
    }

    suffix_matches.sort_by(|a, b| {
        a.path
            .len()
            .cmp(&b.path.len())
            .then_with(|| a.path.cmp(&b.path))
    });

    if suffix_matches.len() > 1 {
        tracing::debug!(
            candidate,
            selected = %suffix_matches[0].path,
            matches = suffix_matches.len(),
            "Ambiguous loctree suffix match; selecting shortest lexical path"
        );
    }

    Some(suffix_matches[0].path.clone())
}

fn directory_in_project(project_root: &Path, dir_path: &Path) -> Option<String> {
    let root = canonicalize_path(project_root);
    let absolute_path = if dir_path.is_absolute() {
        canonicalize_path(dir_path)
    } else {
        dir_path.to_path_buf()
    };

    if absolute_path.is_absolute() && !absolute_path.starts_with(&root) {
        return None;
    }

    let rel = if absolute_path.is_absolute() {
        absolute_path.strip_prefix(&root).ok()?
    } else {
        dir_path
    };

    let normalized = normalize_snapshot_path(rel);
    if normalized.is_empty() {
        return Some(".".to_string());
    }
    Some(normalized)
}

fn best_effort_file_path(project_root: &Path, path: &Path) -> String {
    if let Ok(rel) = path.strip_prefix(project_root) {
        let normalized = normalize_snapshot_path(rel);
        if !normalized.is_empty() {
            return normalized;
        }
    }

    if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
        return file_name.to_string();
    }

    normalize_snapshot_path(path)
}

fn normalize_snapshot_path(path: &Path) -> String {
    let display = path.to_string_lossy().replace('\\', "/");
    display.trim_start_matches("./").to_string()
}

fn normalize_snapshot_str(path: &str) -> String {
    path.trim_start_matches("./").replace('\\', "/")
}

fn canonicalize_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn format_json(value: Value) -> String {
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
}

fn format_sections(sections: Vec<Section>) -> Option<String> {
    if sections.is_empty() {
        return None;
    }

    let mut out = String::new();
    for (idx, section) in sections.iter().enumerate() {
        if idx > 0 {
            out.push_str("\n\n");
        }
        out.push_str("---- LOCTREE ");
        out.push_str(section.title);
        out.push_str(" ----\n");
        out.push_str(section.body.trim_end());
    }

    Some(truncate_context(&out))
}

fn truncate_context(text: &str) -> String {
    let truncated = take_bytes_at_char_boundary(text, MAX_CONTEXT_BYTES);
    if truncated.len() < text.len() {
        tracing::debug!(
            original_len = text.len(),
            truncated_len = truncated.len(),
            "Truncated loctree context to fit limit"
        );
    }
    truncated.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_project() -> (TempDir, PathBuf, PathBuf) {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let root = tempdir.path().join("src");
        std::fs::create_dir_all(&root).expect("create src");
        let file_path = root.join("lib.rs");
        std::fs::write(&file_path, "pub fn hello_world() {}\n").expect("write file");
        (tempdir, root, file_path)
    }

    #[test]
    fn loctree_context_for_read_autoscans() {
        let (_tempdir, _root, file_path) = setup_project();
        let context = loctree_context_for_read_sync(&file_path).expect("loctree context");
        assert!(context.contains("LOCTREE SLICE"));
        assert!(context.contains("LOCTREE IMPACT"));
        assert!(context.contains("lib.rs"));
    }

    #[test]
    fn loctree_context_for_grep_and_exec_read_include_slice() {
        let (_tempdir, root, file_path) = setup_project();

        let grep_context =
            loctree_context_for_grep_sync("hello_world", &file_path).expect("grep context");
        assert!(grep_context.contains("LOCTREE FIND"));
        assert!(grep_context.contains("hello_world"));

        let command = vec![
            "bash".to_string(),
            "-lc".to_string(),
            "cat lib.rs".to_string(),
        ];
        let exec_context = loctree_context_for_exec_sync(&root, &command).expect("exec context");
        assert!(exec_context.contains("LOCTREE SLICE"));
        assert!(exec_context.contains("LOCTREE IMPACT"));
    }

    #[test]
    fn loctree_context_stats_counts_sections() {
        let context = format!(
            "{LOCTREE_FIND_HEADER}\n{{}}\n{LOCTREE_SLICE_HEADER}\n{{}}\n{LOCTREE_IMPACT_HEADER}\n{{}}\n{LOCTREE_FOCUS_HEADER}\n{{}}"
        );
        let stats = loctree_context_stats(Some(&context)).expect("stats");
        assert_eq!(stats.bytes, context.len());
        assert_eq!(stats.find, 1);
        assert_eq!(stats.slice, 1);
        assert_eq!(stats.impact, 1);
        assert_eq!(stats.focus, 1);
        assert_eq!(stats.total_sections(), 4);
    }

    #[test]
    fn loctree_context_stats_ignores_empty_input() {
        assert!(loctree_context_stats(None).is_none());
        assert!(loctree_context_stats(Some(" \n\t")).is_none());
    }
}
