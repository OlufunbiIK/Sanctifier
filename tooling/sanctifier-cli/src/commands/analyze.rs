use crate::commands::webhook::{
    send_scan_completed_webhooks, ScanWebhookPayload, ScanWebhookSummary,
};
use clap::Args;
use colored::*;
use rayon::prelude::*;
use sanctifier_core::finding_codes;
use sanctifier_core::{Analyzer, ContractCallEdge, SanctifyConfig, SizeWarningLevel};
use serde_json;
use std::fs;
use std::path::{Path, PathBuf};


#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Path to the contract directory or Cargo.toml
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    pub format: String,

    /// Limit for ledger entry size in bytes
    #[arg(short, long, default_value = "64000")]
    pub limit: usize,

    /// Path to a custom vulnerability database JSON file
    #[arg(long)]
    pub vuln_db: Option<PathBuf>,

    /// Per-file analysis timeout in seconds (0 = no timeout)
    #[arg(short, long, default_value = "30")]
    pub timeout: u64,

    /// Webhook endpoint(s) to notify when scan completes (Discord/Slack/Teams/custom)
    #[arg(long = "webhook-url")]
    pub webhook_urls: Vec<String>,
}

// ── Per-file result container ────────────────────────────────────────────────

/// All findings produced by analysing a single `.rs` file.
#[derive(Default)]
pub(crate) struct FileAnalysisResult {
    pub(crate) file_path: String,
    pub(crate) call_graph: Vec<ContractCallEdge>,
    pub(crate) collisions: Vec<sanctifier_core::StorageCollisionIssue>,
    pub(crate) size_warnings: Vec<sanctifier_core::SizeWarning>,
    pub(crate) unsafe_patterns: Vec<sanctifier_core::UnsafePattern>,
    pub(crate) auth_gaps: Vec<String>,
    pub(crate) panic_issues: Vec<sanctifier_core::PanicIssue>,
    pub(crate) arithmetic_issues: Vec<sanctifier_core::ArithmeticIssue>,
    pub(crate) custom_matches: Vec<sanctifier_core::CustomRuleMatch>,
    pub(crate) vuln_matches: Vec<VulnMatch>,
    pub(crate) event_issues: Vec<sanctifier_core::EventIssue>,
    pub(crate) unhandled_results: Vec<sanctifier_core::UnhandledResultIssue>,
    pub(crate) upgrade_reports: Vec<sanctifier_core::UpgradeReport>,
    pub(crate) smt_issues: Vec<sanctifier_core::smt::SmtInvariantIssue>,
    pub(crate) sep41_checked_contracts: Vec<String>,
    pub(crate) sep41_issues: Vec<sanctifier_core::Sep41Issue>,
    pub(crate) timed_out: bool,
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub fn exec(args: AnalyzeArgs) -> anyhow::Result<()> {
    let mut path = args.path.clone();
    
    // Normalize path separators: ensure backslashes provided by users familiar with Windows 
    // are converted to forward slashes on Unix systems to allow cross-platform path strings.
    #[cfg(not(windows))]
    {
        let s = path.to_string_lossy();
        if s.contains('\\') {
            path = PathBuf::from(s.replace('\\', "/"));
        }
    }

    let format = &args.format;
    let _limit = args.limit;
    let is_json = format == "json";
    let timeout_secs = args.timeout;

    if !is_soroban_project(&path) {
        if is_json {
            let err = serde_json::json!({
                "error": format!("{:?} is not a valid Soroban project", path),
                "success": false,
            });
            println!("{}", serde_json::to_string_pretty(&err)?);
        } else {
            error!(
                target: "sanctifier",
                path = %path.display(),
                "Invalid Soroban project: missing Cargo.toml with a soroban-sdk dependency"
            );
        }
        std::process::exit(1);
    }

    info!(target: "sanctifier", path = %path.display(), "Valid Soroban project found");
    info!(target: "sanctifier", path = %path.display(), "Analyzing contract");

    let mut config = load_config(&path);
    config.ledger_limit = args.limit;
    let analyzer = Arc::new(Analyzer::new(config));

    // Load vulnerability database
    let vuln_db = Arc::new(match &args.vuln_db {
        Some(db_path) => {
            info!(
                target: "sanctifier",
                path = %db_path.display(),
                "Loading custom vulnerability database"
            );
            VulnDatabase::load(db_path)?
        }
        None => {
            let database = VulnDatabase::load_default();
            info!(
                target: "sanctifier",
                version = %database.version,
                "Loading built-in vulnerability database"
            );
            database
        }
    });

    // ── Phase 1: collect all .rs file paths ──────────────────────────────
    let rs_files = if path.is_dir() {
        collect_rs_files(&path, &analyzer.config.ignore_paths)
    } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
        vec![path.clone()]
    } else {
        vec![]
    };

    let total_files = rs_files.len();

    // ── Phase 2: analyse in parallel with per-file timeout ───────────────
    let counter = Arc::new(AtomicUsize::new(0));
    let timeout_dur = if timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(timeout_secs))
    };

    let mut results: Vec<FileAnalysisResult> = rs_files
        .par_iter()
        .map(|file_path| {
            let idx = counter.fetch_add(1, Ordering::Relaxed) + 1;
            let file_name = file_path.display().to_string();

            // Progress indicator → stderr (safe for JSON piping)
            if !is_json {
                eprintln!("[{}/{}] Analyzing {}", idx, total_files, file_name);
            }

            let content = match fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => return FileAnalysisResult::default(),
            };

            debug!(target: "sanctifier", file = %file_name, "Scanning Rust source file");

            // Clone Arcs for the closure
            let analyzer = Arc::clone(&analyzer);
            let vuln_db = Arc::clone(&vuln_db);
            let file_name_clone = file_name.clone();

            match run_with_timeout(timeout_dur, move || {
                analyze_single_file(&analyzer, &vuln_db, &content, &file_name_clone)
            }) {
                Some(res) => res,
                None => {
                    // Timeout – emit a synthetic finding
                    warn!(
                        target: "sanctifier",
                        file = %file_name,
                        timeout_secs = timeout_secs,
                        "Analysis timed out"
                    );
                    FileAnalysisResult {
                        file_path: file_name,
                        timed_out: true,
                        ..Default::default()
                    }
                }
            }
        })
        .collect();

    // ── Phase 3: sort by file path for deterministic output ──────────────
    results.sort_by(|a, b| a.file_path.cmp(&b.file_path));

    // ── Phase 4: merge into flat vectors ─────────────────────────────────
    let mut collisions = Vec::new();
    let mut call_graph = Vec::new();
    let mut size_warnings = Vec::new();
    let mut unsafe_patterns = Vec::new();
    let mut auth_gaps = Vec::new();
    let mut panic_issues = Vec::new();
    let mut arithmetic_issues = Vec::new();

        }
        call_graph.extend(r.call_graph);
        collisions.extend(r.collisions);
        size_warnings.extend(r.size_warnings);
        unsafe_patterns.extend(r.unsafe_patterns);
        auth_gaps.extend(r.auth_gaps);
        panic_issues.extend(r.panic_issues);
        arithmetic_issues.extend(r.arithmetic_issues);
        custom_matches.extend(r.custom_matches);
        vuln_matches.extend(r.vuln_matches);
        event_issues.extend(r.event_issues);
        unhandled_results.extend(r.unhandled_results);
        upgrade_reports.extend(r.upgrade_reports);
        smt_issues.extend(r.smt_issues);
        sep41_checked_contracts.extend(r.sep41_checked_contracts);
        sep41_issues.extend(r.sep41_issues);
    }

    let total_findings = collisions.len()
        + size_warnings.len()
        + unsafe_patterns.len()
        + auth_gaps.len()
        + panic_issues.len()
        + arithmetic_issues.len()
        + custom_matches.len()
        + event_issues.len()
        + unhandled_results.len()
        + upgrade_reports
            .iter()
            .map(|r| r.findings.len())
            .sum::<usize>()
        + smt_issues.len()
        + sep41_issues.len()
        + timed_out_files.len();

    let has_critical =
        !auth_gaps.is_empty() || panic_issues.iter().any(|p| p.issue_type == "panic!");
    let has_high = !arithmetic_issues.is_empty()
        || !panic_issues.is_empty()
        || !smt_issues.is_empty()
        || !sep41_issues.is_empty()
        || !unhandled_results.is_empty()
        || size_warnings
            .iter()
            .any(|w| w.level == SizeWarningLevel::ExceedsLimit);
    let timestamp = chrono_timestamp();

    let webhook_payload = ScanWebhookPayload {
        event: "scan.completed",
        project_path: path.display().to_string(),
        timestamp_unix: timestamp.clone(),
        summary: ScanWebhookSummary {
            total_findings,
            has_critical,
            has_high,
        },
    };

    if let Err(err) = send_scan_completed_webhooks(&args.webhook_urls, &webhook_payload) {
        warn!(target: "sanctifier", error = %err, "Failed to initialize webhook client");
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let rules_executed: usize = 6;

    if is_json {
        let report = serde_json::json!({

            "storage_collisions": collisions,
            "call_graph": call_graph,
            "ledger_size_warnings": size_warnings,
            "unsafe_patterns": unsafe_patterns,
            "auth_gaps": auth_gaps,
            "panic_issues": panic_issues,
            "arithmetic_issues": arithmetic_issues,
            "custom_rules": custom_matches,
            "event_issues": event_issues,
            "unhandled_results": unhandled_results,
            "upgrade_reports": upgrade_reports,
            "smt_issues": smt_issues,
            "sep41_checked_contracts": sep41_checked_contracts,
            "sep41_issues": sep41_issues,
            "vulnerability_db_matches": vuln_matches,
            "vulnerability_db_version": vuln_db.version,
            "timed_out_files": timed_out_files,
            "metadata": {
                "version": env!("CARGO_PKG_VERSION"),
                "timestamp": timestamp,
                "project_path": path.display().to_string(),
                "format": "sanctifier-ci-v1",
                "timeout_secs": timeout_secs,
            },
            "error_codes": finding_codes::all_finding_codes(),
            "summary": {
                "total_findings": total_findings,
                "storage_collisions": collisions.len(),
                "auth_gaps": auth_gaps.len(),
                "panic_issues": panic_issues.len(),
                "arithmetic_issues": arithmetic_issues.len(),
                "size_warnings": size_warnings.len(),
                "unsafe_patterns": unsafe_patterns.len(),
                "custom_rule_matches": custom_matches.len(),
                "event_issues": event_issues.len(),
                "unhandled_results": unhandled_results.len(),
                "smt_issues": smt_issues.len(),
                "sep41_issues": sep41_issues.len(),
                "timed_out_files": timed_out_files.len(),
                "has_critical": has_critical,
                "has_high": has_high,
            },
            "findings": {
                "storage_collisions": collisions.iter().map(|c| serde_json::json!({
                    "code": finding_codes::STORAGE_COLLISION,
                    "key_value": c.key_value,
                    "key_type": c.key_type,
                    "location": c.location,
                    "message": c.message,
                })).collect::<Vec<_>>(),
                "ledger_size_warnings": size_warnings.iter().map(|w| serde_json::json!({
                    "code": finding_codes::LEDGER_SIZE_RISK,
                    "struct_name": w.struct_name,
                    "estimated_size": w.estimated_size,
                    "limit": w.limit,
                    "level": w.level,
                })).collect::<Vec<_>>(),
                "unsafe_patterns": unsafe_patterns.iter().map(|p| serde_json::json!({
                    "code": finding_codes::UNSAFE_PATTERN,
                    "pattern_type": p.pattern_type,
                    "line": p.line,
                    "snippet": p.snippet,
                })).collect::<Vec<_>>(),
                "auth_gaps": auth_gaps.iter().map(|g| serde_json::json!({
                    "code": finding_codes::AUTH_GAP,
                    "function": g,
                })).collect::<Vec<_>>(),
                "panic_issues": panic_issues.iter().map(|p| serde_json::json!({
                    "code": finding_codes::PANIC_USAGE,
                    "function_name": p.function_name,
                    "issue_type": p.issue_type,
                    "location": p.location,
                })).collect::<Vec<_>>(),
                "arithmetic_issues": arithmetic_issues.iter().map(|a| serde_json::json!({
                    "code": finding_codes::ARITHMETIC_OVERFLOW,
                    "function_name": a.function_name,
                    "operation": a.operation,
                    "suggestion": a.suggestion,
                    "location": a.location,
                })).collect::<Vec<_>>(),
                "custom_rules": custom_matches.iter().map(|m| serde_json::json!({
                    "code": finding_codes::CUSTOM_RULE_MATCH,
                    "rule_name": m.rule_name,
                    "line": m.line,
                    "snippet": m.snippet,
                    "severity": m.severity,
                })).collect::<Vec<_>>(),
                "event_issues": event_issues.iter().map(|e| serde_json::json!({
                    "code": finding_codes::EVENT_INCONSISTENCY,
                    "event_name": e.event_name,
                    "issue_type": e.issue_type,
                    "location": e.location,
                    "message": e.message,
                })).collect::<Vec<_>>(),
                "unhandled_results": unhandled_results.iter().map(|r| serde_json::json!({
                    "code": finding_codes::UNHANDLED_RESULT,
                    "function_name": r.function_name,
                    "call_expression": r.call_expression,
                    "location": r.location,
                    "message": r.message,
                })).collect::<Vec<_>>(),
                "upgrade_risks": upgrade_reports.iter().flat_map(|r| &r.findings).map(|f| serde_json::json!({
                    "code": finding_codes::UPGRADE_RISK,
                    "category": f.category,
                    "function_name": f.function_name,
                    "location": f.location,
                    "message": f.message,
                    "suggestion": f.suggestion,
                })).collect::<Vec<_>>(),
                "smt_issues": smt_issues.iter().map(|s| serde_json::json!({
                    "code": finding_codes::SMT_INVARIANT_VIOLATION,
                    "function_name": s.function_name,
                    "description": s.description,
                    "location": s.location,
                })).collect::<Vec<_>>(),
                "sep41_issues": sep41_issues.iter().map(|issue| serde_json::json!({
                    "code": finding_codes::SEP41_INTERFACE_DEVIATION,
                    "function_name": issue.function_name,
                    "kind": issue.kind,
                    "location": issue.location,
                    "message": issue.message,
                    "expected_signature": issue.expected_signature,
                    "actual_signature": issue.actual_signature,
                })).collect::<Vec<_>>(),
                "timeouts": timed_out_files.iter().map(|f| serde_json::json!({
                    "code": finding_codes::ANALYSIS_TIMEOUT,
                    "file": f,
                    "message": format!("Analysis timed out after {}s", timeout_secs),
                })).collect::<Vec<_>>(),
            },
        });
        println!("{}", serde_json::to_string_pretty(&report)?);

        if has_critical || has_high {
            std::process::exit(1);
        }
        return Ok(());
    }

    // ── Text output ──────────────────────────────────────────────────────

    if !timed_out_files.is_empty() {
        println!(
            "\n{} {} file(s) timed out ({}s limit):",
            "⏱️".yellow(),
            timed_out_files.len(),
            timeout_secs
        );
        for f in &timed_out_files {
            println!(
                "   {} [{}] {}",
                "->".red(),
                finding_codes::ANALYSIS_TIMEOUT.bold(),
                f
            );
        }
    }

    if collisions.is_empty() {
        println!("\n{} No storage key collisions found.", "✅".green());
    } else {
        println!(
            "\n{} Found potential Storage Key Collisions!",
            "⚠️".yellow()
        );
        for collision in collisions {
            println!(
                "   {} [{}] Value: {}",
                "->".red(),
                finding_codes::STORAGE_COLLISION.bold(),
                collision.key_value.bold()
            );
            println!("      Type: {}", collision.key_type);
            println!("      Location: {}", collision.location);
            println!("      Message: {}", collision.message);
        }
    }

    if auth_gaps.is_empty() {
        println!("{} No authentication gaps found.", "✅".green());
    } else {
        println!("\n{} Found potential Authentication Gaps!", "⚠️".yellow());
        for gap in auth_gaps {
            println!(
                "   {} [{}] Function: {}",
                "->".red(),
                finding_codes::AUTH_GAP.bold(),
                gap.bold()
            );
        }
    }

    if panic_issues.is_empty() {
        println!("{} No explicit Panics/Unwraps found.", "✅".green());
    } else {
        println!("\n{} Found explicit Panics/Unwraps!", "⚠️".yellow());
        for issue in panic_issues {
            println!(
                "   {} [{}] Type: {}",
                "->".red(),
                finding_codes::PANIC_USAGE.bold(),
                issue.issue_type.bold()
            );
            println!("      Location: {}", issue.location);
        }
    }

    if arithmetic_issues.is_empty() {
        println!("{} No unchecked Arithmetic Operations found.", "✅".green());
    } else {
        println!("\n{} Found unchecked Arithmetic Operations!", "⚠️".yellow());
        for issue in arithmetic_issues {
            println!(
                "   {} [{}] Op: {}",
                "->".red(),
                finding_codes::ARITHMETIC_OVERFLOW.bold(),
                issue.operation.bold()
            );
            println!("      Location: {}", issue.location);
        }
    }

    if size_warnings.is_empty() {
        println!("{} No ledger size issues found.", "✅".green());
    } else {
        println!("\n{} Found Ledger Size Warnings!", "⚠️".yellow());
        for warning in size_warnings {
            println!(
                "   {} [{}] Struct: {}",
                "->".red(),
                finding_codes::LEDGER_SIZE_RISK.bold(),
                warning.struct_name.bold()
            );
            println!("      Size: {} bytes", warning.estimated_size);
        }
    }

    if !event_issues.is_empty() {
        println!(
            "\n{} Found Event Consistency/Optimization issues!",
            "⚠️".yellow()
        );
        for issue in &event_issues {
            println!(
                "   {} [{}] Event: {}",
                "->".red(),
                finding_codes::EVENT_INCONSISTENCY.bold(),
                issue.event_name.bold()
            );
            println!("      Type: {:?}", issue.issue_type);
            println!("      Location: {}", issue.location);
            println!("      Message: {}", issue.message);
        }
    }

    if !unhandled_results.is_empty() {
        println!("\n{} Found Unhandled Result issues!", "⚠️".yellow());
        for issue in &unhandled_results {
            println!(
                "   {} [{}] Function: {}",
                "->".red(),
                finding_codes::UNHANDLED_RESULT.bold(),
                issue.function_name.bold()
            );
            println!("      Call: {}", issue.call_expression);
            println!("      Location: {}", issue.location);
            println!("      Message: {}", issue.message);
        }
    }

    let total_upgrade_findings: usize = upgrade_reports.iter().map(|r| r.findings.len()).sum();
    if total_upgrade_findings > 0 {
        println!("\n{} Found Upgrade/Admin Risk issues!", "⚠️".yellow());
        for report in &upgrade_reports {
            for finding in &report.findings {
                println!(
                    "   {} [{}] Category: {:?}",
                    "->".red(),
                    finding_codes::UPGRADE_RISK.bold(),
                    finding.category
                );
                if let Some(f_name) = &finding.function_name {
                    println!("      Function: {}", f_name);
                }
                println!("      Location: {}", finding.location);
                println!("      Message: {}", finding.message);
                println!("      Suggestion: {}", finding.suggestion);
            }
        }
    }

    if !smt_issues.is_empty() {
        println!("\n{} Found Formal Verification (SMT) issues!", "❌".red());
        for issue in &smt_issues {
            println!(
                "   {} [{}] Function: {}",
                "->".red(),
                finding_codes::SMT_INVARIANT_VIOLATION.bold(),
                issue.function_name.bold()
            );
            println!("      Description: {}", issue.description);
            println!("      Location: {}", issue.location);
        }
    }

    if !sep41_checked_contracts.is_empty() && sep41_issues.is_empty() {
        println!("{} SEP-41 token interface verified exactly.", "✅".green());
    } else if !sep41_issues.is_empty() {
        println!("\n{} Found SEP-41 Interface Deviations!", "⚠️".yellow());
        for issue in &sep41_issues {
            println!(
                "   {} [{}] Function: {}",
                "->".red(),
                finding_codes::SEP41_INTERFACE_DEVIATION.bold(),
                issue.function_name.bold()
            );
            println!("      Kind: {:?}", issue.kind);
            println!("      Location: {}", issue.location);
            println!("      Message: {}", issue.message);
            println!("      Expected: {}", issue.expected_signature);
            if let Some(actual) = &issue.actual_signature {
                println!("      Actual: {}", actual);
            }
        }
    }

    // Vulnerability database matches
    if vuln_matches.is_empty() {
        println!(
            "{} No known vulnerability patterns matched (DB v{}).",
            "✅".green(),
            vuln_db.version
        );
    } else {
        println!(
            "\n{} Found {} known vulnerability pattern(s) (DB v{})!",
            "🛡️".red(),
            vuln_matches.len(),
            vuln_db.version
        );
        for m in &vuln_matches {
            let sev_icon = match m.severity.as_str() {
                "critical" => "❌".red(),
                "high" => "🔴".red(),
                "medium" => "⚠️".yellow(),
                _ => "ℹ️".blue(),
            };
            println!(
                "   {} [{}] {} ({})",
                sev_icon,
                m.vuln_id.bold(),
                m.name.bold(),
                m.severity.to_uppercase()
            );
            println!("      File: {}:{}", m.file, m.line);
            println!("      {}", m.description);
            println!("      Suggestion: {}", m.recommendation);
        }
    }

    println!("\n{} Static analysis complete.", "✨".green());
    println!(
        "⏱  Analysis completed in {:.1}s ({} files)",
        duration_ms as f64 / 1000.0,
        files_analyzed
    );

    Ok(())
}

// ── Analyse one file (runs inside thread / rayon task) ───────────────────────

pub(crate) fn analyze_single_file(
    analyzer: &Analyzer,
    vuln_db: &VulnDatabase,
    content: &str,
    file_name: &str,
) -> FileAnalysisResult {
    let contract_name = infer_contract_name(content).unwrap_or_else(|| {
        Path::new(file_name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>")
            .to_string()
    });
    let mut res = FileAnalysisResult {
        file_path: file_name.to_string(),
        call_graph: analyzer.scan_invoke_contract_calls(content, &contract_name, file_name),
        ..Default::default()
    };

    let mut c = analyzer.scan_storage_collisions(content);
    for i in &mut c {
        i.location = format!("{}:{}", file_name, i.location);
    }
    res.collisions = c;

    res.size_warnings = analyzer.analyze_ledger_size(content);

    let mut u = analyzer.analyze_unsafe_patterns(content);
    for i in &mut u {
        i.snippet = format!("{}:{}", file_name, i.snippet);
    }
    res.unsafe_patterns = u;

    for g in analyzer.scan_auth_gaps(content) {
        res.auth_gaps.push(format!("{}:{}", file_name, g));
    }

    let mut p = analyzer.scan_panics(content);
    for i in &mut p {
        i.location = format!("{}:{}", file_name, i.location);
    }
    res.panic_issues = p;

    let mut a = analyzer.scan_arithmetic_overflow(content);
    for i in &mut a {
        i.location = format!("{}:{}", file_name, i.location);
    }
    res.arithmetic_issues = a;

    let mut custom = analyzer.analyze_custom_rules(content, &analyzer.config.custom_rules);
    for m in &mut custom {
        m.snippet = format!("{}:{}: {}", file_name, m.line, m.snippet);
    }
    res.custom_matches = custom;

    res.vuln_matches = vuln_db.scan(content, file_name);

    let mut e = analyzer.scan_events(content);
    for i in &mut e {
        i.location = format!("{}:{}", file_name, i.location);
    }
    res.event_issues = e;

    let mut r = analyzer.scan_unhandled_results(content);
    for i in &mut r {
        i.location = format!("{}:{}", file_name, i.location);
    }
    res.unhandled_results = r;

    let mut up = analyzer.analyze_upgrade_patterns(content);
    for f in &mut up.findings {
        f.location = format!("{}:{}", file_name, f.location);
    }
    res.upgrade_reports.push(up);

    let mut smt = analyzer.verify_smt_invariants(content);
    for i in &mut smt {
        i.location = format!("{}:{}", file_name, i.location);
    }
    res.smt_issues = smt;

    let sep41_report = analyzer.verify_sep41_interface(content);
    if sep41_report.candidate {
        res.sep41_checked_contracts.push(file_name.to_string());
        for mut issue in sep41_report.issues {
            issue.location = format!("{}:{}", file_name, issue.location);
            res.sep41_issues.push(issue);
        }
    }

    res
}

fn infer_contract_name(source: &str) -> Option<String> {
    let mut saw_contract_attr = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[contract]") {
            saw_contract_attr = true;
            continue;
        }
        if !saw_contract_attr {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("pub struct ") {
            return Some(
                rest.trim_end_matches(';')
                    .split_whitespace()
                    .next()?
                    .to_string(),
            );
        }
        if let Some(rest) = trimmed.strip_prefix("struct ") {
            return Some(
                rest.trim_end_matches(';')
                    .split_whitespace()
                    .next()?
                    .to_string(),
            );
        }
    }
    None
}

// ── Per-file timeout wrapper ─────────────────────────────────────────────────

/// Run `f` on a dedicated OS thread with an optional deadline.
/// Returns `None` if the deadline elapses before `f` completes.
pub(crate) fn run_with_timeout<F, R>(timeout: Option<Duration>, f: F) -> Option<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    match timeout {
        None => Some(f()),
        Some(dur) => {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = f();
                let _ = tx.send(result);
            });
            rx.recv_timeout(dur).ok()
        }
    }
}

// ── Recursive file collection ────────────────────────────────────────────────

/// Walk `dir` recursively, returning all `.rs` file paths while honouring
/// `ignore_paths`.
pub(crate) fn collect_rs_files(dir: &Path, ignore_paths: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let ignore_patterns: Vec<PathBuf> = ignore_paths.iter().map(PathBuf::from).collect();
    collect_rs_files_inner(dir, &ignore_patterns, &mut out);
    out
}

fn collect_rs_files_inner(dir: &Path, ignore_patterns: &[PathBuf], out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let is_ignored = ignore_patterns.iter().any(|p| path.ends_with(p));
            if !is_ignored {
                collect_rs_files_inner(&path, ignore_patterns, out);
            }
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn chrono_timestamp() -> String {
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    format!("{}", secs)
}

pub(crate) fn load_config(path: &Path) -> SanctifyConfig {
    let mut current = if path.is_file() {
        path.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        path.to_path_buf()
    };

    loop {
        let config_path = current.join(".sanctify.toml");
        if config_path.exists() {
            if let Ok(content) = fs::read_to_string(&config_path) {
                if let Ok(config) = toml::from_str(&content) {
                    return config;
                }
            }
        }
        if !current.pop() {
            break;
        }
    }
    SanctifyConfig::default()
}

pub(crate) fn is_soroban_project(path: &Path) -> bool {
    // Basic heuristics for tests.
    if path.extension().and_then(|s| s.to_str()) == Some("rs") {
        return true;
    }
    let cargo_toml_path = if path.is_dir() {
        path.join("Cargo.toml")
    } else {
        path.to_path_buf()
    };
    cargo_toml_path.exists()
}
