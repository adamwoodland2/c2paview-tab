//! c2paview-helper: reads and validates the C2PA Content Credentials of one file and
//! prints a plain, line-oriented description of what to show in the Explorer tab.
//!
//! This runs as a separate, short-lived process launched by the shell extension so
//! that a malformed or hostile file can never take Explorer down with it. It never
//! touches the network: no HTTP client is compiled in, remote manifest fetching and
//! OCSP are disabled, and the trust lists are read from a local directory.
//!
//! Usage: c2paview-helper <file> [--trust-dir DIR] [--json]
//!
//! Output protocol (UTF-8, one record per line, fields separated by TAB):
//!   V     <protocol version>
//!   META  <key> <value>                 diagnostics (helper version, timings, trust snapshot)
//!   STATE <trusted|untrusted|unverified|incomplete|invalid|malformed|remote|none|unsupported|error>
//!   HEAD  <headline>                    one line, the L2 "status" summary
//!   TEXT  <paragraph>                   zero or more explanatory lines
//!   NODE  <depth> <x|-> <text>          tree items; 'x' = expanded by default
//!   JSON  <compact manifest-store json> for the "Copy manifest JSON" button
//!   END
//! Text fields are sanitised: control and bidi-override characters removed, length capped.

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use c2pa::{Context, Reader, ValidationState};
use serde_json::Value;

const PROTOCOL_VERSION: u32 = 1;
const MAX_TEXT_CHARS: usize = 400;
const MAX_NODES: usize = 3000;
const MAX_INGREDIENT_DEPTH: usize = 5;
const DEBRIS_SCAN_CAP: u64 = 64 * 1024 * 1024;

// ------------------------------------------------------------------ CLI

struct Opts {
    file: PathBuf,
    trust_dir: Option<PathBuf>,
    json: bool,
}

fn parse_args() -> Result<Opts, String> {
    let mut file = None;
    let mut trust_dir = None;
    let mut json = false;
    let mut args = std::env::args_os().skip(1);
    let mut only_positional = false;
    while let Some(a) = args.next() {
        let s = a.to_string_lossy().into_owned();
        if !only_positional && s == "--" {
            only_positional = true;
        } else if !only_positional && s == "--trust-dir" {
            let v = args.next().ok_or("--trust-dir needs a directory")?;
            trust_dir = Some(PathBuf::from(v));
        } else if !only_positional && s == "--json" {
            json = true;
        } else if !only_positional && s.starts_with("--") {
            return Err(format!("unknown option {s}"));
        } else if file.is_none() {
            file = Some(PathBuf::from(a));
        } else {
            return Err("only one file may be given".into());
        }
    }
    Ok(Opts { file: file.ok_or("usage: c2paview-helper <file> [--trust-dir DIR] [--json]")?, trust_dir, json })
}

// ------------------------------------------------------------------ output

struct Out {
    lines: Vec<String>,
    nodes: usize,
}

impl Out {
    fn new() -> Self {
        let mut o = Out { lines: Vec::new(), nodes: 0 };
        o.lines.push(format!("V\t{PROTOCOL_VERSION}"));
        o
    }
    fn rec(&mut self, tag: &str, fields: &[&str]) {
        let mut s = String::from(tag);
        for f in fields {
            s.push('\t');
            s.push_str(&clean(f));
        }
        self.lines.push(s);
    }
    fn meta(&mut self, k: &str, v: &str) { self.rec("META", &[k, v]); }
    fn state(&mut self, s: &str) { self.rec("STATE", &[s]); }
    fn head(&mut self, s: &str) { self.rec("HEAD", &[s]); }
    fn text(&mut self, s: &str) { self.rec("TEXT", &[s]); }
    fn node(&mut self, depth: usize, expanded: bool, text: &str) {
        if self.nodes >= MAX_NODES {
            if self.nodes == MAX_NODES {
                self.lines.push("NODE\t0\t-\t… (output truncated)".into());
                self.nodes += 1;
            }
            return;
        }
        self.nodes += 1;
        let d = depth.to_string();
        self.rec("NODE", &[&d, if expanded { "x" } else { "-" }, text]);
    }
    fn json(&mut self, compact: &str) {
        // Already JSON-escaped by serde: no raw control characters can appear.
        self.lines.push(format!("JSON\t{compact}"));
    }
    fn finish(mut self) -> String {
        self.lines.push("END".into());
        let mut s = self.lines.join("\n");
        s.push('\n');
        s
    }
}

/// Strip characters that could break the line protocol or spoof the display
/// (C2PA guidance: filter user-generated text in manifests before showing it).
fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_TEXT_CHARS + 8));
    let mut n = 0usize;
    for c in s.chars() {
        let drop = matches!(c,
            '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' |
            '\u{FEFF}' | '\u{061C}' | '\u{2028}' | '\u{2029}' | '\u{FFF9}'..='\u{FFFB}' |
            '\u{E0000}'..='\u{E007F}');
        let ch = if c.is_control() || drop { ' ' } else { c };
        if ch == ' ' && out.ends_with(' ') { continue; }
        if n >= MAX_TEXT_CHARS {
            out.push('…');
            break;
        }
        out.push(ch);
        n += 1;
    }
    out.trim().to_string()
}

// ------------------------------------------------------------------ trust lists

struct TrustInfo {
    settings_json: String,
    loaded: bool,
    snapshot: Option<String>,
}

fn read_text(dir: &Path, name: &str) -> Option<String> {
    fs::read_to_string(dir.join(name)).ok().filter(|s| !s.trim().is_empty())
}

fn load_trust(dir: Option<&Path>) -> TrustInfo {
    let mut anchors = String::new();
    let mut allowed = None;
    let mut config = None;
    let mut snapshot = None;
    if let Some(d) = dir {
        for f in ["c2pa-trust-list.pem", "c2pa-tsa-trust-list.pem", "interim-anchors.pem"] {
            if let Some(t) = read_text(d, f) {
                anchors.push_str(&t);
                anchors.push('\n');
            }
        }
        allowed = read_text(d, "interim-allowed.sha256.txt");
        config = read_text(d, "store.cfg");
        snapshot = read_text(d, "VERSION.txt").map(|s| s.lines().next().unwrap_or("").trim().to_string());
    }
    let loaded = !anchors.is_empty() || allowed.is_some();
    let verify = serde_json::json!({
        "verify_after_reading": true,
        "verify_trust": loaded,
        "ocsp_fetch": false,
        "remote_manifest_fetch": false
    });
    let mut settings = serde_json::json!({ "verify": verify });
    if loaded {
        let mut trust = serde_json::Map::new();
        if !anchors.is_empty() { trust.insert("trust_anchors".into(), Value::String(anchors)); }
        if let Some(a) = allowed { trust.insert("allowed_list".into(), Value::String(a)); }
        if let Some(c) = config { trust.insert("trust_config".into(), Value::String(c)); }
        settings["trust"] = Value::Object(trust);
    }
    TrustInfo { settings_json: settings.to_string(), loaded, snapshot }
}

// ------------------------------------------------------------------ helpers over the JSON store

fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str).map(str::trim).filter(|x| !x.is_empty())
}

fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn is_success_code(code: &str) -> bool {
    code.ends_with(".validated")
        || code.ends_with(".match")
        || code.ends_with(".trusted")
        || code.ends_with(".insideValidity")
        || code.ends_with(".notRevoked")
        || code.ends_with(".accessible")
        || code.ends_with(".additionalExclusionsPresent")
}

fn is_informational_code(code: &str) -> bool {
    matches!(code,
        "signingCredential.ocsp.skipped" | "signingCredential.ocsp.inaccessible" | "signingCredential.ocsp.unknown" |
        "algorithm.deprecated" | "manifest.unreferenced" | "ingredient.unknownProvenance" | "manifest.unknownProvenance")
}

/// Codes the reference implementation tolerates for "Valid": the file is intact but
/// the signer is simply not on the list we were given.
fn is_trust_only_code(code: &str) -> bool {
    matches!(code, "signingCredential.untrusted" | "timeStamp.untrusted" | "cawg.x509.credential.untrusted" | "cawg.ica.untrusted_issuer")
}

fn is_tamper_code(code: &str) -> bool {
    matches!(code,
        "assertion.dataHash.mismatch" | "assertion.bmffHash.mismatch" | "assertion.boxesHash.mismatch" |
        "assertion.collectionHash.mismatch" | "assertion.hashedURI.mismatch" | "hashedURI.mismatch" |
        "claimSignature.mismatch" | "ingredient.hashedURI.mismatch")
}

fn code_hint(code: &str) -> &'static str {
    match code {
        "assertion.dataHash.mismatch" | "assertion.bmffHash.mismatch" | "assertion.boxesHash.mismatch" =>
            "the file's content has been changed since it was signed",
        "assertion.hashedURI.mismatch" | "hashedURI.mismatch" => "part of the credential was altered after signing",
        "claimSignature.mismatch" => "the signature does not match the credential",
        "claimSignature.missing" => "the credential has no signature",
        "signingCredential.untrusted" => "the signing certificate is not on the trust list",
        "signingCredential.expired" => "the signing certificate had expired",
        "signingCredential.invalid" => "the signing certificate is not valid for signing credentials",
        "signingCredential.ocsp.revoked" => "the signing certificate was revoked",
        "signingCredential.ocsp.skipped" => "revocation was not checked (offline)",
        "claimSignature.outsideValidity" => "signed outside the certificate's validity period",
        "timeStamp.mismatch" => "the trusted timestamp does not match the signature",
        "timeStamp.untrusted" => "the timestamp authority is not on the trust list",
        "timeStamp.outsideValidity" => "the timestamp is outside its certificate's validity period",
        "timeStamp.malformed" => "the trusted timestamp could not be read",
        "ingredient.manifest.missing" => "an ingredient's credentials are referenced but missing",
        "ingredient.manifest.mismatch" => "an ingredient's credentials changed after it was used",
        "ingredient.unknownProvenance" => "an ingredient had no credentials of its own",
        "ingredient.hashedURI.mismatch" => "an ingredient reference was altered after signing",
        "manifest.unreferenced" => "a credential in the file is not linked to the active one",
        "algorithm.deprecated" => "uses a deprecated cryptographic algorithm",
        "algorithm.unsupported" => "uses a cryptographic algorithm this reader does not support",
        "claim.hardBindings.missing" => "the credential is not bound to the file content",
        "assertion.missing" | "assertion.required.missing" => "a required part of the credential is missing",
        "assertion.undeclared" => "the credential contains an undeclared part",
        "general.error" => "the credential could not be read",
        _ => "",
    }
}

fn where_hint(url: &str) -> Option<String> {
    let i = url.find("/c2pa.assertions/")?;
    let rest = &url[i + "/c2pa.assertions/".len()..];
    let name = rest.split('/').next().unwrap_or("");
    let base = name.split("__").next().unwrap_or(name);
    let base = base.trim_end_matches(".v2").trim_end_matches(".v3");
    Some(match base {
        "c2pa.hash.data" => "the hash covering the file's content".to_string(),
        "c2pa.hash.boxes" => "the hash covering the file structure".to_string(),
        "c2pa.hash.bmff" => "the hash covering the video/audio container".to_string(),
        "c2pa.hash.collection" => "the hash covering the file collection".to_string(),
        "c2pa.thumbnail.claim.jpeg" | "c2pa.thumbnail.claim.png" => "the embedded thumbnail".to_string(),
        "c2pa.thumbnail.ingredient.jpeg" | "c2pa.thumbnail.ingredient.png" => "an ingredient's thumbnail".to_string(),
        "c2pa.actions" => "the recorded edit history".to_string(),
        "c2pa.ingredient" => "an ingredient reference".to_string(),
        other => format!("the \"{other}\" section"),
    })
}

fn status_line(st: &Value) -> String {
    let code = s(st, "code").unwrap_or("?");
    let mut line = code.to_string();
    let hint = code_hint(code);
    if !hint.is_empty() {
        line.push_str(" – ");
        line.push_str(hint);
    } else if let Some(e) = s(st, "explanation") {
        line.push_str(" – ");
        line.push_str(e);
    }
    if let Some(w) = s(st, "url").and_then(where_hint) {
        line.push_str(" (where: ");
        line.push_str(&w);
        line.push(')');
    }
    line
}

struct Statuses {
    failures: Vec<Value>,
    informational: Vec<Value>,
    successes: usize,
}

/// Split status codes into failure / informational / success, preferring the explicit
/// v2 `validation_results` lists and falling back to classifying the flat v1 list.
fn split_statuses(results: Option<&Value>, flat: &[Value]) -> Statuses {
    if let Some(r) = results {
        let am = r.get("activeManifest").unwrap_or(&Value::Null);
        return Statuses {
            failures: arr(am, "failure").to_vec(),
            informational: arr(am, "informational").to_vec(),
            successes: arr(am, "success").len(),
        };
    }
    let mut st = Statuses { failures: vec![], informational: vec![], successes: 0 };
    for v in flat {
        let code = s(v, "code").unwrap_or("");
        if is_success_code(code) { st.successes += 1; }
        else if is_informational_code(code) { st.informational.push(v.clone()); }
        else { st.failures.push(v.clone()); }
    }
    st
}

fn ingredient_failures(store: &Value) -> Vec<Value> {
    let mut out = vec![];
    if let Some(deltas) = store.get("validation_results").and_then(|r| r.get("ingredientDeltas")).and_then(Value::as_array) {
        for d in deltas {
            for f in arr(d.get("validationDeltas").unwrap_or(&Value::Null), "failure") {
                if !s(f, "code").map(is_trust_only_code).unwrap_or(false) {
                    out.push(f.clone());
                }
            }
        }
    }
    out
}

fn fmt_time(iso: &str) -> String {
    // Expect RFC 3339: YYYY-MM-DDTHH:MM[:SS[.fff]](Z|±HH:MM)
    let b = iso.as_bytes();
    let ok = b.len() >= 16
        && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit) && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit) && (b[10] == b'T' || b[10] == b' ')
        && b[11..13].iter().all(u8::is_ascii_digit) && b[13] == b':'
        && b[14..16].iter().all(u8::is_ascii_digit);
    if !ok { return iso.to_string(); }
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let month: usize = iso[5..7].parse().unwrap_or(0);
    let day: u32 = iso[8..10].parse().unwrap_or(0);
    if !(1..=12).contains(&month) { return iso.to_string(); }
    let tail = &iso[16..];
    let zone = if tail.ends_with('Z') || tail.ends_with("+00:00") || tail.is_empty() {
        "UTC".to_string()
    } else if let Some(p) = tail.rfind(['+', '-']) {
        format!("UTC{}", &tail[p..])
    } else {
        String::new()
    };
    format!("{} {} {}, {} {}", day, MONTHS[month - 1], &iso[..4], &iso[11..16], zone).trim().to_string()
}

fn fmt_bytes(n: u64) -> String {
    if n >= 1 << 30 { format!("{:.1} GB", n as f64 / (1u64 << 30) as f64) }
    else if n >= 1 << 20 { format!("{:.1} MB", n as f64 / (1u64 << 20) as f64) }
    else { format!("{} KB", n.div_ceil(1024)) }
}

// ------------------------------------------------------------------ manifest rendering

fn action_label(action: &str) -> String {
    match action {
        "c2pa.created" => "Created".into(),
        "c2pa.opened" => "Opened".into(),
        "c2pa.saved" => "Saved".into(),
        "c2pa.color_adjustments" | "c2pa.filtered" => "Colour adjustments (brightness, tone, filters)".into(),
        "c2pa.cropped" => "Cropped".into(),
        "c2pa.resized" => "Resized".into(),
        "c2pa.orientation" => "Rotated or flipped".into(),
        "c2pa.edited" => "Edited".into(),
        "c2pa.edited.metadata" => "Metadata edited".into(),
        "c2pa.drawing" => "Drawing or painting".into(),
        "c2pa.placed" => "Compositing (merging, layering)".into(),
        "c2pa.removed" => "Content removed".into(),
        "c2pa.transcoded" | "c2pa.converted" => "Format conversion".into(),
        "c2pa.published" => "Published".into(),
        "c2pa.repackaged" => "Repackaged".into(),
        "c2pa.redacted" => "Information redacted".into(),
        "c2pa.translated" => "Translated".into(),
        "c2pa.unknown" => "Unknown or unrecorded changes".into(),
        "c2pa.deleted" => "Deleted".into(),
        "c2pa.dubbed" => "Dubbed".into(),
        "c2pa.managed" => "Managed".into(),
        "c2pa.printed" => "Printed".into(),
        "c2pa.produced" => "Produced".into(),
        "c2pa.watermarked" => "Watermarked".into(),
        other => {
            let t = other.trim_start_matches("c2pa.").replace(['_', '.'], " ");
            let mut c = t.chars();
            match c.next() { Some(f) => f.to_uppercase().collect::<String>() + c.as_str(), None => String::new() }
        }
    }
}

/// IPTC digital source type → the plain wording the C2PA UX guidance asks for.
fn source_type_label(dst: &str) -> Option<&'static str> {
    let key = dst.rsplit('/').next().unwrap_or(dst);
    Some(match key {
        "trainedAlgorithmicMedia" => "Fully generated with AI",
        "compositeWithTrainedAlgorithmicMedia" => "Partially edited using AI",
        "algorithmicallyEnhanced" => "Enhanced by software (not generative AI)",
        "compositeSynthetic" => "Composite including synthetic (non-AI) elements",
        "algorithmicMedia" => "Generated by software (not AI)",
        "digitalCapture" => "Captured by a camera or recording device",
        "negativeFilm" | "positiveFilm" | "print" => "Scanned or photographed from film or print",
        "digitalCreation" | "digitalArt" => "Created digitally by a person",
        "computationalCapture" => "Captured by a camera using computational photography",
        "humanEdits" => "Edited by a person",
        "screenCapture" => "Screen capture",
        "composite" | "compositeCapture" => "Composite of several sources",
        "virtualRecording" => "Recorded from a virtual environment",
        _ => return None,
    })
}

fn agent_name(v: &Value) -> Option<String> {
    match v {
        Value::String(x) => Some(x.trim().to_string()).filter(|x| !x.is_empty()),
        Value::Object(_) => {
            let name = s(v, "name")?;
            Some(match s(v, "version") { Some(ver) => format!("{name} {ver}"), None => name.to_string() })
        }
        _ => None,
    }
}

fn claim_generator(m: &Value) -> Option<String> {
    if let Some(list) = m.get("claim_generator_info").and_then(Value::as_array) {
        let names: Vec<String> = list.iter().filter_map(agent_name).collect();
        if !names.is_empty() { return Some(names.join(", ")); }
    }
    s(m, "claim_generator").map(|cg| cg.split('(').next().unwrap_or(cg).trim().replace(['_', '/'], " "))
}

struct ManifestFacts {
    ai: Option<&'static str>,
}

/// Rank AI disclosures so a fully-generated ingredient does not get lost among edits.
fn ai_rank(label: &str) -> u8 {
    match label {
        "Fully generated with AI" => 3,
        "Partially edited using AI" => 2,
        _ => 1,
    }
}

fn render_manifest(out: &mut Out, store: &Value, label: &str, depth: usize, visited: &mut HashSet<String>) -> ManifestFacts {
    let mut facts = ManifestFacts { ai: None };
    let manifests = store.get("manifests").unwrap_or(&Value::Null);
    let Some(m) = manifests.get(label) else {
        out.node(depth, false, "Credential details are not available");
        return facts;
    };
    if !visited.insert(label.to_string()) || depth > MAX_INGREDIENT_DEPTH * 2 {
        out.node(depth, false, "(already shown above)");
        return facts;
    }

    // --- signer / time / app
    let sig = m.get("signature_info").unwrap_or(&Value::Null);
    let issuer = s(sig, "issuer").or_else(|| s(sig, "common_name"));
    match issuer {
        Some(i) => {
            out.node(depth, false, &format!("Signed by: {i}"));
            if let Some(cn) = s(sig, "common_name").filter(|cn| Some(*cn) != issuer) {
                out.node(depth + 1, false, &format!("Certificate name: {cn}"));
            }
            if let Some(sn) = s(sig, "cert_serial_number") { out.node(depth + 1, false, &format!("Certificate serial: {sn}")); }
            if let Some(alg) = s(sig, "alg") { out.node(depth + 1, false, &format!("Signature algorithm: {}", alg.to_uppercase())); }
        }
        None => out.node(depth, false, "Signed by: (signer name not available)"),
    }
    match s(sig, "time") {
        Some(t) => out.node(depth, false, &format!("Signed on: {}", fmt_time(t))),
        None => out.node(depth, false, "Signed on: not recorded – no trusted timestamp, so this credential can no longer be verified once the signing certificate expires"),
    }
    if let Some(cg) = claim_generator(m) { out.node(depth, false, &format!("App used: {cg}")); }
    if let Some(t) = s(m, "title") { out.node(depth, false, &format!("Title: {t}")); }
    if let Some(f) = s(m, "format") { out.node(depth, false, &format!("Format: {f}")); }

    // --- assertions
    let assertions = arr(m, "assertions");
    let mut actions: Vec<(String, usize)> = Vec::new();
    let mut ai_best: Option<&'static str> = None;
    let mut producers: Vec<String> = Vec::new();
    let mut others: Vec<String> = Vec::new();
    for a in assertions {
        let lbl = s(a, "label").unwrap_or("");
        let data = a.get("data").unwrap_or(&Value::Null);
        if lbl.starts_with("c2pa.actions") {
            for act in arr(data, "actions") {
                let name = s(act, "action").unwrap_or("");
                let mut line = action_label(name);
                if let Some(sa) = act.get("softwareAgent").and_then(agent_name) { line.push_str(&format!(" – {sa}")); }
                if let Some(dst) = s(act, "digitalSourceType") {
                    if let Some(l) = source_type_label(dst) {
                        line.push_str(&format!(" · {}", l.to_lowercase()));
                        if ai_best.map(|b| ai_rank(l) > ai_rank(b)).unwrap_or(true) { ai_best = Some(l); }
                    }
                }
                if let Some(d) = s(act, "description") { line.push_str(&format!(" ({d})")); }
                match actions.iter_mut().find(|(l, _)| *l == line) {
                    Some(e) => e.1 += 1,
                    None => actions.push((line, 1)),
                }
            }
        } else if lbl.starts_with("stds.schema-org.CreativeWork") {
            for who in arr(data, "author").iter().chain(arr(data, "creator").iter()) {
                if let Some(n) = s(who, "name") { producers.push(n.to_string()); }
            }
            others.push("Creator and attribution details – entered by the creator".into());
        } else if lbl.starts_with("cawg.identity") {
            let mut who = String::new();
            if let Some(n) = data.get("credentialSubject").and_then(|c| s(c, "name")) { who = n.to_string(); }
            if let Some(vc) = data.get("verifiedIdentities").and_then(Value::as_array).and_then(|v| v.first()) {
                if let Some(n) = s(vc, "name") { who = n.to_string(); }
            }
            if !who.is_empty() { producers.push(who); }
            others.push("Identity assertion (CAWG) – a named party takes responsibility for this file".into());
        } else if lbl.starts_with("c2pa.training-mining") || lbl.starts_with("cawg.training-mining") {
            others.push("AI training and data-mining preferences – entered by the creator".into());
        } else if lbl.starts_with("stds.exif") {
            others.push("Camera details (EXIF) – recorded by the capture device".into());
        } else if lbl.starts_with("stds.iptc") {
            others.push("Descriptive metadata (IPTC) – entered by the creator".into());
        } else if lbl.starts_with("c2pa.metadata") {
            others.push("Metadata – recorded by the signing app".into());
        } else if lbl.starts_with("c2pa.hash.") || lbl.starts_with("c2pa.thumbnail") || lbl.starts_with("c2pa.ingredient") || lbl.starts_with("c2pa.claim") {
            // structural: covered elsewhere
        } else if lbl.starts_with("c2pa.soft-binding") {
            others.push("Watermark / fingerprint reference (soft binding) – recorded by the signing app".into());
        } else if !lbl.is_empty() {
            others.push(format!("{lbl} – recorded by the signing app"));
        }
    }
    facts.ai = ai_best;
    producers.sort();
    producers.dedup();
    if !producers.is_empty() { out.node(depth, false, &format!("Produced by: {}", producers.join(", "))); }
    if let Some(ai) = ai_best { out.node(depth, false, &format!("Source: {ai}")); }

    if !actions.is_empty() {
        out.node(depth, depth == 0, "What was done");
        for (line, n) in &actions {
            let t = if *n > 1 { format!("{line} (×{n})") } else { line.clone() };
            out.node(depth + 1, false, &t);
        }
    }
    others.sort();
    others.dedup();
    if !others.is_empty() {
        out.node(depth, false, "Also recorded");
        for o in &others { out.node(depth + 1, false, o); }
    }

    // --- ingredients
    let ings = arr(m, "ingredients");
    if !ings.is_empty() {
        out.node(depth, depth == 0, &format!("Made from {} ingredient{}", ings.len(), if ings.len() == 1 { "" } else { "s" }));
        for ing in ings {
            let title = s(ing, "title").unwrap_or("(untitled)");
            let rel = match s(ing, "relationship") {
                Some("parentOf") => " (the file this was made from)",
                Some("componentOf") => " (added into this file)",
                Some("inputTo") => " (input to an AI model)",
                _ => "",
            };
            let flat = ing.get("validation_status").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
            let st = split_statuses(ing.get("validation_results"), flat);
            let trust_only = !st.failures.is_empty() && st.failures.iter().all(|f| s(f, "code").map(is_trust_only_code).unwrap_or(false));
            let sub = s(ing, "active_manifest");
            let status = if !st.failures.is_empty() && !trust_only { " · has verification problems" }
                else if trust_only { " · signer not on the trust list" }
                else if sub.is_some() { " · carries its own Content Credentials" }
                else { " · no Content Credentials of its own" };
            out.node(depth + 1, false, &format!("{title}{rel}{status}"));
            if let Some(dst) = s(ing, "digital_source_type").and_then(source_type_label) {
                out.node(depth + 2, false, &format!("Source: {dst}"));
                if ai_best.map(|b| ai_rank(dst) > ai_rank(b)).unwrap_or(true) { facts.ai = Some(dst); }
            }
            for f in &st.failures { out.node(depth + 2, false, &format!("✗ {}", status_line(f))); }
            if let Some(sub) = sub {
                if depth / 2 < MAX_INGREDIENT_DEPTH {
                    let sub_facts = render_manifest(out, store, sub, depth + 2, visited);
                    if let Some(a) = sub_facts.ai {
                        if facts.ai.map(|b| ai_rank(a) > ai_rank(b)).unwrap_or(true) { facts.ai = Some(a); }
                    }
                } else {
                    out.node(depth + 2, false, "(nested too deeply to show)");
                }
            }
        }
    }
    facts
}

// ------------------------------------------------------------------ states

fn describe(reader: &Reader, trust: &TrustInfo, file: &Path, out: &mut Out) {
    let state = reader.validation_state();
    let json = reader.json();
    let store: Value = serde_json::from_str(&json).unwrap_or(Value::Null);
    let active = s(&store, "active_manifest").unwrap_or("").to_string();
    let manifests = store.get("manifests").and_then(Value::as_object);
    let count = manifests.map(|m| m.len()).unwrap_or(0);
    let flat = store.get("validation_status").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let st = split_statuses(store.get("validation_results"), flat);
    let ing_fail = ingredient_failures(&store);
    let issuer = manifests
        .and_then(|m| m.get(&active))
        .and_then(|m| m.get("signature_info"))
        .and_then(|sig| s(sig, "issuer").or_else(|| s(sig, "common_name")))
        .unwrap_or("an unnamed signer")
        .to_string();

    let hard_failures: Vec<&Value> = st.failures.iter().filter(|f| !s(f, "code").map(is_trust_only_code).unwrap_or(false)).collect();
    let untrusted = st.failures.iter().any(|f| s(f, "code") == Some("signingCredential.untrusted"));
    let tampered = hard_failures.iter().any(|f| s(f, "code").map(is_tamper_code).unwrap_or(false));
    let expired = hard_failures.iter().any(|f| s(f, "code") == Some("signingCredential.expired"));
    let revoked = hard_failures.iter().any(|f| s(f, "code") == Some("signingCredential.ocsp.revoked"));

    // Decide the display state. Mirrors ValidationState but is explicit about *why*.
    let display = if matches!(state, ValidationState::Invalid) || !hard_failures.is_empty() {
        "invalid"
    } else if !ing_fail.is_empty() {
        "incomplete"
    } else if matches!(state, ValidationState::Trusted) {
        "trusted"
    } else if !trust.loaded {
        "unverified"
    } else if untrusted || matches!(state, ValidationState::Valid) {
        "untrusted"
    } else {
        "unverified"
    };
    out.state(display);

    match display {
        "trusted" => {
            out.head(&format!("Signed by {issuer}"));
            out.text("This file has Content Credentials. It has not been changed since it was signed, and the signer's certificate is on the trust list published by the C2PA.");
        }
        "untrusted" => {
            out.head("The identity of the signer can't be verified");
            out.text(&format!("This file has Content Credentials and has not been changed since it was signed, but the signing certificate (\"{issuer}\") is not on the trust list, so the signer's identity can't be confirmed. Treat the name as you would an unknown sender."));
        }
        "unverified" => {
            out.head(&format!("Signed by {issuer} – signer not checked"));
            out.text("This file has Content Credentials and has not been changed since it was signed. The trust lists are missing from this install, so the signer's identity was not checked.");
        }
        "incomplete" => {
            out.head("These Content Credentials contain incomplete provenance");
            out.text(&format!("The file itself has not been changed since it was signed by {issuer}, but the credentials of one or more ingredients could not be verified, so part of its history is unconfirmed."));
            out.node(0, true, "Problems found");
            for f in &ing_fail { out.node(1, false, &format!("✗ ingredient: {}", status_line(f))); }
        }
        _ => {
            out.head("There is a problem with this file's Content Credentials");
            if tampered {
                out.text("The file has been changed since it was signed, so its Content Credentials no longer describe this content. What you see may differ from what the signer signed.");
            } else if revoked {
                out.text("The signing certificate was revoked – the credentials can't be relied on.");
            } else if expired {
                out.text("Expired certificate: the credentials were signed with a certificate that had already expired, or there is no trusted timestamp to prove they were signed while it was valid.");
            } else {
                out.text("The credentials could not be verified. The details below show which checks failed.");
            }
            out.node(0, true, "Problems found");
            for f in &hard_failures { out.node(1, false, &format!("✗ {}", status_line(f))); }
        }
    }

    // AI disclosure comes from the manifest walk; render the tree, then insert the
    // disclosure as the first node by rendering into a scratch buffer.
    let mut tree = Out { lines: Vec::new(), nodes: 0 };
    let mut visited = HashSet::new();
    let facts = if active.is_empty() {
        ManifestFacts { ai: None }
    } else {
        render_manifest(&mut tree, &store, &active, 0, &mut visited)
    };
    if let Some(ai) = facts.ai {
        out.node(0, false, &format!("AI disclosure: {ai}"));
    }
    out.lines.extend(tree.lines);
    out.nodes += tree.nodes;

    // Verification checks, failures first.
    let total = st.failures.len() + st.informational.len() + st.successes;
    if total > 0 {
        out.node(0, false, &format!("Verification checks ({} run)", total));
        for f in &st.failures { out.node(1, false, &format!("✗ {}", status_line(f))); }
        for i in &st.informational { out.node(1, false, &format!("ⓘ {}", status_line(i))); }
        if st.successes > 0 { out.node(1, false, &format!("✓ {} check{} passed", st.successes, if st.successes == 1 { "" } else { "s" })); }
    }
    if count > 1 {
        out.node(0, false, &format!("Credentials in this file: {count} (the newest is shown above)"));
        if let Some(m) = manifests {
            for (label, mv) in m {
                if *label == active { continue; }
                let who = mv.get("signature_info").and_then(|sig| s(sig, "issuer")).unwrap_or("unknown signer");
                out.node(1, false, &format!("{label} – signed by {who}"));
            }
        }
    }
    about_node(out, trust, Some(file));

    match serde_json::to_string(&store) {
        Ok(compact) if !store.is_null() => out.json(&compact),
        _ => out.json(&json.replace(['\r', '\n'], " ")),
    }
}

fn about_node(out: &mut Out, trust: &TrustInfo, file: Option<&Path>) {
    out.node(0, false, "About this check");
    out.node(1, false, "Checked on this PC by the C2PA reference implementation (c2pa-rs). Nothing was sent over the network.");
    match (&trust.snapshot, trust.loaded) {
        (Some(d), true) => out.node(1, false, &format!("Trust list snapshot: {d} (C2PA conformance trust list + interim Content Credentials list)")),
        (None, true) => out.node(1, false, "Trust list snapshot: date not recorded"),
        (_, false) => out.node(1, false, "Trust lists: not installed – signer identity is not checked"),
    }
    if let Some(f) = file {
        if let Ok(md) = fs::metadata(f) { out.node(1, false, &format!("File size: {}", fmt_bytes(md.len()))); }
    }
}

fn none_state(file: &Path, trust: &TrustInfo, out: &mut Out) {
    out.state("none");
    out.head("No Content Credentials");
    out.text("This file doesn't carry Content Credentials. Most files don't – that is not evidence either way about how the file was made or whether it has been edited.");
    let traces = debris_scan(file);
    if !traces.is_empty() {
        out.text("However, traces suggest it once had Content Credentials that were removed – for example by an upload, export, compression or format conversion:");
        out.node(0, true, "Traces of removed credentials");
        for t in &traces { out.node(1, false, t); }
    }
    about_node(out, trust, Some(file));
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() { return None; }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn debris_scan(file: &Path) -> Vec<String> {
    let mut traces = Vec::new();
    let Ok(mut f) = fs::File::open(file) else { return traces };
    let mut buf = Vec::new();
    if Read::by_ref(&mut f).take(DEBRIS_SCAN_CAP).read_to_end(&mut buf).is_err() { return traces; }
    if find(&buf, b"dcterms:provenance").is_some() {
        traces.push("The file's XMP metadata still contains a dcterms:provenance pointer to a manifest that is no longer in the file.".into());
    }
    if let Some(p) = find(&buf, b".c2pa") {
        let start = p.saturating_sub(220);
        if find(&buf[start..p], b"http").is_some() {
            traces.push("The metadata references a remote .c2pa manifest URL – the credentials may live there rather than in the file. This tab only reads embedded credentials and never fetches remote ones.".into());
        }
    }
    if find(&buf, b"contentauth:urn:uuid").is_some() || find(&buf, b"c2pa_manifest").is_some() {
        traces.push("Fragments of a Content Credentials identifier remain in the file.".into());
    }
    if let Some(p) = find(&buf, b"jumb") {
        let end = (p + 64).min(buf.len());
        if find(&buf[p..end], b"c2pa").is_some() {
            traces.push("A leftover JUMBF/C2PA fragment is present but not readable as credentials – probably truncated by an editor or converter.".into());
        }
    }
    traces
}

fn simple_state(out: &mut Out, state: &str, head: &str, text: &str, detail: Option<String>) {
    out.state(state);
    out.head(head);
    out.text(text);
    if let Some(d) = detail { out.node(0, false, &format!("Technical detail: {d}")); }
}

fn run(o: &Opts) -> String {
    let started = Instant::now();
    let mut out = Out::new();
    out.meta("helper_version", env!("CARGO_PKG_VERSION"));
    let trust = load_trust(o.trust_dir.as_deref());
    out.meta("trust_lists", if trust.loaded { "loaded" } else { "missing" });

    let ctx = match Context::new().with_settings(trust.settings_json.as_str()) {
        Ok(c) => c,
        Err(e) => {
            simple_state(&mut out, "error", "Content Credentials couldn't be checked",
                "The verifier could not be configured. Reinstalling the C2PA View tab should fix this.", Some(e.to_string()));
            about_node(&mut out, &trust, None);
            return out.finish();
        }
    };

    if let Err(e) = fs::metadata(&o.file) {
        if o.json { return format!("{}
", serde_json::json!({ "error": e.to_string() })); }
        simple_state(&mut out, "error", "Content Credentials couldn't be checked", "The file could not be opened.", Some(e.to_string()));
        about_node(&mut out, &trust, None);
        return out.finish();
    }
    let result = Reader::from_context(ctx).with_file(&o.file);
    if o.json {
        return match &result {
            Ok(r) => format!("{}\n", r.json()),
            Err(e) => format!("{}\n", serde_json::json!({ "error": e.to_string() })),
        };
    }
    match result {
        Ok(reader) => describe(&reader, &trust, &o.file, &mut out),
        Err(c2pa::Error::JumbfNotFound) => none_state(&o.file, &trust, &mut out),
        Err(c2pa::Error::UnsupportedType) => {
            simple_state(&mut out, "unsupported", "Content Credentials can't be read from this file type",
                "This file type is not one that Content Credentials can be embedded in, or the file's contents don't match its extension.", None);
            about_node(&mut out, &trust, Some(&o.file));
        }
        Err(c2pa::Error::RemoteManifestUrl(url)) | Err(c2pa::Error::RemoteManifestFetch(url)) => {
            simple_state(&mut out, "remote", "Content Credentials are stored online, not in this file",
                "This file points to Content Credentials kept on a remote server. To protect your privacy this tab works entirely offline and does not fetch them.", None);
            out.node(0, false, &format!("Remote location: {url}"));
            about_node(&mut out, &trust, Some(&o.file));
        }
        Err(c2pa::Error::IoError(e)) => {
            simple_state(&mut out, "error", "Content Credentials couldn't be checked",
                "The file could not be read.", Some(e.to_string()));
            about_node(&mut out, &trust, None);
        }
        Err(e) => {
            simple_state(&mut out, "malformed", "There is a problem with this file's Content Credentials and they can't be viewed",
                "The file contains Content Credentials data that is damaged or not well-formed, so nothing in it can be verified or shown.", Some(e.to_string()));
            about_node(&mut out, &trust, Some(&o.file));
        }
    }
    out.meta("elapsed_ms", &started.elapsed().as_millis().to_string());
    out.finish()
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let text = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&opts))) {
        Ok(t) => t,
        Err(_) => {
            let mut out = Out::new();
            simple_state(&mut out, "error", "Content Credentials couldn't be checked",
                "The verifier stopped unexpectedly while reading this file.", None);
            out.finish()
        }
    };
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(text.as_bytes());
    let _ = lock.flush();
    ExitCode::SUCCESS
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../samples/signed.jpg")
    }
    fn trust_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../trust")
    }

    fn run_on(file: &Path, trust: bool) -> String {
        run(&Opts { file: file.to_path_buf(), trust_dir: if trust { Some(trust_dir()) } else { None }, json: false })
    }

    #[test]
    fn clean_strips_controls_and_bidi() {
        assert_eq!(clean("a\u{202E}b\tc\nd"), "a b c d");
        assert_eq!(clean("  spaced   out  "), "spaced out");
        let long = "x".repeat(1000);
        let c = clean(&long);
        assert!(c.chars().count() <= MAX_TEXT_CHARS + 1 && c.ends_with('…'));
    }

    #[test]
    fn time_formatting() {
        assert_eq!(fmt_time("2026-09-02T11:37:41Z"), "2 Sep 2026, 11:37 UTC");
        assert_eq!(fmt_time("2026-09-02T11:37:41.123+00:00"), "2 Sep 2026, 11:37 UTC");
        assert_eq!(fmt_time("2026-09-02T11:37:41+10:00"), "2 Sep 2026, 11:37 UTC+10:00");
        assert_eq!(fmt_time("garbage"), "garbage");
    }

    #[test]
    fn source_type_wording() {
        assert_eq!(source_type_label("http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"), Some("Fully generated with AI"));
        assert_eq!(source_type_label("https://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia"), Some("Partially edited using AI"));
        assert_eq!(source_type_label("http://cv.iptc.org/newscodes/digitalsourcetype/somethingNew"), None);
    }

    #[test]
    fn sample_is_intact_but_untrusted() {
        // The bundled sample is signed with the C2PA test certificate, which is not on any trust list.
        let out = run_on(&sample_path(), true);
        assert!(out.starts_with("V\t1\n"), "{out}");
        assert!(out.contains("\nSTATE\tuntrusted\n"), "{out}");
        assert!(out.contains("\nHEAD\tThe identity of the signer can't be verified\n"), "{out}");
        assert!(out.contains("\nNODE\t0\t-\tSigned by: "), "{out}");
        assert!(out.contains("\nJSON\t{"), "{out}");
        assert!(out.trim_end().ends_with("END"), "{out}");
    }

    #[test]
    fn sample_without_trust_lists_is_unverified() {
        let out = run_on(&sample_path(), false);
        assert!(out.contains("\nSTATE\tunverified\n"), "{out}");
    }

    #[test]
    fn plain_png_has_no_credentials() {
        // Smallest valid PNG: 1x1 transparent pixel.
        const PNG: &[u8] = &[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
            0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x60, 0x00, 0x02, 0x00,
            0x00, 0x05, 0x00, 0x01, 0xE2, 0x26, 0x05, 0x9B, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,
            0xAE, 0x42, 0x60, 0x82,
        ];
        let dir = std::env::temp_dir().join(format!("c2paview-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("plain.png");
        fs::write(&p, PNG).unwrap();
        let out = run_on(&p, true);
        let _ = fs::remove_dir_all(&dir);
        assert!(out.contains("\nSTATE\tnone\n"), "{out}");
        assert!(out.contains("\nHEAD\tNo Content Credentials\n"), "{out}");
    }

    #[test]
    fn missing_file_is_an_error_state() {
        let out = run_on(Path::new("Z:/definitely/not/here.jpg"), true);
        assert!(out.contains("\nSTATE\terror\n") || out.contains("\nSTATE\tnone\n"), "{out}");
    }

    #[test]
    fn tampered_sample_is_invalid() {
        // Flip a byte deep in the image data (after the manifest) so the content hash no longer matches.
        let mut bytes = fs::read(sample_path()).unwrap();
        let i = bytes.len() - 2000;
        bytes[i] ^= 0xFF;
        let dir = std::env::temp_dir().join(format!("c2paview-test-t-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("tampered.jpg");
        fs::write(&p, &bytes).unwrap();
        let out = run_on(&p, true);
        let _ = fs::remove_dir_all(&dir);
        assert!(out.contains("\nSTATE\tinvalid\n") || out.contains("\nSTATE\tmalformed\n"), "{out}");
    }
}
