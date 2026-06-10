use http::request::Parts;
use regex::Regex;

use crate::config::{WafAction, WafCondition, WafConfig, WafMode, WafPhase};

#[derive(Default)]
pub struct WafEngine;

impl WafEngine {
    pub fn inspect(&self, config: &WafConfig, phase: WafPhase, headers: &Parts, body: &[u8]) -> WafResult {
        if !config.enabled {
            return WafResult::Allow;
        }

        if phase == WafPhase::RequestBody && body.len() > config.max_body_size {
            return WafResult::Action(WafAction::Block, "Payload too large".into());
        }

        let mut total_score = 0u32;

        for rule in &config.rules {
            if rule.phase != phase {
                continue;
            }

            match &rule.condition {
                WafCondition::IpMatch(ips) => {
                    let client_ip = headers
                        .headers
                        .get("x-real-ip")
                        .or_else(|| headers.headers.get("x-forwarded-for"))
                        .and_then(|v| v.to_str().ok());
                    if let Some(ip) = client_ip
                        && ips.iter().any(|i| i.eq_ignore_ascii_case(ip))
                    {
                        return self.trigger_action(&config.mode, &rule.action, "IP Blocked");
                    }
                },

                WafCondition::PathStartsWith(prefix) => {
                    let path = headers.uri.path();
                    if path.starts_with(prefix) {
                        let res = self.trigger_action(&config.mode, &rule.action, "Path Blocked");
                        if let WafResult::Action(..) = res {
                            return res;
                        }
                    }
                },

                WafCondition::HeaderContains { header, value } => {
                    if let Some(h_val) = headers.headers.get(header).and_then(|v| v.to_str().ok())
                        && h_val.to_lowercase().contains(&value.to_lowercase())
                    {
                        total_score += rule.score;
                    }
                },

                WafCondition::BodyContains(sigs) => {
                    if phase == WafPhase::RequestBody || phase == WafPhase::ResponseBody {
                        for sig in sigs {
                            if sig.len() <= body.len() && body.windows(sig.len()).any(|w| w.eq_ignore_ascii_case(sig.as_bytes()))
                            {
                                total_score += rule.score;
                                break;
                            }
                        }
                    }
                },

                WafCondition::BodyRegex(pattern) => {
                    if let Ok(re) = Regex::new(pattern)
                        && let Ok(body_str) = std::str::from_utf8(body)
                        && re.is_match(body_str)
                    {
                        total_score += rule.score;
                    }
                },

                #[allow(clippy::collapsible_match)]
                WafCondition::SqlTokenMatch => {
                    if phase == WafPhase::RequestBody && is_suspicious_sql(body) {
                        total_score += rule.score;
                    }
                },

                _ => {},
            }

            if total_score >= config.anomaly_threshold {
                return self.trigger_action(&config.mode, &WafAction::Block, "Anomaly score exceeded");
            }
        }

        WafResult::Allow
    }

    #[inline(always)]
    fn trigger_action(&self, mode: &WafMode, action: &WafAction, reason: &str) -> WafResult {
        match mode {
            WafMode::DetectionOnly => WafResult::Log(reason.to_string()),
            WafMode::Blocking => WafResult::Action(action.clone(), reason.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum WafResult {
    Allow,
    Log(String),
    Action(WafAction, String),
}

fn is_suspicious_sql(body: &[u8]) -> bool {
    if !body.contains(&b'\'') && !body.contains(&b'"') {
        return false;
    }

    const KEYWORDS: &[&[u8]] = &[b"select", b"union", b"insert", b"delete", b"drop", b"update", b"from", b"where"];

    let mut count = 0u8;
    let mut i = 0;
    while i < body.len() {
        if !body[i].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let start = i;
        while i < body.len() && body[i].is_ascii_alphabetic() {
            i += 1;
        }
        let word = &body[start..i];
        if KEYWORDS.iter().any(|kw| kw.eq_ignore_ascii_case(word)) {
            count += 1;
            if count >= 2 {
                return true;
            }
        }
    }
    false
}
