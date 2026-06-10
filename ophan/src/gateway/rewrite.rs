use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;

pub enum RewriteRule {
    Exact { from: Box<str>, to: Box<str> },
    Prefix { from: Box<str>, to: Box<str> },
    Suffix { from: Box<str>, to: Box<str> },
    Regex { from: Regex, to: Box<str> },
}

pub struct RewriteEngine {
    exact: Vec<RewriteRule>,
    prefixes: Vec<RewriteRule>,
    suffixes: Vec<RewriteRule>,
    regexes: Vec<RewriteRule>,
    trailing_slash: Option<bool>,
}

impl RewriteEngine {
    pub fn new(raw_rules: &HashMap<String, String>, trailing_slash: Option<bool>) -> Self {
        let mut exact = Vec::new();
        let mut prefixes = Vec::new();
        let mut suffixes = Vec::new();
        let mut regexes = Vec::new();

        for (from, to) in raw_rules {
            let to = to.clone().into_boxed_str();

            if let Some(prefix) = from.strip_suffix('*') {
                prefixes.push(RewriteRule::Prefix { from: prefix.to_owned().into_boxed_str(), to });

                continue;
            }

            if let Some(suffix) = from.strip_prefix('*') {
                suffixes.push(RewriteRule::Suffix { from: suffix.to_owned().into_boxed_str(), to });

                continue;
            }

            if is_plain_path(from) {
                exact.push(RewriteRule::Exact { from: from.clone().into_boxed_str(), to });

                continue;
            }

            if let Ok(re) = Regex::new(from) {
                regexes.push(RewriteRule::Regex { from: re, to });
            }
        }

        Self { exact, prefixes, suffixes, regexes, trailing_slash }
    }
}

fn is_plain_path(path: &str) -> bool {
    !path.contains(['^', '$', '[', ']', '(', ')', '+', '?', '|', '\\'])
}

impl RewriteEngine {
    pub fn execute<'a>(&self, path: &'a str) -> Cow<'a, str> {
        let mut result = Cow::Borrowed(path);

        if let Some(rewritten) = self.match_exact(result.as_ref()) {
            result = Cow::Owned(rewritten);
        } else if let Some(rewritten) = self.match_prefix(result.as_ref()) {
            result = Cow::Owned(rewritten);
        } else if let Some(rewritten) = self.match_suffix(result.as_ref()) {
            result = Cow::Owned(rewritten);
        } else if let Some(rewritten) = self.match_regex(result.as_ref()) {
            result = Cow::Owned(rewritten);
        }

        self.apply_trailing_slash(result)
    }

    fn match_exact(&self, path: &str) -> Option<String> {
        for rule in &self.exact {
            if let RewriteRule::Exact { from, to } = rule
                && path == from.as_ref()
            {
                return Some(to.to_string());
            }
        }

        None
    }

    fn match_prefix(&self, path: &str) -> Option<String> {
        for rule in &self.prefixes {
            if let RewriteRule::Prefix { from, to } = rule
                && let Some(rest) = path.strip_prefix(from.as_ref())
            {
                let mut out = String::with_capacity(to.len() + rest.len());

                out.push_str(to);
                out.push_str(rest);

                return Some(out);
            }
        }

        None
    }

    fn match_suffix(&self, path: &str) -> Option<String> {
        for rule in &self.suffixes {
            if let RewriteRule::Suffix { from, to } = rule
                && path.ends_with(from.as_ref())
            {
                return Some(to.to_string());
            }
        }

        None
    }

    fn match_regex(&self, path: &str) -> Option<String> {
        for rule in &self.regexes {
            if let RewriteRule::Regex { from, to } = rule {
                let replaced = from.replace(path, to.as_ref());

                if replaced != path {
                    return Some(replaced.into_owned());
                }
            }
        }

        None
    }

    fn apply_trailing_slash<'a>(&self, path: Cow<'a, str>) -> Cow<'a, str> {
        let Some(force) = self.trailing_slash else {
            return path;
        };

        if force {
            if path.ends_with('/') {
                return path;
            }

            let mut owned = path.into_owned();
            owned.push('/');

            return Cow::Owned(owned);
        }

        if path == "/" || !path.ends_with('/') {
            return path;
        }

        let mut owned = path.into_owned();
        owned.pop();

        Cow::Owned(owned)
    }
}
