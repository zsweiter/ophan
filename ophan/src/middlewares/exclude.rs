pub struct ExcludesEngine {
    exact: hashbrown::HashSet<Box<str>>,
    prefixes: Vec<Box<str>>,
    suffixes: Vec<Box<str>>,
}

impl ExcludesEngine {
    pub fn compile(patterns: &[String]) -> Self {
        let mut exact = hashbrown::HashSet::new();
        let mut prefixes = Vec::new();
        let mut suffixes = Vec::new();

        for pattern in patterns {
            if let Some(prefix) = pattern.strip_suffix('*') {
                prefixes.push(prefix.into());
            } else if let Some(suffix) = pattern.strip_prefix('*') {
                suffixes.push(suffix.into());
            } else {
                exact.insert(pattern.clone().into_boxed_str());
            }
        }

        Self { exact, prefixes, suffixes }
    }
}

impl ExcludesEngine {
    #[inline]
    pub fn contains(&self, path: &str) -> bool {
        if self.exact.contains(path) {
            return true;
        }

        for prefix in &self.prefixes {
            if path.starts_with(prefix.as_ref()) {
                return true;
            }
        }

        for suffix in &self.suffixes {
            if path.ends_with(suffix.as_ref()) {
                return true;
            }
        }

        false
    }
}
