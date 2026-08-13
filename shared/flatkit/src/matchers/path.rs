//!  Multi-pattern glob matcher (`PathMatcherSet`).
//!
use ahash::AHashSet;
use std::str::FromStr;

const MAX_GROUP_OPTIONS: u32 = 16;
const MAX_DEEP_WILDCARDS: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobError {
    UnclosedGroup,
    NestedGroup,
    EmptyGroup,
    GroupOptionsLimit,
    UnclosedCharClass,
    EmptyCharClass,
    InvalidCharRange,
    TooManyDeepWildcards,
}

impl GlobError {
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnclosedGroup => "unclosed group: missing '}'",
            Self::NestedGroup => "nested groups are not supported",
            Self::EmptyGroup => "empty group",
            Self::GroupOptionsLimit => "group exceeds maximum alternatives",
            Self::UnclosedCharClass => "unclosed character class: missing ']'",
            Self::EmptyCharClass => "empty character class",
            Self::InvalidCharRange => "invalid character range",
            Self::TooManyDeepWildcards => "too many deep wildcards (**)",
        }
    }
}

impl std::fmt::Display for GlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for GlobError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Literal(Box<[u8]>),
    Wildcard,        // *
    DeepWildcard,    // **
    DeepWildcardDir, // **/
    AnyChar,         // ?
    Group(Box<[Box<[u8]>]>),
    CharClass { bitmap: [u8; 32], negated: bool },
}

/// A single compiled glob pattern.
#[derive(Debug, Clone)]
pub struct GlobPattern {
    tokens: Box<[Tok]>,
    is_exact: bool,
}

impl GlobPattern {
    pub fn compile(pattern: impl AsRef<[u8]>) -> Result<Self, GlobError> {
        let tokens = tokenize(pattern.as_ref())?;
        let is_exact = tokens.len() == 1 && matches!(tokens[0], Tok::Literal(_));
        Ok(Self { tokens: tokens.into_boxed_slice(), is_exact })
    }

    #[inline]
    pub fn is_exact(&self) -> bool {
        self.is_exact
    }
}

impl FromStr for GlobPattern {
    type Err = GlobError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::compile(s.as_bytes())
    }
}

impl TryFrom<&str> for GlobPattern {
    type Error = GlobError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

fn tokenize(pattern: &[u8]) -> Result<Vec<Tok>, GlobError> {
    if pattern.is_empty() {
        return Ok(vec![Tok::Literal(Box::new([]))]);
    }

    let mut tokens = Vec::new();
    let mut i = 0;
    let mut deep_count = 0usize;

    while i < pattern.len() {
        match pattern[i] {
            b'*' => {
                let next = i + 1;
                if next < pattern.len() && pattern[next] == b'*' {
                    deep_count += 1;
                    if deep_count > MAX_DEEP_WILDCARDS {
                        return Err(GlobError::TooManyDeepWildcards);
                    }
                    if next + 1 < pattern.len() && pattern[next + 1] == b'/' {
                        tokens.push(Tok::DeepWildcardDir);
                        i += 3;
                    } else {
                        tokens.push(Tok::DeepWildcard);
                        i += 2;
                    }
                } else {
                    tokens.push(Tok::Wildcard);
                    i += 1;
                }
            },
            b'?' => {
                tokens.push(Tok::AnyChar);
                i += 1;
            },
            b'{' => {
                let start = i + 1;
                let mut end = start;
                while end < pattern.len() && pattern[end] != b'}' {
                    if pattern[end] == b'{' {
                        return Err(GlobError::NestedGroup);
                    }
                    end += 1;
                }
                if end == pattern.len() {
                    return Err(GlobError::UnclosedGroup);
                }
                let content = &pattern[start..end];
                if content.is_empty() {
                    return Err(GlobError::EmptyGroup);
                }

                let mut opts = Vec::new();
                let mut opt_start = 0;
                let mut count = 1u32;
                for (k, &b) in content.iter().enumerate() {
                    if b == b',' {
                        count += 1;
                        if count > MAX_GROUP_OPTIONS {
                            return Err(GlobError::GroupOptionsLimit);
                        }
                        let piece = &content[opt_start..k];
                        if piece.is_empty() {
                            return Err(GlobError::EmptyGroup);
                        }
                        opts.push(piece.into());
                        opt_start = k + 1;
                    }
                }
                let last = &content[opt_start..];
                if last.is_empty() {
                    return Err(GlobError::EmptyGroup);
                }
                opts.push(last.into());
                tokens.push(Tok::Group(opts.into_boxed_slice()));
                i = end + 1;
            },
            b'[' => {
                let mut idx = i + 1;
                let mut negated = false;
                if idx < pattern.len() && pattern[idx] == b'^' {
                    negated = true;
                    idx += 1;
                }
                let start = idx;
                while idx < pattern.len() && pattern[idx] != b']' {
                    idx += 1;
                }
                if idx == pattern.len() {
                    return Err(GlobError::UnclosedCharClass);
                }
                let class = &pattern[start..idx];
                if class.is_empty() {
                    return Err(GlobError::EmptyCharClass);
                }

                let mut bitmap = [0u8; 32];
                let mut pos = 0;
                while pos < class.len() {
                    if pos + 2 < class.len() && class[pos + 1] == b'-' {
                        let a = class[pos];
                        let b = class[pos + 2];
                        if a > b {
                            return Err(GlobError::InvalidCharRange);
                        }
                        for c in a..=b {
                            bitmap[(c / 8) as usize] |= 1 << (c % 8);
                        }
                        pos += 3;
                    } else {
                        let c = class[pos];
                        bitmap[(c / 8) as usize] |= 1 << (c % 8);
                        pos += 1;
                    }
                }
                tokens.push(Tok::CharClass { bitmap, negated });
                i = idx + 1;
            },
            _ => {
                let start = i;
                while i < pattern.len() && !matches!(pattern[i], b'*' | b'?' | b'{' | b'[') {
                    i += 1;
                }
                tokens.push(Tok::Literal(pattern[start..i].into()));
            },
        }
    }
    Ok(tokens)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeToken {
    Literal { start: u32, end: u32 },
    Wildcard,
    DeepWildcard,
    DeepWilcardDir,
    AnyChar,
    Group { start: u32, end: u32 }, // range into group_spans
    CharClass([u8; 32], bool),
}

#[derive(Debug, Clone)]
struct Node {
    token: NodeToken,
    children: (u32, u32), // start, end in nodes vec
    is_terminal: bool,
}

#[derive(Debug, Clone, Copy)]
struct GroupSpan {
    start: u32,
    end: u32,
}

#[derive(Debug, Clone)]
enum FastPath {
    Exact(AHashSet<Box<[u8]>>),
    SingleLiteral(Box<[u8]>),
    General,
}

fn lower_token(tok: &Tok, arena: &mut Vec<u8>, group_spans: &mut Vec<GroupSpan>) -> NodeToken {
    match tok {
        Tok::Literal(lit) => {
            let start = arena.len() as u32;
            arena.extend_from_slice(lit);
            let end = arena.len() as u32;
            NodeToken::Literal { start, end }
        },
        Tok::Wildcard => NodeToken::Wildcard,
        Tok::DeepWildcard => NodeToken::DeepWildcard,
        Tok::DeepWildcardDir => NodeToken::DeepWilcardDir,
        Tok::AnyChar => NodeToken::AnyChar,
        Tok::CharClass { bitmap, negated } => NodeToken::CharClass(*bitmap, *negated),
        Tok::Group(opts) => {
            let gstart = group_spans.len() as u32;
            for opt in opts {
                let start = arena.len() as u32;
                arena.extend_from_slice(opt);
                let end = arena.len() as u32;
                group_spans.push(GroupSpan { start, end });
            }

            let gend = group_spans.len() as u32;
            NodeToken::Group { start: gstart, end: gend }
        },
    }
}

#[derive(Debug, Clone)]
pub struct PathMatcherSet {
    nodes: Vec<Node>,
    root: (u32, u32),
    arena: Vec<u8>,
    group_spans: Vec<GroupSpan>,
    fast: Option<FastPath>,
}

impl PathMatcherSet {
    pub fn new<T: AsRef<[u8]>>(patterns: &[T]) -> Result<Self, GlobError> {
        Self::compile(patterns)
    }

    pub fn compile<T: AsRef<[u8]>>(patterns: &[T]) -> Result<Self, GlobError> {
        let mut parsed = Vec::with_capacity(patterns.len());
        for p in patterns {
            parsed.push(GlobPattern::compile(p)?);
        }

        Ok(Self::from_patterns(&parsed))
    }

    pub fn from_patterns(patterns: &[GlobPattern]) -> Self {
        if patterns.is_empty() {
            return Self {
                nodes: Vec::new(),
                root: (0, 0),
                arena: Vec::new(),
                group_spans: Vec::new(),
                fast: None,
            };
        }

        // ---------- Fast-path detection ----------
        let all_literal = patterns.iter().all(|p| p.tokens.len() == 1 && matches!(p.tokens[0], Tok::Literal(_)));

        if all_literal {
            if patterns.len() == 1 {
                if let Tok::Literal(lit) = &patterns[0].tokens[0] {
                    return Self {
                        nodes: Vec::new(),
                        root: (0, 0),
                        arena: Vec::new(),
                        group_spans: Vec::new(),
                        fast: Some(FastPath::SingleLiteral(lit.clone())),
                    };
                }
            }

            let mut set = AHashSet::with_capacity(patterns.len());
            for p in patterns {
                if let Tok::Literal(lit) = &p.tokens[0] {
                    set.insert(lit.clone());
                }
            }

            return Self {
                nodes: Vec::new(),
                root: (0, 0),
                arena: Vec::new(),
                group_spans: Vec::new(),
                fast: Some(FastPath::Exact(set)),
            };
        }

        // ---------- General path: build trie + arena ----------
        let mut arena = Vec::new();
        let mut group_spans = Vec::new();

        // temporary tree
        #[derive(Clone)]
        struct Temp {
            token: NodeToken,
            is_terminal: bool,
            children: Vec<Temp>,
        }

        let mut root_children: Vec<Temp> = Vec::new();

        for pat in patterns {
            let mut level = &mut root_children;
            let len = pat.tokens.len();

            for (idx, tok) in pat.tokens.iter().enumerate() {
                let is_last = idx + 1 == len;
                let node_tok = lower_token(tok, &mut arena, &mut group_spans);

                if let Some(pos) = level.iter().position(|n| n.token == node_tok) {
                    if is_last {
                        level[pos].is_terminal = true;
                    }
                    level = &mut level[pos].children;
                } else {
                    level.push(Temp { token: node_tok, is_terminal: is_last, children: Vec::new() });
                    let last = level.len() - 1;
                    level = &mut level[last].children;
                }
            }
        }

        // flatten
        fn flatten(temps: Vec<Temp>, out: &mut Vec<Node>) -> (u32, u32) {
            if temps.is_empty() {
                return (0, 0);
            }
            let start = out.len() as u32;
            for t in &temps {
                out.push(Node { token: t.token, children: (0, 0), is_terminal: t.is_terminal });
            }
            let end = out.len() as u32;

            for (i, t) in temps.into_iter().enumerate() {
                let (cs, ce) = flatten(t.children, out);
                out[start as usize + i].children = (cs, ce);
            }
            (start, end)
        }

        let mut nodes = Vec::new();
        let root = flatten(root_children, &mut nodes);

        Self {
            nodes,
            root,
            arena,
            group_spans,
            fast: Some(FastPath::General),
        }
    }
}

impl PathMatcherSet {
    #[inline]
    pub fn is_match<T: AsRef<[u8]>>(&self, input: T) -> bool {
        self.matches(input)
    }

    #[inline]
    pub fn matches<T: AsRef<[u8]>>(&self, input: T) -> bool {
        let Some(fast) = &self.fast else {
            return false;
        };

        match fast {
            FastPath::SingleLiteral(lit) => input.as_ref() == lit.as_ref(),
            FastPath::Exact(set) => set.contains(input.as_ref()),
            FastPath::General => self.matches_backtrack(input.as_ref()),
        }
    }
}

const MAX_STACK_DEPTH: usize = 64; // 2 KB aprox.

#[derive(Clone, Copy)]
struct MatchFrame<'a> {
    input: &'a [u8],
    child_start: u32,
    child_end: u32,
    progress: u32,
}

impl PathMatcherSet {
    fn matches_backtrack(&self, input: &[u8]) -> bool {
        if self.nodes.is_empty() {
            return false;
        }

        let mut stack = [MatchFrame { input: &[], child_start: 0, child_end: 0, progress: 0 }; MAX_STACK_DEPTH];

        let mut sp = 1; // stack pointer
        stack[0] = MatchFrame {
            input,
            child_start: self.root.0,
            child_end: self.root.1,
            progress: 0,
        };

        while sp > 0 {
            let fi = sp - 1;
            let frame = &mut stack[fi];

            // Input is all consumed
            if frame.input.is_empty() {
                for idx in frame.child_start..frame.child_end {
                    let node = &self.nodes[idx as usize];
                    match node.token {
                        NodeToken::DeepWildcard | NodeToken::DeepWilcardDir => return true,
                        NodeToken::Wildcard if node.is_terminal => return true,
                        NodeToken::Group { start, end } if node.is_terminal => {
                            for g in start..end {
                                let span = self.group_spans[g as usize];
                                if span.start == span.end {
                                    return true;
                                }
                            }
                        },
                        _ => {},
                    }
                }
                sp -= 1;
                continue;
            }

            if frame.child_start >= frame.child_end {
                sp -= 1;
                continue;
            }

            let node_idx = frame.child_start;
            let node = &self.nodes[node_idx as usize];
            let remaining = frame.input;

            match node.token {
                // ----------------------------------------------------------------
                NodeToken::Literal { start, end } => {
                    let lit = &self.arena[start as usize..end as usize];
                    frame.child_start += 1;

                    if remaining.starts_with(lit) {
                        let next = &remaining[lit.len()..];
                        if next.is_empty() && node.is_terminal {
                            return true;
                        }
                        if node.children.0 < node.children.1 {
                            if sp >= MAX_STACK_DEPTH {
                                return false; // stack overflow 
                            }
                            stack[sp] = MatchFrame {
                                input: next,
                                child_start: node.children.0,
                                child_end: node.children.1,
                                progress: 0,
                            };
                            sp += 1;
                        }
                    }
                },

                // ----------------------------------------------------------------
                NodeToken::Wildcard => {
                    // *
                    let offset = frame.progress as usize;

                    if offset <= remaining.len() && (offset == 0 || remaining[offset - 1] != b'/') {
                        frame.progress += 1;

                        let next = &remaining[offset..];
                        if next.is_empty() && node.is_terminal {
                            return true;
                        }
                        if node.children.0 < node.children.1 {
                            if sp >= MAX_STACK_DEPTH {
                                return false;
                            }
                            stack[sp] = MatchFrame {
                                input: next,
                                child_start: node.children.0,
                                child_end: node.children.1,
                                progress: 0,
                            };
                            sp += 1;
                        }
                    } else {
                        frame.progress = 0;
                        frame.child_start += 1;
                    }
                },

                // ----------------------------------------------------------------
                NodeToken::DeepWildcard | NodeToken::DeepWilcardDir => {
                    // ** o **/
                    if node.is_terminal {
                        return true;
                    }

                    let offset = frame.progress as usize;

                    if offset == 0 {
                        frame.progress = 1;
                        if node.children.0 < node.children.1 {
                            if sp >= MAX_STACK_DEPTH {
                                return false;
                            }
                            stack[sp] = MatchFrame {
                                input: remaining,
                                child_start: node.children.0,
                                child_end: node.children.1,
                                progress: 0,
                            };
                            sp += 1;
                        }
                    } else {
                        let mut slice = remaining;
                        for _ in 1..offset {
                            if let Some(pos) = slice.iter().position(|&b| b == b'/') {
                                slice = &slice[pos + 1..];
                            } else {
                                // No hay más directorios
                                frame.progress = 0;
                                frame.child_start += 1;
                                continue;
                            }
                        }

                        if let Some(pos) = slice.iter().position(|&b| b == b'/') {
                            let next = &slice[pos + 1..];
                            frame.progress += 1;

                            if node.children.0 < node.children.1 {
                                if sp >= MAX_STACK_DEPTH {
                                    return false;
                                }
                                stack[sp] = MatchFrame {
                                    input: next,
                                    child_start: node.children.0,
                                    child_end: node.children.1,
                                    progress: 0,
                                };
                                sp += 1;
                            }
                        } else {
                            frame.progress = 0;
                            frame.child_start += 1;
                        }
                    }
                },

                // ----------------------------------------------------------------
                NodeToken::AnyChar => {
                    // ?
                    frame.child_start += 1;
                    if !remaining.is_empty() && remaining[0] != b'/' {
                        let next = &remaining[1..];
                        if next.is_empty() && node.is_terminal {
                            return true;
                        }
                        if node.children.0 < node.children.1 {
                            if sp >= MAX_STACK_DEPTH {
                                return false;
                            }
                            stack[sp] = MatchFrame {
                                input: next,
                                child_start: node.children.0,
                                child_end: node.children.1,
                                progress: 0,
                            };
                            sp += 1;
                        }
                    }
                },

                // ----------------------------------------------------------------
                NodeToken::CharClass(bitmap, negated) => {
                    frame.child_start += 1;
                    if !remaining.is_empty() {
                        let b = remaining[0];
                        let bit_set = (bitmap[(b / 8) as usize] & (1 << (b % 8))) != 0;
                        if bit_set != negated {
                            let next = &remaining[1..];
                            if next.is_empty() && node.is_terminal {
                                return true;
                            }
                            if node.children.0 < node.children.1 {
                                if sp >= MAX_STACK_DEPTH {
                                    return false;
                                }
                                stack[sp] = MatchFrame {
                                    input: next,
                                    child_start: node.children.0,
                                    child_end: node.children.1,
                                    progress: 0,
                                };
                                sp += 1;
                            }
                        }
                    }
                },

                // ----------------------------------------------------------------
                NodeToken::Group { start, end } => {
                    frame.child_start += 1;
                    let mut pushed = 0u32;

                    for g in (start..end).rev() {
                        let span = self.group_spans[g as usize];
                        let opt = &self.arena[span.start as usize..span.end as usize];

                        if remaining.starts_with(opt) {
                            let next = &remaining[opt.len()..];
                            if next.is_empty() && node.is_terminal {
                                return true;
                            }
                            if node.children.0 < node.children.1 {
                                if sp + pushed as usize >= MAX_STACK_DEPTH {
                                    return false;
                                }
                                stack[sp + pushed as usize] = MatchFrame {
                                    input: next,
                                    child_start: node.children.0,
                                    child_end: node.children.1,
                                    progress: 0,
                                };
                                pushed += 1;
                            }
                        }
                    }
                    sp += pushed as usize;
                },
            }
        }

        false
    }
}

impl<T: AsRef<[u8]>> TryFrom<&[T]> for PathMatcherSet {
    type Error = GlobError;
    fn try_from(value: &[T]) -> Result<Self, Self::Error> {
        Self::compile(value)
    }
}

impl TryFrom<Vec<&str>> for PathMatcherSet {
    type Error = GlobError;
    fn try_from(value: Vec<&str>) -> Result<Self, Self::Error> {
        Self::compile(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =======================================================================
    // 1. PERFECT CASES (Happy Paths)
    // =======================================================================

    #[test]
    fn test_fast_paths() {
        let matcher = PathMatcherSet::try_from(vec!["src/main.rs"]).unwrap();
        assert!(matcher.matches("src/main.rs"));
        assert!(!matcher.matches("src/lib.rs"));

        let matcher = PathMatcherSet::try_from(vec!["a", "b", "c"]).unwrap();
        assert!(matcher.matches("a"));
        assert!(matcher.matches("c"));
        assert!(!matcher.matches("d"));
    }

    #[test]
    fn test_wildcard_single_segment() {
        let matcher = PathMatcherSet::try_from(vec!["src/*.rs"]).unwrap();
        assert!(matcher.matches("src/main.rs"));
        assert!(matcher.matches("src/lib.rs"));

        assert!(!matcher.matches("src/core/main.rs"));
        assert!(!matcher.matches("src/main.c"));
    }

    #[test]
    fn test_any_char() {
        let matcher = PathMatcherSet::try_from(vec!["test_?.rs"]).unwrap();
        assert!(matcher.matches("test_1.rs"));
        assert!(matcher.matches("test_a.rs"));

        assert!(!matcher.matches("test_10.rs"));
        assert!(!matcher.matches("test_/.rs"));
    }

    #[test]
    fn test_deep_wildcard() {
        let matcher = PathMatcherSet::try_from(vec!["src/**/*.rs"]).unwrap();
        assert!(matcher.matches("src/main.rs"));
        assert!(matcher.matches("src/utils/math.rs"));
        assert!(matcher.matches("src/a/b/c/d.rs"));

        assert!(!matcher.matches("test/main.rs"));
        assert!(!matcher.matches("src/main.c"));
    }

    #[test]
    fn test_char_classes() {
        let matcher = PathMatcherSet::try_from(vec!["[a-cx-z]1.rs", "test_[^0-9].rs"]).unwrap();

        assert!(matcher.matches("a1.rs"));
        assert!(matcher.matches("b1.rs"));
        assert!(matcher.matches("z1.rs"));
        assert!(!matcher.matches("d1.rs"));

        assert!(matcher.matches("test_a.rs"));
        assert!(matcher.matches("test_X.rs"));
        assert!(!matcher.matches("test_5.rs"));
    }

    #[test]
    fn test_groups() {
        let matcher = PathMatcherSet::try_from(vec!["src/{main,lib,core}.rs"]).unwrap();
        assert!(matcher.matches("src/main.rs"));
        assert!(matcher.matches("src/lib.rs"));
        assert!(matcher.matches("src/core.rs"));
        assert!(!matcher.matches("src/utils.rs"));
    }

    #[test]
    fn test_multi_pattern_set() {
        let matcher = PathMatcherSet::try_from(vec!["*.md", "src/**/*.rs", "scripts/{build,deploy}.sh"]).unwrap();

        assert!(matcher.matches("readme.md"));
        assert!(matcher.matches("src/main.rs"));
        assert!(matcher.matches("src/net/p2p/mod.rs"));
        assert!(matcher.matches("scripts/build.sh"));

        assert!(!matcher.matches("readme.txt"));
        assert!(!matcher.matches("scripts/test.sh"));
        assert!(!matcher.matches("tests/main.rs"));
    }

    // =======================================================================
    // 2. BAD CASES (Compilation & Error Handling)
    // =======================================================================

    #[test]
    fn test_compile_errors_groups() {
        assert_eq!(PathMatcherSet::compile(&["{a,b"]).unwrap_err(), GlobError::UnclosedGroup);
        assert_eq!(PathMatcherSet::compile(&["{a,{b,c}}"]).unwrap_err(), GlobError::NestedGroup);
        assert_eq!(PathMatcherSet::compile(&["{}"]).unwrap_err(), GlobError::EmptyGroup);
        assert_eq!(PathMatcherSet::compile(&["{a,}"]).unwrap_err(), GlobError::EmptyGroup);
    }

    #[test]
    fn test_compile_errors_limits() {
        // Max (MAX_GROUP_OPTIONS = 16)
        let too_many_opts = "{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17}";
        assert_eq!(
            PathMatcherSet::compile(&[too_many_opts]).unwrap_err(),
            GlobError::GroupOptionsLimit
        );

        // Max (MAX_DEEP_WILDCARDS = 6)
        let too_many_deep = "**/**/**/**/**/**/**";
        assert_eq!(
            PathMatcherSet::compile(&[too_many_deep]).unwrap_err(),
            GlobError::TooManyDeepWildcards
        );
    }

    #[test]
    fn test_compile_errors_char_classes() {
        assert_eq!(PathMatcherSet::compile(&["[a-z"]).unwrap_err(), GlobError::UnclosedCharClass);
        assert_eq!(PathMatcherSet::compile(&["[]"]).unwrap_err(), GlobError::EmptyCharClass);
        assert_eq!(PathMatcherSet::compile(&["[z-a]"]).unwrap_err(), GlobError::InvalidCharRange);
    }

    // =======================================================================
    // 3. EDGE CASES & PATHOLOGICAL CASES
    // =======================================================================

    #[test]
    fn test_catastrophic_backtracking_prevention() {
        // bad case (O(2^N))
        // NFA, best case (O(N*M)).

        let matcher = PathMatcherSet::try_from(vec!["*a*b*c*d*e*f*g*h*i*j*k"]).unwrap();

        let input = "a".repeat(100) + &"b".repeat(100) + &"c".repeat(100) + "x";

        assert!(!matcher.matches(&input));
    }

    #[test]
    fn test_empty_strings() {
        let matcher = PathMatcherSet::try_from(vec![""]).unwrap();
        assert!(matcher.matches(""));
        assert!(!matcher.matches("a"));

        let matcher = PathMatcherSet::try_from(vec!["*"]).unwrap();
        assert!(matcher.matches(""));
        assert!(matcher.matches("a"));

        let matcher = PathMatcherSet::try_from(vec!["**"]).unwrap();
        assert!(matcher.matches(""));
    }

    #[test]
    fn test_deep_wildcard_boundary() {
        let matcher = PathMatcherSet::try_from(vec!["a/**/b"]).unwrap();

        assert!(matcher.matches("a/b"));
        assert!(matcher.matches("a/x/b"));
        assert!(matcher.matches("a/x/y/b"));

        assert!(!matcher.matches("x/a/b"));
        assert!(!matcher.matches("a/b/x"));
    }

    #[test]
    fn test_consecutive_stars() {
        let matcher = PathMatcherSet::try_from(vec!["a*b*c"]).unwrap();
        assert!(matcher.matches("abc"));
        assert!(matcher.matches("aXXXXbYYYYc"));
    }

    #[test]
    fn test_empty_patterns_and_inputs() {
        // Strict empty pattern
        let matcher = PathMatcherSet::try_from(vec![""]).unwrap();
        assert!(matcher.matches(""));
        assert!(!matcher.matches("a"));
        assert!(!matcher.matches("/"));

        // Wildcards vs Empty string
        let matcher = PathMatcherSet::try_from(vec!["*", "**", "**/"]).unwrap();
        assert!(matcher.matches(""));

        // Zero-length literal at the end of a path
        let matcher = PathMatcherSet::try_from(vec!["src/"]).unwrap();
        assert!(matcher.matches("src/"));
        assert!(!matcher.matches("src"));
    }

    // =======================================================================
    // 2. PATHOLOGICAL EPSILON TRANSITIONS (Catastrophic NFA Check)
    // =======================================================================

    #[test]
    fn test_overlapping_deep_wildcards() {
        // If the algorithm used Backtracking, a pattern like **/**/**/**
        // would cause an immediate hang. In our NFA it must be sub-millisecond.
        let matcher = PathMatcherSet::try_from(vec!["a/**/**/**/b"]).unwrap();
        assert!(matcher.matches("a/b"));
        assert!(matcher.matches("a/x/y/z/b"));
        assert!(!matcher.matches("a/x/y/z/c"));
    }

    #[test]
    fn test_consecutive_stars_and_chars() {
        let matcher = PathMatcherSet::try_from(vec!["*a*b*c*d*"]).unwrap();
        // Heavy interleaved matching
        assert!(matcher.matches("a_b_c_d_"));
        assert!(matcher.matches("xxxxaxxxxbxxxxcxxxxdxxxx"));
        // Fails fast without infinite recursion
        assert!(!matcher.matches("xxxxaxxxxbxxxxcxxxxXxxxx"));
    }

    // =======================================================================
    // 3. GROUP COMBINATORICS
    // =======================================================================

    #[test]
    fn test_group_explosion() {
        // A poor regex engine would create 3 * 3 * 3 = 27 branches in memory.
        // Our NFA just advances the offset.
        let matcher = PathMatcherSet::try_from(vec!["{a,b,c}{x,y,z}{1,2,3}"]).unwrap();

        assert!(matcher.matches("ax1"));
        assert!(matcher.matches("cz3"));
        assert!(matcher.matches("by2"));
        assert!(!matcher.matches("a1x"));
        assert!(!matcher.matches("dz3")); // 'd' is not in the group
    }

    // =======================================================================
    // 4. DIRECTORY BOUNDARY ENFORCEMENT
    // =======================================================================

    #[test]
    fn test_directory_boundary_strictness() {
        let matcher = PathMatcherSet::try_from(vec!["*/*/*"]).unwrap();

        // Exactly 3 segments
        assert!(matcher.matches("a/b/c"));
        // Fails: 2 segments
        assert!(!matcher.matches("a/b"));
        // Fails: 4 segments
        assert!(!matcher.matches("a/b/c/d"));
    }

    #[test]
    fn test_anychar_directory_barrier() {
        let matcher = PathMatcherSet::try_from(vec!["a?b"]).unwrap();
        assert!(matcher.matches("aXb"));
        // '?' CANNOT be replaced by a directory separator
        assert!(!matcher.matches("a/b"));
    }

    // =======================================================================
    // 5. BYTE-LEVEL AND UTF-8 BEHAVIOR (Raw Byte Processing)
    // =======================================================================

    #[test]
    fn test_utf8_byte_matching() {
        // Your engine operates at the u8 (byte) level, not char (unicode).
        // The character "ñ" in UTF-8 takes 2 bytes (0xC3 0xB1).
        let matcher = PathMatcherSet::try_from(vec!["ni?o.rs"]).unwrap();

        // Fails because "ñ" is 2 bytes, and '?' only consumes 1 byte.
        assert!(!matcher.matches("niño.rs"));

        // If we want to catch "ñ", we need two '??' or use the general '*' wildcard
        let matcher2 = PathMatcherSet::try_from(vec!["ni??o.rs"]).unwrap();
        assert!(matcher2.matches("niño.rs"));

        // Exact match works because the byte literals are identical
        let matcher3 = PathMatcherSet::try_from(vec!["niño.rs"]).unwrap();
        assert!(matcher3.matches("niño.rs"));
    }

    // =======================================================================
    // 6. CHARACTER CLASS TRAPS
    // =======================================================================

    #[test]
    fn test_tricky_char_classes() {
        // [a-z] vs [a\-z] or classes attempting to include '-' or '^'
        // Your current tokenizer assumes '-' denotes a range if it's between characters.

        let matcher = PathMatcherSet::try_from(vec!["test_[a-c].rs"]).unwrap();
        assert!(matcher.matches("test_a.rs"));
        assert!(matcher.matches("test_c.rs"));
        assert!(!matcher.matches("test_d.rs"));

        // Negated class matching slashes
        // [^a] will match '/', which is correct at standard globbing level
        // unless explicitly limited.
        let matcher2 = PathMatcherSet::try_from(vec!["[^a]"]).unwrap();
        assert!(matcher2.matches("b"));
        assert!(matcher2.matches("/"));
    }
}
