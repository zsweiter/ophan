#[derive(Debug, Clone, PartialEq)]
pub struct WafConfig {
    pub enabled: bool,
    pub mode: WafMode,
    pub rules: Vec<WafRule>,
    pub max_body_size: usize, // en bytes
    pub anomaly_threshold: u32,
    pub excludes: Vec<String>,
}

impl WafConfig {
    pub fn merge(&mut self, other: WafConfig) {
        self.enabled = other.enabled;
        self.mode = other.mode;
        if !other.rules.is_empty() {
            self.rules = other.rules;
        }
        self.max_body_size = other.max_body_size;
        self.anomaly_threshold = other.anomaly_threshold;
        if !other.excludes.is_empty() {
            self.excludes = other.excludes;
        }
    }
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: WafMode::Blocking,
            rules: vec![
                WafRule {
                    id: "owasp_sql_injection".into(),
                    phase: WafPhase::RequestBody,
                    condition: WafCondition::BodyContains(vec![
                        "union select".into(),
                        "union all select".into(),
                        "insert into".into(),
                        "delete from".into(),
                        "drop table".into(),
                        "drop database".into(),
                        "update set".into(),
                        "exec(".into(),
                        "execute(".into(),
                        "xp_cmdshell".into(),
                        "information_schema".into(),
                        "sysobjects".into(),
                        "syscolumns".into(),
                        "';--".into(),
                        "';#".into(),
                        "\";--".into(),
                        "\";#".into(),
                    ]),
                    action: WafAction::Block,
                    score: 10,
                },
                WafRule {
                    id: "owasp_rce".into(),
                    phase: WafPhase::RequestBody,
                    condition: WafCondition::BodyContains(vec![
                        "exec(".into(),
                        "system(".into(),
                        "passthru(".into(),
                        "shell_exec(".into(),
                        "popen(".into(),
                        "proc_open(".into(),
                        "eval(".into(),
                        "assert(".into(),
                        "base64_decode(".into(),
                        "gzinflate(".into(),
                        "str_rot13(".into(),
                        "| cat /etc/passwd".into(),
                        "| ls -la".into(),
                        "| wget ".into(),
                        "| curl ".into(),
                        ";cat ".into(),
                        ";ls ".into(),
                        ";pwd".into(),
                        "&&cat ".into(),
                        "&&ls ".into(),
                    ]),
                    action: WafAction::Block,
                    score: 10,
                },
                WafRule {
                    id: "owasp_path_traversal".into(),
                    phase: WafPhase::RequestBody,
                    condition: WafCondition::BodyContains(vec![
                        "../".into(),
                        "..\\".into(),
                        "%2e%2e%2f".into(),
                        "%2e%2e/".into(),
                        "..%2f".into(),
                        "%2e%2e%5c".into(),
                        "..%5c".into(),
                        "%252e%252e%252f".into(),
                        "%c0%ae%c0%ae%c0%af".into(),
                        "/etc/passwd".into(),
                        "/etc/shadow".into(),
                        "/proc/self/environ".into(),
                    ]),
                    action: WafAction::Block,
                    score: 10,
                },
                WafRule {
                    id: "owasp_xss".into(),
                    phase: WafPhase::RequestBody,
                    condition: WafCondition::BodyContains(vec![
                        "<script".into(),
                        "<script>".into(),
                        "</script>".into(),
                        "javascript:".into(),
                        "vbscript:".into(),
                        "onload=".into(),
                        "onerror=".into(),
                        "onclick=".into(),
                        "onfocus=".into(),
                        "onblur=".into(),
                        "<iframe".into(),
                        "<object".into(),
                        "<embed".into(),
                        "<applet".into(),
                        "<form".into(),
                        "<input".into(),
                        "<textarea".into(),
                        "<button".into(),
                        "<select".into(),
                        "<style".into(),
                        "<link".into(),
                        "<meta".into(),
                        "<base".into(),
                        "expression(".into(),
                        "url(".into(),
                        "data:text/html".into(),
                    ]),
                    action: WafAction::Block,
                    score: 10,
                },
                WafRule {
                    id: "owasp_xxe".into(),
                    phase: WafPhase::RequestBody,
                    condition: WafCondition::BodyContains(vec![
                        "<!DOCTYPE".into(),
                        "<!ENTITY".into(),
                        "SYSTEM \"file:".into(),
                        "SYSTEM 'file:".into(),
                        "<![CDATA[".into(),
                        "]>".into(),
                        "&xxe;".into(),
                        "&ext;".into(),
                    ]),
                    action: WafAction::Block,
                    score: 10,
                },
                WafRule {
                    id: "owasp_ssrf".into(),
                    phase: WafPhase::RequestBody,
                    condition: WafCondition::BodyContains(vec![
                        "http://localhost".into(),
                        "http://127.0.0.1".into(),
                        "http://0.0.0.0".into(),
                        "http://::1".into(),
                        "http://169.254.".into(),
                        "http://10.".into(),
                        "http://172.16.".into(),
                        "http://172.17.".into(),
                        "http://172.18.".into(),
                        "http://172.19.".into(),
                        "http://172.20.".into(),
                        "http://172.21.".into(),
                        "http://172.22.".into(),
                        "http://172.23.".into(),
                        "http://172.24.".into(),
                        "http://172.25.".into(),
                        "http://172.26.".into(),
                        "http://172.27.".into(),
                        "http://172.28.".into(),
                        "http://172.29.".into(),
                        "http://172.30.".into(),
                        "http://172.31.".into(),
                        "http://192.168.".into(),
                        "https://localhost".into(),
                        "https://127.0.0.1".into(),
                        "https://0.0.0.0".into(),
                    ]),
                    action: WafAction::Block,
                    score: 8,
                },
                WafRule {
                    id: "owasp_ldap_injection".into(),
                    phase: WafPhase::RequestBody,
                    condition: WafCondition::BodyContains(vec![
                        ")(|(".into(),
                        ")(cn=".into(),
                        ")(uid=".into(),
                        ")(sn=".into(),
                        ")(objectClass=".into(),
                        "*()|&'".into(),
                    ]),
                    action: WafAction::Block,
                    score: 8,
                },
                WafRule {
                    id: "owasp_xpath_injection".into(),
                    phase: WafPhase::RequestBody,
                    condition: WafCondition::BodyContains(vec![
                        "//*".into(),
                        "/*".into(),
                        "[@".into(),
                        "and 1=1".into(),
                        "or 1=1".into(),
                        "and 2=2".into(),
                        "or 2=2".into(),
                        "string-length(".into(),
                        "substring(".into(),
                        "concat(".into(),
                    ]),
                    action: WafAction::Block,
                    score: 8,
                },
                WafRule {
                    id: "owasp_sql_token_match".into(),
                    phase: WafPhase::RequestBody,
                    condition: WafCondition::SqlTokenMatch,
                    action: WafAction::Block,
                    score: 5,
                },
            ],
            max_body_size: 4 * 1024 * 1024,
            anomaly_threshold: 10,
            excludes: vec![],
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum WafMode {
    DetectionOnly,
    #[default]
    Blocking,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WafRule {
    pub id: String,
    pub phase: WafPhase,
    pub condition: WafCondition,
    pub action: WafAction,
    pub score: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WafPhase {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WafAction {
    Log,
    Block,
    Redirect(String),
    Challenge,
    RateLimit,
    Allow,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WafCondition {
    IpMatch(Vec<String>),
    PathStartsWith(String),
    HeaderContains { header: String, value: String },
    BodyContains(Vec<String>),
    UserAgentContains(Vec<String>),
    SqlTokenMatch,
    BodyRegex(String),
}
