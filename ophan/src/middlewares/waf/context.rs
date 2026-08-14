#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum WafState {
    /// The request has not been inspected.
    #[default]
    NotInspected,

    /// The request was inspected and no blocking rule matched.
    Allowed,

    /// The request matched one or more rules, but was only logged.
    Logged,

    /// The request matched one or more blocking rules.
    Blocked,
}

/// This context stores the inspection result and metadata that may be used
/// for logging, metrics, or response generation.
#[derive(Debug, Default)]
pub struct WafContext {
    /// Final inspection state.
    pub state: WafState,

    /// Identifier of the rule responsible for the final decision.
    ///
    /// `None` if no rule matched.
    pub matched_rule: Option<String>,

    /// Accumulated anomaly score assigned during inspection.
    ///
    /// Higher scores indicate a greater likelihood of malicious traffic.
    pub score: u32,
}
