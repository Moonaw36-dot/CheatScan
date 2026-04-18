use std::fmt;

#[derive(Debug, Clone, Copy)]
pub enum ImportanceEnum {
    Safe,
    Suspicious,
    CheatMenu,
}

impl fmt::Display for ImportanceEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportanceEnum::Safe => write!(f, "Safe"),
            ImportanceEnum::Suspicious => write!(f, "Suspicious"),
            ImportanceEnum::CheatMenu => write!(f, "CheatMenu"),
        }
    }
}