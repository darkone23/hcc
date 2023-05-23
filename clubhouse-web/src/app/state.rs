/*
use super::tabs::get_tabs;

use bounce::*;

#[derive(PartialEq, Atom)]
pub struct ActiveTab {
    pub name: String,
}

impl From<String> for ActiveTab {
    fn from(s: String) -> Self {
        Self { name: s }
    }
}

impl Default for ActiveTab {
    fn default() -> Self {
        Self {
            name: String::from(&get_tabs().get(0).unwrap().name),
        }
    }
}

impl fmt::Display for ActiveTab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}
*/
