/*
use yew::prelude::*;

use bounce::*;

#[derive(Clone, PartialEq, Atom)]
pub struct Tab {
    pub name: String,
    pub html: Html,
    pub htmx: bool,
}

impl Default for Tab {
    fn default() -> Self {
        get_tabs().get(1).unwrap().clone()
    }
}

impl fmt::Display for Tab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

pub fn get_tabs() -> [Tab; 3] {
    [
        Tab {
            name: "media".to_string(),
            html: html! {
                 <div key="media">
                    <div id="media-top-hx-target"
                         hx-get="/media"
                         hx-trigger="load" />
                 </div>
            },
            htmx: true,
        },
        Tab {
            name: "hcc".to_string(),
            html: html! {
                <div key="hcc">
                    <div id="hcc-top-hx-target"
                         hx-get="/handshake"
                         hx-trigger="load" />
                 </div>
            },
            htmx: true,
        },
        Tab {
            name: "about".to_string(),
            html: html! {
            <div key="about">
              <h1>{ "👋" }</h1>
              <p>{"nice to see you..." }</p>
            </div>
            },
            htmx: false,
        },
    ]
}

*/
