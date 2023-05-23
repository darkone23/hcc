use crate::htmx::HtmxProcessedComponent;

use super::audioplayer::AudioPlayer;

use yew::prelude::*;
use yew_hooks::prelude::use_window_scroll;

/*

// this is here for tailwind parser...

opacity-0	opacity: 0;
opacity-10	opacity: 0.1;
opacity-20	opacity: 0.2;
opacity-25	opacity: 0.25;
opacity-30	opacity: 0.3;
opacity-40	opacity: 0.4;
opacity-50	opacity: 0.5;
opacity-60	opacity: 0.6;
opacity-70	opacity: 0.7;
opacity-80	opacity: 0.8;
opacity-90	opacity: 0.9;
opacity-100	opacity: 1;
​
Basic usage
*/

#[function_component(App)]
pub fn app() -> Html {
    let (_x, y) = use_window_scroll();

    let splash_ref = use_node_ref();

    let maybe_cast = splash_ref.cast::<web_sys::HtmlHeadElement>();

    let splash_height: i32 = if maybe_cast.is_some() {
        maybe_cast.unwrap().scroll_height() - 64 // header is 64 px
    } else {
        0
    };

    let scroll_depth = ((y as f32) / (splash_height as f32) * 10.0).floor() * 10.0;
    let scroll_depth_inverse = 100.0 - scroll_depth;

    let (header_opacity, splash_opacity) = if scroll_depth.is_nan() {
        (String::from("opacity-0"), String::from("opacity-100"))
    } else {
        (
            format!("opacity-{}", scroll_depth),
            format!("opacity-{}", scroll_depth_inverse),
        )
    };

    // log!("setting header opacity to: ", header_opacity.clone());

    let header_inner_styles = format!(
        "fixed top-0 h-16 z-10 w-full bg-black text-white p-4 transition-opacity {}",
        header_opacity
    );

    let splash_inner_styles = format!(
        "splash mx-auto h-screen mb-2 text-center transition-opacity {}",
        splash_opacity
    );

    let header_element = html! {
                    <div key="header-hx"
                         id="header-top-hx-target"
                         hx-get="/header"
                         hx-trigger="load" />
    };

    let splash_element = html! {
                    <div key="splash-hx"
                         id="splash-top-hx-target"
                         hx-get="/splash"
                         hx-trigger="load" />
    };

    let media_wall = html! {
                    <div key="media-hx"
                         id="hcc-top-hx-target"
                         hx-get="/media"
                         hx-trigger="load" />
    };

    let sidebar_element = html! {
                    <div key="sidebar-hx"
                         id="sidebar-top-hx-target"
                         hx-get="/sidebar"
                         hx-trigger="load" />
    };

    let footer_element = html! {
                    <div key="footer-hx"
                         id="footer-top-hx-target"
                         hx-get="/footer"
                         hx-trigger="load" />
    };

    let body = html! {
      <div class="page scroll-smooth text-white">

        <div class={header_inner_styles}>
            {header_element}
        </div>

        <div class="content-wrapper relative">

              <div ref={splash_ref} class={splash_inner_styles}>
                {splash_element}
              </div>

              <div class="main-content-container">
                    <div class="main-content min-h-screen flex pb-6">

                        <div class="content-items flex-1">
                            {media_wall}
                        </div>

                        <div class="sidebar text-center mr-3">
                          <div class="sticky top-16">

                            <div class="sidebar-main">
                                <AudioPlayer />
                            </div>

                            <div class="sidebar-extra mb-12 relative top-4">
                                {sidebar_element}
                            </div>
                        </div>

                        </div>
                   </div>

                  <div class="footer w-full z-10 mt-2 pt-2 text-center">
                    {footer_element}
                  </div>
                </div>

        </div>

    </div>

    };

    html! {
      <HtmxProcessedComponent name={"app"} body={body} process={true} />
    }
}

/*
#[function_component(Header)]
fn header() -> Html {
    html! {
      <h1 class="bg-white bg-opacity-75 p-1 text-4xl font-extralight tracking-widest">{ "homepage" }</h1>
    }
}

#[function_component(Sidebar)]
fn sidebar() -> Html {
    let on_tab_select = {
        let setter = use_atom_setter::<ActiveTab>();
        Callback::from(move |tab: Tab| setter(ActiveTab::from(tab.name)))
    };

    let tab_vec: Vec<Tab> = get_tabs().into();

    let tabs = html! {
      <SidebarTabsList
        tabs={tab_vec}
        on_click={on_tab_select} />
    };

    html! {
      <ul>{tabs}</ul>
    }
}

#[function_component(Content)]
fn content() -> Html {
    let tabs = get_tabs();
    let active = use_atom_value::<ActiveTab>();
    let active_tab = tabs.iter().find(|t| active.name == t.name).unwrap();

    html! {
        <HtmxProcessedComponent
            name={active_tab.name.clone()}
            process={active_tab.htmx}
            body={active_tab.html.clone()} />
    }
}

#[derive(Clone, Properties, PartialEq)]
struct SidebarTabsListProps {
    tabs: Vec<Tab>,
    on_click: Callback<Tab>,
}

#[function_component(SidebarTabsList)]
fn tabs_list(SidebarTabsListProps { tabs, on_click }: &SidebarTabsListProps) -> Html {
    tabs.iter()
        .map(|tab| {
            let on_tab_click = {
                let callback = on_click.clone();
                let t = tab.clone();
                Callback::from(move |_| callback.emit(t.clone()))
            };

            let active = use_atom_value::<ActiveTab>();

            let is_active_class = {
                if active.name == tab.name {
                    "active"
                } else {
                    "inactive"
                }
            };

            let class_name = format!("link {}", is_active_class);

            html! {
              <li onclick={on_tab_click} class={class_name}>{&tab.name}</li>
            }
        })
        .collect()
}

*/
