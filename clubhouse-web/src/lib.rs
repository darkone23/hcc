#![recursion_limit = "512"]

mod app;
mod encryption;
mod htmx;
mod media_renderer;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

pub use encryption::recv_claims;
pub use encryption::ClientKeyring;

pub use media_renderer::render_media_node;

// This is like the `main` function, except for JavaScript.

#[wasm_bindgen]
pub fn render_app() {
    let render = Closure::wrap(Box::new(move || {
        yew::Renderer::<app::home::App>::new().render();
        ()
    }) as Box<dyn FnMut()>);

    let render_fn = render.as_ref().unchecked_ref();

    let window = web_sys::window().unwrap();
    window
        .request_animation_frame(render_fn)
        .expect("request app rendering");

    render.forget();
}

#[wasm_bindgen(start)]
pub fn main_js() -> Result<(), JsValue> {
    // we have to wait until our encryption is loaded to render, so we will just export our render_app fn instead

    wasm_logger::init(wasm_logger::Config::default());

    Ok(())
}
