use web_sys::Element;

use yew::prelude::*;
use yew_hooks::prelude::use_mount;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::app::audioplayer;

struct MediaRenderer {}

#[derive(Properties, Clone, PartialEq)]
struct MediaRendererProps {
    slug: String,
    medium: String,
    media: JsValue,
}

#[derive(Properties, Serialize, Deserialize, Clone, PartialEq)]
struct AudioNodeProps {
    // Matches AudioMedia on server...
    // pull into shared lib...
    title: String,
    duration: i32,
    khz: i32,
    kbps: i32,
    url: String,
}

#[function_component(AudioNode)]
fn audio_node(props: &AudioNodeProps) -> Html {
    let _mount_event = {
        let props = props.clone();
        use_mount(move || {
            audioplayer::push(
                props.title.as_str(),
                props.url.as_str(),
                props.duration,
                props.khz,
                props.kbps,
            )
        })
    };
    html! {
        <span />
    }
}

#[derive(Properties, Serialize, Deserialize, Clone, PartialEq)]
struct ImageNodeProps {
    url: String, // todo: add alt text, etc
}

#[function_component(ImageNode)]
fn image_node(props: &ImageNodeProps) -> Html {
    html! {
        <img src={props.url.clone()} />
    }
}

#[derive(Properties, Serialize, Deserialize, Clone, PartialEq)]
struct TextNodeProps {
    body: String,
}

#[function_component(TextNode)]
fn text_node(props: &TextNodeProps) -> Html {
    html! {
        <span>{props.body.clone()}</span>
    }
}

impl MediaRenderer {
    fn render_image(&self, ctx: &Context<Self>) -> Html {
        let media = ctx.props().media.to_owned();
        let parsed: ImageNodeProps =
            serde_wasm_bindgen::from_value(media).expect("hope I can serde media - img");
        html! {
            <ImageNode url={parsed.url}/>
        }
    }

    fn render_text(&self, ctx: &Context<Self>) -> Html {
        let media = ctx.props().media.to_owned();
        let parsed: TextNodeProps =
            serde_wasm_bindgen::from_value(media).expect("hope I can serde media - txt");
        html! {
            <TextNode body={parsed.body} />
        }
    }

    fn render_audio(&self, ctx: &Context<Self>) -> Html {
        let media = ctx.props().media.to_owned();
        let parsed: AudioNodeProps =
            serde_wasm_bindgen::from_value(media).expect("hope I can serde media - audio");
        html! {
            <AudioNode url={parsed.url}
                       title={parsed.title}
                       duration={parsed.duration}
                       khz={parsed.khz}
                       kbps={parsed.kbps} />
        }
    }

    fn render_default(&self, ctx: &Context<Self>) -> Html {
        let medium = ctx.props().medium.clone();
        let slug = ctx.props().slug.clone();
        let title = format!("{}: {}", medium, slug);
        html! {
            <div>
                <h1>{title}</h1>
            </div>
        }
    }
}

impl Component for MediaRenderer {
    type Message = ();
    type Properties = MediaRendererProps;

    fn create(_ctx: &Context<Self>) -> Self {
        Self {}
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match ctx.props().medium.as_str() {
            "image" => self.render_image(ctx),
            "text" => self.render_text(ctx),
            "audio" => self.render_audio(ctx),
            _ => self.render_default(ctx),
        }
    }
}

#[wasm_bindgen]
pub fn render_media_node(el: Element, slug: String, media_type: String, media_json: JsValue) {
    let props = yew::props!(MediaRenderer::Properties {
        slug: slug,
        medium: media_type,
        media: media_json
    });

    yew::Renderer::<MediaRenderer>::with_root_and_props(el, props).render();
}
