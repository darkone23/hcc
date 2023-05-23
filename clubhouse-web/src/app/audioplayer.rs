use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use yew::prelude::*;
use yew_hooks::prelude::{use_event, use_mount};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace=audioplayer)]
    pub fn subscribe(el: &web_sys::Element);

    #[wasm_bindgen(js_namespace=audioplayer)]
    pub fn push(title: &str, url: &str, duration: i32, khz: i32, kbps: i32);

    #[wasm_bindgen(js_namespace=audioplayer)]
    pub fn select(el: i32);

    #[wasm_bindgen(js_namespace=audioplayer)]
    pub fn stop();

    #[wasm_bindgen(js_namespace=audioplayer)]
    pub fn play();

    #[wasm_bindgen(js_namespace=audioplayer)]
    pub fn pause();

    #[wasm_bindgen(js_namespace=audioplayer)]
    pub fn forward();

    #[wasm_bindgen(js_namespace=audioplayer)]
    pub fn back();
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AudioNode {
    url: String,
    title: String,
    duration: i32,
    seek: i32,
    khz: i32,
    kbps: i32,
    num: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AudioPlayerState {
    selected: usize,
    current: usize,
    state: String,
    tracks: Vec<AudioNode>,
}

impl AudioPlayerState {
    fn default() -> Self {
        AudioPlayerState {
            selected: 0,
            current: 0,
            state: String::from("stop"),
            tracks: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct AudioEvent {
    msg: String,
    player: AudioPlayerState,
}

struct NowPlayingDigits {
    seconds_digit_one: char,
    seconds_digit_two: char,
    minutes_digit_one: char,
    minutes_digit_two: char,
    minutes_digit_three: char,
}

impl NowPlayingDigits {
    fn from(duration: &i32) -> Self {
        let minutes = duration / 60;
        let seconds = duration % 60;
        let minutes_as_str = format!("{:01}", minutes).chars().collect::<Vec<_>>();
        let seconds_as_str = format!("{:02}", seconds).chars().collect::<Vec<_>>();
        NowPlayingDigits {
            seconds_digit_one: seconds_as_str.get(0).unwrap_or_else(|| &' ').to_owned(),
            seconds_digit_two: seconds_as_str.get(1).unwrap_or_else(|| &' ').to_owned(),

            minutes_digit_one: minutes_as_str.get(0).unwrap_or_else(|| &' ').to_owned(),
            minutes_digit_two: minutes_as_str.get(1).unwrap_or_else(|| &' ').to_owned(),
            minutes_digit_three: minutes_as_str.get(2).unwrap_or_else(|| &' ').to_owned(),
        }
    }

    fn empty() -> Self {
        NowPlayingDigits {
            seconds_digit_one: ' ',
            seconds_digit_two: ' ',
            minutes_digit_one: ' ',
            minutes_digit_two: ' ',
            minutes_digit_three: ' ',
        }
    }
}

impl ToString for NowPlayingDigits {
    fn to_string(&self) -> String {
        String::from(
            format!(
                "{}{}{}:{}{}", // weird css-float-right stuff going on here....
                self.minutes_digit_three,
                self.minutes_digit_two,
                self.minutes_digit_one,
                self.seconds_digit_one,
                self.seconds_digit_two
            )
            .trim(),
        )
    }
}

struct NowPlayingMarquee {
    title: String,
}

impl NowPlayingMarquee {
    fn from(index: &usize, track: &AudioNode) -> Self {
        let track_num = index + 1;
        let title = format!("{}. {} * * *", track_num, &track.title);
        NowPlayingMarquee { title: title }
    }

    fn empty() -> Self {
        NowPlayingMarquee {
            title: String::from("* * *"),
        }
    }

    fn is_empty(&self) -> bool {
        self.title == "* * *"
    }

    fn elements(self: &Self) -> Html {
        if self.is_empty() {
            html! {
                <div />
            }
        } else {
            html! {
                    <div>
                        <span>{&self.title}</span>
                        <span>{&self.title}</span>
                        <span>{&self.title}</span>
                        <span>{&self.title}</span>
                        <span>{&self.title}</span>
                        <span>{&self.title}</span>
                        <span>{&self.title}</span>
                        <span>{&self.title}</span>
                        <span>{&self.title}</span>
                        <span>{&self.title}</span>
                    </div>
            }
        }
    }

    fn class(&self) -> String {
        if self.is_empty() {
            String::from("")
        } else {
            String::from("marquee")
        }
    }
}

struct AudioPlaylist {
    state: AudioPlayerState,
}

impl AudioPlaylist {
    fn elements(self: &Self) -> Html {
        let selected_url = if let Some(track) = self.state.tracks.get(self.state.selected) {
            String::from(&track.url)
        } else {
            String::from("unset")
        };

        let current_url = if let Some(track) = self.state.tracks.get(self.state.current) {
            String::from(&track.url)
        } else {
            String::from("unset")
        };
        let elements = self
            .state
            .tracks
            .clone()
            .into_iter()
            .map(|track| {
                let selected_class_name = if current_url == track.url {
                    String::from("active")
                } else {
                    String::from("")
                };

                let active_class_name = if selected_url == track.url {
                    String::from("selected")
                } else {
                    String::from("")
                };

                let class_name = format!("{} {}", selected_class_name, active_class_name);

                let track_idx = track.num - 1;

                let digits = NowPlayingDigits::from(&track.duration);
                html! {

                        <li class={class_name} onclick={move |_| { select(track_idx) }}>
                          <span class="num">{track.num}</span>
                          <span class="title">{track.title}</span>
                          <span class="duration float-right">{digits}</span>
                        </li>
                }
            })
            .collect::<Html>();

        html! {
              <ul class="text-left list-none">
                {elements}
              </ul>
        }
    }
}

#[function_component(AudioPlayer)]
pub fn audioplayer() -> Html {
    let player_node = use_node_ref();

    let player_state = use_state(|| AudioPlayerState::default());

    let _audio_events = {
        let player_node = player_node.clone();
        let player_state = player_state.clone();
        use_event(
            player_node,
            "audioplayer",
            move |ev: web_sys::CustomEvent| {
                let detail = ev.detail();
                let audio_event: AudioEvent =
                    serde_wasm_bindgen::from_value(detail).expect("hope I can serde");
                let player = audio_event.player;
                player_state.set(player);
            },
        )
    };

    let _mount_events = {
        let player_node = player_node.clone();

        use_mount(move || {
            let maybe_cast = player_node.cast::<web_sys::HtmlHeadElement>();

            let el = maybe_cast.expect("hope this works...");
            subscribe(&el);
        })
    };

    let current_player_state = &*player_state;
    let current_global_state = String::from(&current_player_state.state);
    let maybe_current_track = current_player_state
        .tracks
        .get(current_player_state.current);

    let now_playing_digits: NowPlayingDigits = if let Some(track) = maybe_current_track {
        NowPlayingDigits::from(&track.seek)
    } else {
        NowPlayingDigits::empty()
    };

    let seek_class = if let Some(track) = maybe_current_track {
        let percent_f32 = (track.seek as f32) / (track.duration as f32);
        let percent_i32 = (percent_f32 * 100.0) as i32;
        format!("seek-left-{}pc", percent_i32)
    } else {
        format!("seek-left-0pc hidden")
    };

    let now_playing_marquee: NowPlayingMarquee = if let Some(track) = maybe_current_track {
        NowPlayingMarquee::from(&current_player_state.current, &track)
    } else {
        NowPlayingMarquee::empty()
    };

    let (khz, kbps) = if let Some(track) = maybe_current_track {
        (track.khz.to_string(), track.kbps.to_string())
    } else {
        (String::from(""), String::from(""))
    };

    let playlist: AudioPlaylist = AudioPlaylist {
        state: current_player_state.to_owned(),
    };

    let state_indicator_id = format!("webamp-state-indicator-{}", current_global_state);

    let webamp = html! {
     <div id="webamp-player" ref={player_node} >
      <div id="webamp-main-window">
        <div id="webamp-main-top"></div>
        <div id="webamp-main-info">
          <div id="webamp-main-info-now-playing-left">
            <div id="webamp-main-info-now-playing-indicator">
              <span id={state_indicator_id} />
            </div>
            <div id="webamp-main-info-now-playing-digits">
              <div id="webamp-main-info-now-playing-minutes">
                <span id="webamp-now-playing-minute-digit-3">{now_playing_digits.minutes_digit_three}</span>
                <span id="webamp-now-playing-minute-digit-2">{now_playing_digits.minutes_digit_two}</span>
                <span id="webamp-now-playing-minute-digit-1">{now_playing_digits.minutes_digit_one}</span>
              </div>
              <div id="webamp-main-info-now-playing-seconds">
                <span id="webamp-now-playing-second-digit-1">{now_playing_digits.seconds_digit_one}</span>
                <span id="webamp-now-playing-second-digit-2">{now_playing_digits.seconds_digit_two}</span>
              </div>
            </div>
          </div>
          <div id="webamp-main-info-now-playing-right">
            <div class={now_playing_marquee.class()}
                 id="webamp-main-info-now-playing-title-marquee">
              {now_playing_marquee.elements()}
            </div>
            <div id="webamp-main-info-now-playing-kbps">
              <span>{kbps}</span>
            </div>
            <div id="webamp-main-info-now-playing-khz">
              <span>{khz}</span>
            </div>
          </div>
          <div id="webamp-main-info-volume">
            // <!-- can animate via margin-left property from 0-62% -->
            <div id="webamp-main-info-volume-position" draggable="true">
            </div>
          </div>
          <div id="webamp-main-info-overlay">
          </div>
        </div>
        <div id="webamp-main-seek">
          <div id="webamp-main-seek-playhead" class={seek_class} draggable="true"></div>
        </div>
        <div id="webamp-main-controls">
          <div id="webamp-main-controls-actions">
            <div id="webamp-main-controls-action-back" onclick={|_| { back() }}></div>
            <div id="webamp-main-controls-action-play" onclick={|_| { play() }}></div>
            <div id="webamp-main-controls-action-pause" onclick={|_| { pause() }}></div>
            <div id="webamp-main-controls-action-stop" onclick={|_| { stop() }}></div>
            <div id="webamp-main-controls-action-forward" onclick={|_| { forward() }}></div>
          </div>
          <div id="webamp-main-controls-overlay"></div>
          <a href="https://archive.org/details/winampskins_OS8_AMP_-_Magenta" target="_blank">
          <div id="webamp-main-controls-info"></div>
          </a>
      </div>
      <div id="webamp-playlist-window">
        <div id="webamp-playlist-top">
          <div id="webamp-playlist-top-left"></div>
          <div class="webamp-playlist-spacer"></div>
          <div class="webamp-playlist-spacer"></div>
          <div class="webamp-playlist-spacer"></div>
          <div id="webamp-playlist-top-title"></div>
          <div class="webamp-playlist-spacer"></div>
          <div class="webamp-playlist-spacer"></div>
          <div class="webamp-playlist-spacer"></div>
          <div id="webamp-playlist-top-right"></div>
        </div>
        <div id="webamp-playlist-middle">
          <div id="webamp-playlist-middle-left">
            <div class="repeat-y"></div>
            <div class="repeat-y"></div>
            <div class="repeat-y"></div>
          </div>
          <div id="webamp-playlist-middle-center">
            <div id="webamp-playlist-middle-contents">
              {playlist.elements()}
            </div>
          </div>
          <div id="webamp-playlist-middle-right">
            <div class="repeat-y"></div>
            <div class="repeat-y"></div>
            <div class="repeat-y"></div>
            <div id="webamp-playlist-middle-scroll" draggable="true"></div>
          </div>
        </div>
        <div id="webamp-playlist-bottom">
          <div id="webamp-playlist-bottom-left">
            <div id="webamp-playlist-bottom-overlay">
              <hr />
            </div>
          </div>
          <div id="webamp-playlist-bottom-center"></div>
          <div id="webamp-playlist-bottom-right"></div>
        </div>
      </div>
      </div>
    </div>
    };

    html! {
        webamp
        // <div>{"I am an audioplayer"}</div>
    }
}
