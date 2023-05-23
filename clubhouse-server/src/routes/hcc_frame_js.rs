use crate::{wiring::ServerWiring, util::encryption::ServerKeyring};

use tide::{http::mime, Request, Response, Result};

// for now - maybe forever:
// just serve the relative dist folder index as an iframe from the rs-wasm sibling project

use askama::Template; // bring trait in scope


#[derive(Template)] // this will generate the code...
#[template(path = "js/hcc_frame.js.j2")] // using the template in this path, relative
struct TokenView {
    csrf_secret_token: String,
    origin_domain: String
}

pub async fn get(req: Request<ServerWiring>) -> Result {

    let jwt_util = {
        req.state().services.jwt_util.clone()
    };

    let session_id = req.session().id();

    let secrets = req.ext::<ServerKeyring>().expect("do not have session secrets...");

    let config = &req.state().config;

    let csrf_secret_token = jwt_util.sign_csrf_token(session_id, &secrets).unwrap();
    
    let origin_domain = String::from(&config.domain);

    let view = TokenView {
        csrf_secret_token,
        origin_domain
    };

    let response_body = view.render().unwrap();

    let response = Response::builder(200)
        .content_type(mime::JAVASCRIPT)
        .body_string(response_body)
        .build();

    Ok(response)
}