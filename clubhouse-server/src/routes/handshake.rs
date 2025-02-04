use tide::{Redirect, Request, Result};

use crate::wiring::ServerWiring;
use domain::session::SessionUser;

pub async fn get(req: Request<ServerWiring>) -> Result {

    // REDIRECT EITHER TO LOGIN APP OR REGULAR APP

    let maybe_user: Option<&SessionUser> = req.ext();

    if maybe_user.is_some() {
        Ok(Redirect::new("/app").into())
    } else {
        Ok(Redirect::new("/login").into())
    }
}