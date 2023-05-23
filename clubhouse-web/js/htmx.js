import encryption from "./encryption";

import "htmx.org";
const htmx = (window.htmx = require("htmx.org"));


function is_element(el) {
  return el && typeof el.getElementsByClassName === "function";
}

function init_media_wall_plugin(el) {
  /*

  media wall transforms a server-side widget into a yew component... needs a little wiring to hook it together

  important classes here are:
    div.media-wall
      > div.media_node

  */

  if (is_element(el)) {
    let collection = el.getElementsByClassName("media-wall");
    let found = collection[0];
    if (is_element(found)) {
      collection = found.getElementsByClassName("media-node");
      Array.from(collection).forEach(function(item) {
        let data = item.dataset;
        let slug = data["slug"];
        let medium = data["medium"];
        let media = JSON.parse(atob(data["media"]));
        if (typeof window.render_media_node === "function") {
          window.render_media_node(item, slug, medium, media);
        }
      });
    }
  }
}

htmx.onLoad(function(target) {
  init_media_wall_plugin(target);
});

let jwt;

let formTransform = {
  "password_confirm": function(key, value, keyring) {
    return ["password_bcrypt", keyring.encrypt(value)];
  },
  "__encrypt": function(key, value, keyring) {
    return [key, keyring.encrypt(value)];
  }
}

function signRequestHeaders(evt) {
  // notice: both AUTH_TOKEN and ANTI_FORGERY_TOKEN
  // are already encrypted using the client encryption key received by the JWT session handshake

  if (evt && evt.detail && evt.detail.headers) {
    // todo: only sign request if we are requesting a secure asset
    if (jwt) {
      evt.detail.headers["x-auth-token"] = jwt;
    }

    // todo: only sign with CSRF if unsafe request method
    const csrf = encryption.getAntiForgeryToken();

    if (csrf) {
      evt.detail.headers["x-anti-forgery-token"] = csrf;
    }

    let keyring = encryption.getKeyring();

    for (const [key, value] of Object.entries(evt.detail.parameters)) {
      let lookupKey = formTransform.hasOwnProperty(key) ? key : "__encrypt";
      let [nextKey, nextValue] = formTransform[lookupKey](key, value, keyring);
      delete evt.detail.parameters[key] ;
      evt.detail.parameters[nextKey] = nextValue;
    }
  }
}

function decryptResponse(evt) {
  let header = evt.detail.xhr.getResponseHeader("x-auth-token");

  let keyring = encryption.getKeyring();

  if (header) {
    jwt = keyring.handle_jwt_challenge(header);
  }

  let obj = evt.detail;
  if (obj && obj.serverResponse) {
    let target = obj.target;
    let serverHtml = keyring.decrypt(obj.serverResponse);

    let node = document.createElement("div");
    node.className = "hcc-htmx";
    node.innerHTML = serverHtml;

    obj["serverResponse"] = serverHtml;
    obj["target"] = node;

    htmx.process(obj.target);

    target.innerHTML = "";
    target.appendChild(obj.target);
  }
}

document.body.addEventListener("htmx:configRequest", signRequestHeaders);

document.body.addEventListener("htmx:beforeSwap", decryptResponse);
