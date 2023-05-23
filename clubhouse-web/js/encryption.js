
let origin = "";
try {
  origin = new URL(document.referrer).origin;
} catch (e) {
  console.warn("Failed to parse document origin", document && document.referrer)
}


const [antiForgeryKey, encryptionKey] = ["au", "af", "ec"];
const TOKEN_DB = {
  [antiForgeryKey]: undefined,
  [encryptionKey]: undefined,
};

let loaded = false;
let working = false;

let callbacks = [];

function onLoad(cb) {
  if (typeof cb === "function") {
    callbacks.push(cb);
    if (loaded) {
      cb()
    }
  }
}

function handleEvent(event) {
  // console.log("handling event:", event);
  
  if (event && event.origin !== origin) {
    // console.log("I DONT LKE YOUR ORIGIN!", origin, "!=", event.origin);
    return;
  } else if (!window.recv_claims || !window.EphemeralKeyring) {
    // console.log("I AM NOT READY TO RECEIVE THESE CLAIMS");
    requestAnimationFrame(handleEvent.bind(null, event));
    return;
  } else if (loaded) {
    // console.log("WORK IS COMPLETE ALREADY");
    return;
  }

  let claims = recv_claims(origin, event.data.token);

  let keyring = new EphemeralKeyring(claims);

  TOKEN_DB[encryptionKey] = keyring;
  TOKEN_DB[antiForgeryKey] = keyring.handle_csrf_challenge(event.data.token);

  event.source.postMessage("ack-token", event.origin);
  window.removeEventListener("message", recvTokenMessage);

  loaded = true;
  
  // console.log("loaded and time to call the callbacks...");
  
  callbacks.forEach(cb => cb());
  
}

function recvTokenMessage(event) {

  // console.log("I am receiving a message from my parent window...", event);
  
  if (working) {
    // console.log("I AM ALREADY WORKING");
    return;
  }
  
  working = true
  
  requestAnimationFrame(handleEvent.bind(null, event));
  
}

window.addEventListener("message", recvTokenMessage);

export default {
    getKeyring: function() {
        return TOKEN_DB[encryptionKey];
    },
    getAntiForgeryToken: function() {
        return TOKEN_DB[antiForgeryKey];
    },
    onEncryptionLoad: onLoad
  };
