# hcc-client

source repository for holycharisma client

## building

managed by npm + webpack + cargo + webassembly

```
- yarn install
- yarn run [watch|build]
```

## client tech stack:

- [rust](https://www.rust-lang.org/) + [webassembly](https://rustwasm.github.io/docs/book/) 
    - rust on the browser, compiles to native wasm
    - intended to provide some level of code-sharing between client and server 

- [yew](https://yew.rs/)
    - toolkit similar to react
    - create web-ui binaries for scripting the browser 
    - interacting with js like ffi

- [htmx](https://htmx.org/)
    - declarative http interactions 
        - `data-hx-patch="/api/some-resource/32"`
    - relies on server side templating to handle responses
        - check out `hcc-server/templates`

- [tailwind](https://tailwindcss.com/)
    - css framework 
    - utility functions for styling
    - runs in js toolkit via [postcss](https://postcss.org/)

## security approach

- server generates secure keyring for session
- sends it to client app via encrypted JWT claims
- all session cookies are httponly 
    - server session not available to client
    - authenticated user may be associated with session
- login handshake with hcc-server:
    - client form POST encrypted email and password to /login
    - server decrypts, verifies, responds with:
        - redirect to application
        - authorization credentials in http headers
    - client stores credentials for subsequent requests
- second anti-csrf token is used to verify the client is running within the hcc-server frame
    - token is signed with server session id hash to verify secure http cookies exist between client and server
- includes [orion](https://github.com/orion-rs/orion) over wasm for client side encryption and decryption

project generated using [yew-wasm-pack-minimal](https://github.com/yewstack/yew-wasm-pack-minimal)