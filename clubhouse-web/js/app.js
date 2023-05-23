import("../css/app.css");

import("./audioplayer.js");

// need to load in dependency order to get around race conditions

// console.log("time to start to import index.js")
import("../pkg/index.js").then((x => {
    // console.log("imported index.js");
    // global exports for JS interop here:

    window.recv_claims = x.recv_claims;
    window.EphemeralKeyring = x.ClientKeyring;
    window.render_media_node = x.render_media_node;
    
    let render = x.render_app;

    // console.log("window exports complete")
    
    import("./encryption.js").then(obj => {
        
        let encryption = obj.default;

        // console.log("encryption module loaded", encryption);

        encryption.onEncryptionLoad(function() {
            
            import("./htmx.js").then(_ => {
            
                // console.log("htmx module loaded");
                render();
    
            });
            
        });
    
    });
    
}));