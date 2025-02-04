{
  description = "hcc build flake";

  inputs = {

    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";     
    
  };


  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rust_env = 
            (pkgs.rust-bin.stable.latest.default.override {
              extensions = [ "rust-src" ];
              targets = [
                "x86_64-unknown-linux-gnu"  
                "wasm32-unknown-unknown"
              ];
            });
      in
      with pkgs;
      {
        devShells.default = mkShell {
          nativeBuildInputs = [
            pkg-config
          ];

          buildInputs = [
            openssl
            openssl.bin

            glibc

            nodejs
            nodePackages.typescript-language-server
            yarn

            wasm-pack
            binaryen

            rust_env
            rust-analyzer

          ];

        };
      }
    );

}