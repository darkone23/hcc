{
  description = "hcc build flake";

  inputs = {

    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
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
      in
      with pkgs;
      {
        devShells.default = mkShell {
          nativeBuildInputs = [
            pkg-config            
          ];
          buildInputs = [
            (rust-bin.stable.latest.default.override {
              extensions = [ "rust-src" ];
              targets = [
                "x86_64-unknown-linux-gnu"  
              ];
            })
            rust-analyzer

            openssl
            openssl.bin
          ];
        };
      }
    );

}