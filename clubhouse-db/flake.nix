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
        # todo: figure out how to do this the 'non-legacy' way
        #       - define this as an overlay or something?
        sea_orm_cli = nixpkgs.legacyPackages.${system}.callPackage ./nixpkgs/sea-orm-cli {};
      in
      with pkgs;
      {
        sea_orm_cli = sea_orm_cli;
        devShells.default = mkShell {
          buildInputs = [
            rust-bin.stable.latest.default
            pkg-config
            openssl
            openssl.bin
            sea_orm_cli
          ];
        };
      }
    );

}