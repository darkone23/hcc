{ 
  fetchurl
, rustPlatform
, cmake
, pkg-config
, openssl
, installShellFiles
}:

rustPlatform.buildRustPackage rec {
  pname = "sea-orm-cli";
  version = "0.11.3";

  # url = "https://crates.io/api/v1/crates/sea-orm-cli/0.11.3/download";
  src = ./sea-orm-cli-0.11.3/.;  

  cargoSha256 = "sha256-4lPtj11Gc+0r2WQT8gx8eX+YK5L+HnUBR0w6pm3VlRQ=";

  nativeBuildInputs = [ cmake pkg-config installShellFiles ];

  buildInputs = [ 
      openssl
      openssl.bin
   ]; 

  doCheck = false;

}
