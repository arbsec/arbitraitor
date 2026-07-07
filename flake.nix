{
  description = "Policy-enforced download, inspection, provenance verification, and execution gate for untrusted content";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "arbitraitor";
          version = "0.1.0-unstable";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ rustToolchain pkgs.pkg-config ];
          buildInputs = with pkgs; [
            openssl
            sqlite
          ] ++ lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          buildPhase = ''
            cargo build --release -p arbitraitor-cli
          '';

          installPhase = ''
            mkdir -p $out/bin
            cp target/release/arbitraitor $out/bin/
          '';

          doCheck = false;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            pkg-config
            openssl
            sqlite
            cargo-nextest
            cargo-hakari
          ];
        };
      });
}
