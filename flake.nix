{
  description = "Lazynmap Nix Flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        lazynmapPkg = pkgs.rustPlatform.buildRustPackage {
          pname = "lazynmap";
          version = "0.1.1";

          src = ./.;

          cargoHash = "sha256-W9f3/jcd8WLWzf4d2QTYWuwdgCobtohKoK3bLvtuvQE=";
        };
      in
      {
        devShell = pkgs.mkShell {
          packages = [
            pkgs.rust-bin.stable.latest.default
          ];
        };

        packages.default = lazynmapPkg;

        apps.default = {
          type = "app";
          program = "${lazynmapPkg}/bin/lazynmap";
        };
      }
    );
}
