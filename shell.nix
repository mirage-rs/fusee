{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  name = "rust-shell";
  nativeBuildInputs = with pkgs; [
    rust-analyzer
    python3
    hexyl
    (latest.rustChannels.stable.rust.override { extensions = [ "rust-src" ]; })
  ];
}
