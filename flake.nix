{
  description = "Flake utils demo";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell  {
          packages= [
            (
              import ./pkgs/ebpf/default.nix {
                inherit (pkgs) buildGoModule lib fetchFromGitHub go;
            }
          )];
          nativeBuildInputs = with pkgs; [
           clang-tools
           clang
           llvm
           #bpftools # dump vmlinux.h
          ];
          buildinputs = with pkgs;[
            libbpf
            linuxHeaders
          ];
        };
      }
    );
}
