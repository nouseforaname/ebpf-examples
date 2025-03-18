{
  description = "Flake utils demo";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell  {
          packages = with pkgs; [

          ];
          nativeBuildInputs = with pkgs; [
            clang-tools
            clang
            llvm

          ];
          buildinputs = with pkgs;[
            libbpf
            linuxHeaders
          ];
        };
      }
    );
}
