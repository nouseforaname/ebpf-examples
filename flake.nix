{
  description = "Flake utils demo";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell  {
          #clang: error: unsupported option '-fzero-call-used-regs=used-gpr' for target 'bpfel'
          hardeningDisable = [
            "zerocallusedregs"
          ];
          packages = with pkgs; [
            glibc_multi.dev
            libbpf
            (
              import ./pkgs/ebpf/default.nix {
                inherit (pkgs) buildGoModule lib fetchFromGitHub go;
            }
          )];
          nativeBuildInputs = with pkgs; [
           clang-tools
           clang
           llvm
           bpftools # dump vmlinux.h
           #gdb # readin out symbol addresses from binaries
           perf-tools  #uprobe debugging. docs: https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt
          ];
         #buildinputs = with pkgs;[
         #];

        };
      }
    );
}
