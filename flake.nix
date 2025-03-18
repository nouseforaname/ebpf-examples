{
  description = "rust go ebpf devshell playground";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    #need rust nightly, it's a requirement of aya rs
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

  };

  outputs = { nixpkgs, flake-utils, rust-overlay,... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
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
            rust-bin.beta.latest.default


            #aya rs dev env guide dependency
            cargo-generate
            bpf-linker
          ];
         #buildinputs = with pkgs;[
         #];

        };
      }
    );
}

