{
  description = "rust go ebpf devshell playground";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    #need rust nightly, it's a requirement of aya rs
  };

  outputs = { nixpkgs, flake-utils,... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        aya-tool = import ./pkgs/aya/default.nix { inherit (pkgs) fetchFromGitHub cargo cacert rustPlatform; version = "0.13.1"; };
        ebpf-go = import ./pkgs/ebpf/default.nix {
             inherit (pkgs) buildGoModule lib fetchFromGitHub go;
        };
      in
      {
        devShells.default = pkgs.mkShell  {
          #clang: error: unsupported option '-fzero-call-used-regs=used-gpr' for target 'bpfel'
          hardeningDisable = [
            "zerocallusedregs"
          ];

          packages = with pkgs; [
            aya-tool
            ebpf-go
            bpf-linker
            glibc_multi.dev
            libbpf
            cargo-generate
          ];
          nativeBuildInputs = with pkgs; [
            clang-tools
            clang
            llvm
            bpftools # dump vmlinux.h
            #gdb # readin out symbol addresses from binaries
            perf-tools  #uprobe debugging. docs: https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt


            rustup # the build scripts in aya rs will call `cargo +nightly` which is a rustup feature, not cargo itself.

            bpftrace #this can be used to find information about the structs that the bpf programs function is called with.

            rust-bindgen #aya rs dev env guide dependency
            cargo-generate
            bpf-linker # dependency of aya tool generate rust bindings https://aya-rs.dev/book/aya/aya-tool/
          ];

        };
      }
    );
}

