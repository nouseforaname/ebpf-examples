{
  lib,
  buildGoModule,
  fetchFromGitHub,
  go,
}:
buildGoModule rec {
  inherit go;
  pname = "ebpf";
  version = "0.17.3";
  src = fetchFromGitHub {
    owner = "cilium";
    repo = "ebpf";
    rev = "v${version}";
    hash = "sha256-UVZjDa6sIsRL1i4II69CyqoAObfZfKsOXDE7UeALoHk=";
  };
  modRoot = ".";
  date = "2025-03-11T13:26:01Z";

  vendorHash = "sha256-xLooIXAS8Qpa/6NLij3cand+0Vg8YJzB614u8c0+9BY=";

  ldflags = [
  ];

  doCheck = false;

  # Only build gopls, and not the integration tests or documentation generator.
  subPackages = [ "cmd/bpf2go" ];

  meta = with lib; {
    description = "ebpf-go is a pure-Go library to read, modify and load eBPF programs and attach them to various hooks in the Linux kernel.";
    homepage = "https://github.com/cilium/ebpf";
    changelog = "https://github.com/cilium/ebpf/releases/tag/v${src.version}";
    license = licenses.mit;
    maintainers = with maintainers; [
      nouseforaname
    ];
    mainProgram = "ebpf2go";
  };
}
