{
rustPlatform,
version,
fetchFromGitHub,
cargo,
cacert,
}:
  rustPlatform.buildRustPackage {
    pname="aya-tool";
    version = version;
    src = fetchFromGitHub {
      owner = "aya-rs";
      repo = "aya";
      rev = "aya-v${version}";
      #hash = pkgs.lib.fakeHash;
      hash = "sha256-4yIP52o8lo2DpOtYGLuOhFmnascQDbOkL8GQyoN68UU=";

      nativeBuildInputs = [
        cargo cacert
      ];
      postFetch = ''
        pushd $out
          cargo generate-lockfile --manifest-path ./Cargo.toml
        popd
      '';
    };

    doCheck = false;
    useFetchCargoVendor = true;
    cargoHash = "sha256-HAiwtvB5oBqAQm4ekfiNwCrKyQ0fVZhD1E/ULcLED2Y=";
  }
