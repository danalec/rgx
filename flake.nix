{
  description = "rgx — full-text search inside PDFs, Office documents, archives, 3D models, LLM checkpoints, databases and e-mail";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      version = "0.1.10";
      base = "https://github.com/danalec/rgx/releases/download/rgx-v${version}";

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      # One release asset per platform. The digests are the SHA-256 of the
      # archive itself, in SRI form, as published on the release.
      assets = {
        x86_64-linux = {
          file = "rgx-v${version}-x86_64-linux-gnu.tar.gz";
          hash = "sha256-pHFTAVrmE2+zG0zVdCTYQyOq1lXZOmHIOIIKUGLrzTg=";
        };
        aarch64-linux = {
          file = "rgx-v${version}-aarch64-linux.tar.gz";
          hash = "sha256-avL/6Sp7Umpatnn94nHwiR6S701etxxk0BXQKVaOAFM=";
        };
        x86_64-darwin = {
          file = "rgx-v${version}-x86_64-macos.tar.gz";
          hash = "sha256-lZZtLOmRHAS8AWW3S7NZOykIYs1wF6kdgngfgkxAu8E=";
        };
        aarch64-darwin = {
          file = "rgx-v${version}-aarch64-macos.tar.gz";
          hash = "sha256-FEhOLtSN0CQ0ob0r+IL5UEW2wZqUdjxf9rxhp1OAewk=";
        };
      };

      # Instruction-set tuned builds. They are not the default: the portable
      # build already selects its kernels at runtime, and these raise the
      # compiler's baseline for CPUs that have the features.
      tuned = {
        x86_64-linux = {
          rgx-search-avx2 = {
            file = "rgx-v${version}-avx2-linux.tar.gz";
            hash = "sha256-8TMro5zK0rTfMnTFEDZSeY8UydCF56tB6lojIJAopF4=";
          };
          rgx-search-znver4 = {
            file = "rgx-v${version}-znver4-linux.tar.gz";
            hash = "sha256-+GjaEICzz9SaspQLpxa7AcPO47iXrLepZQ0GIczSrU4=";
          };
        };
      };

      # The package is rgx-search, the name the project already uses on
      # crates.io and the AUR; the binary it installs is rgx.
      mkRgx =
        pkgs: file: hash:
        pkgs.stdenv.mkDerivation {
          pname = "rgx-search";
          inherit version;

          src = pkgs.fetchurl {
            url = "${base}/${file}";
            inherit hash;
          };

          # The archive holds a prebuilt ELF/Mach-O binary, so on Linux its
          # interpreter and shared-library paths have to be rewritten for the
          # Nix store.
          nativeBuildInputs = pkgs.lib.optional pkgs.stdenv.hostPlatform.isLinux pkgs.autoPatchelfHook;
          buildInputs = pkgs.lib.optional pkgs.stdenv.hostPlatform.isLinux pkgs.stdenv.cc.cc.lib;

          sourceRoot = ".";
          dontBuild = true;
          dontFixup = pkgs.stdenv.hostPlatform.isDarwin;

          installPhase = ''
            runHook preInstall
            mkdir -p "$out/bin" "$out/share/doc/rgx" "$out/share/licenses/rgx"
            (
              cd */
              install -m755 rgx "$out/bin/rgx"
              for f in README.md MANUAL.md COPYING NOTICE LICENSE-APACHE; do
                if [ -f "$f" ]; then
                  install -m644 "$f" "$out/share/doc/rgx/$f"
                fi
              done
              for f in COPYING NOTICE LICENSE-APACHE; do
                if [ -f "$f" ]; then
                  install -m644 "$f" "$out/share/licenses/rgx/$f"
                fi
              done
            )
            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "Search inside PDFs, Office documents, archives, 3D models, LLM checkpoints, databases and e-mail";
            longDescription = ''
              rgx is a line-oriented search tool that reads inside files: PDFs,
              Office documents, archives, 3D models, LLM checkpoints, databases,
              e-mail and media metadata. It keeps ripgrep's interface — the same
              flags and the same 0/1/2 exit codes — so it drops into an rg
              workflow unchanged. Every adapter runs in the search process: a
              byte slice in, searchable text out, with no subprocess per file.

              This package installs the binary published on the upstream
              release; the source lives at the homepage.
            '';
            homepage = "https://github.com/danalec/rgx";
            changelog = "https://github.com/danalec/rgx/releases/tag/rgx-v${version}";
            license = licenses.asl20;
            mainProgram = "rgx";
            sourceProvenance = [ sourceTypes.binaryNativeCode ];
            platforms = platforms.unix;
          };
        };

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          mk = a: mkRgx pkgs a.file a.hash;
          portable = mk assets.${pkgs.stdenv.hostPlatform.system};
          tunedHere =
            if builtins.hasAttr pkgs.stdenv.hostPlatform.system tuned then
              builtins.mapAttrs (_: a: mkRgx pkgs a.file a.hash) tuned.${pkgs.stdenv.hostPlatform.system}
            else
              { };
        in
        {
          rgx-search = portable;
          default = portable;
        }
        // tunedHere
      );

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/rgx";
          meta.description = "Search inside PDFs, Office documents, archives, 3D models, LLM checkpoints, databases and e-mail";
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            rust-analyzer
            clippy
            cargo-nextest
            mold
            pkg-config
          ];
        };
      });

      checks = forAllSystems (
        pkgs:
        let
          rgx = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        in
        {
          smoke = pkgs.runCommand "rgx-smoke" { nativeBuildInputs = [ rgx ]; } ''
            export HOME=$TMPDIR
            rgx --version
            printf 'hello from nix\n' > "$TMPDIR/sample.txt"
            rgx nix "$TMPDIR/sample.txt" | grep -q 'hello from nix'
            touch "$out"
          '';
        }
      );
    };
}
