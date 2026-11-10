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
          rgx-search-v2 = {
            file = "rgx-v${version}-v2-linux.tar.gz";
            hash = "sha256-qJXpuqvpaFizl1kZTC4vSYm5WgXDSl8g476jUS3/uoU=";
          };
          rgx-search-avx2 = {
            file = "rgx-v${version}-avx2-linux.tar.gz";
            hash = "sha256-8TMro5zK0rTfMnTFEDZSeY8UydCF56tB6lojIJAopF4=";
          };
          rgx-search-v4 = {
            file = "rgx-v${version}-v4-linux.tar.gz";
            hash = "sha256-y4hynUfCoRddWUBLrimNGwJ7S8AbAdC5e5YRwVDD4lk=";
          };
          rgx-search-znver4 = {
            file = "rgx-v${version}-znver4-linux.tar.gz";
            hash = "sha256-+GjaEICzz9SaspQLpxa7AcPO47iXrLepZQ0GIczSrU4=";
          };
        };
      };

      # The statically linked musl build is a libc variant, not an ISA tier.
      # It does not go through autoPatchelfHook: there is no ELF interpreter
      # to rewrite on a static binary.
      musl = {
        x86_64-linux = {
          rgx-search-musl = {
            file = "rgx-v${version}-x86_64-linux-musl.tar.gz";
            hash = "sha256-cFmvf32S0jRwVba2xdL+NfTdWi5Ms76Xe+ETx0nm2ms=";
          };
        };
      };

      # The package is rgx-search, the name the project already uses on
      # crates.io and the AUR; the binary it installs is rgx.
      #
      # `static` says the archive holds a statically linked executable: there
      # is no ELF interpreter to rewrite, so autoPatchelfHook must not run on
      # it (it would fail looking for one).
      mkRgx =
        pkgs:
        {
          file,
          hash,
          static ? false,
        }:
        pkgs.stdenv.mkDerivation {
          pname = "rgx-search";
          inherit version;

          src = pkgs.fetchurl {
            url = "${base}/${file}";
            inherit hash;
          };

          # The archive holds a prebuilt ELF/Mach-O binary, so on Linux its
          # interpreter and shared-library paths have to be rewritten for the
          # Nix store -- unless it is a static binary, which has neither.
          nativeBuildInputs = pkgs.lib.optional (pkgs.stdenv.hostPlatform.isLinux && !static) pkgs.autoPatchelfHook;
          buildInputs = pkgs.lib.optional (pkgs.stdenv.hostPlatform.isLinux && !static) pkgs.stdenv.cc.cc.lib;

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
          sys = pkgs.stdenv.hostPlatform.system;
          mk = a: mkRgx pkgs a;
          portable = mk assets.${sys};
          tunedHere =
            if builtins.hasAttr sys tuned then
              builtins.mapAttrs (_: a: mk a) tuned.${sys}
            else
              { };
          muslHere =
            if builtins.hasAttr sys musl then
              builtins.mapAttrs (_: a: mk (a // { static = true; })) musl.${sys}
            else
              { };
        in
        {
          rgx-search = portable;
          default = portable;
        }
        // tunedHere
        // muslHere
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
