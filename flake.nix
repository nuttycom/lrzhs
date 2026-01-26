{
  description = "A flake for building lrzhs, a set of Haskell bindings for librustzcash";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    crane,
    ...
  }: let
    ## Define local packages, parameterized over the package set.

    lrzhs_ffi = pkgs: let
      craneLib = crane.mkLib pkgs;
    in
      craneLib.buildPackage {
        src = craneLib.cleanCargoSource ./rust/.;

        buildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [
          pkgs.darwin.apple_sdk.frameworks.Security
          pkgs.libiconv
        ];

        doCheck = true;
      };

    lrzhs = lrzhs_ffi: hpkgs:
      hpkgs.callCabal2nix "lrzhs" ./. {
        inherit lrzhs_ffi;
      };
  in {
    overlays = {
      ## The default overlay uses the local packages specialized to `final`.
      default = final: prev: {
        lrzhs_ffi = lrzhs_ffi final;

        haskellPackages =
          prev.haskellPackages.extend (self.overlays.haskell final prev);
      };

      ## The haskell overlay allows users to apply the local packages to any GHC
      ## package set, not just `pkgs.haskellPackages`.
      haskell = final: prev: hfinal: hprev: {
        lrzhs = lrzhs (lrzhs_ffi final) hfinal;
      };
    };
  }
  // flake-utils.lib.eachDefaultSystem(system: let
    pkgs = import nixpkgs { inherit system; };
  in {
    ## The packages output publishes the local packages using the flake inputs.
    packages = {
      default = self.packages.${system}.lrzhs;
      lrzhs = lrzhs (lrzhs_ffi pkgs) pkgs.haskellPackages;
      lrzhs_ffi = lrzhs_ffi pkgs;
    };

    devShells = {
      default = pkgs.mkShell {
        inputsFrom =
          builtins.attrValues self.packages.${system};

        buildInputs = [
          (lrzhs_ffi pkgs)
          pkgs.haskellPackages.haskell-language-server
          pkgs.cabal-install
        ];
      };
    };
  });
}
