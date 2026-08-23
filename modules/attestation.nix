{ config, lib, pkgs, ... }:

let
  cfg = config.my.attestation;

  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    optionalString
    concatStringsSep;

  # Fixed projection
  projectedConfig = {
    attestation = {
      enable = cfg.enable;
      deviceId = cfg.deviceId;
      publicKeyFile = toString cfg.publicKeyFile;
      endpoint = cfg.endpoint;
      projectionVersion = 1;
    };

    services = {
      openssh = {
        enable = config.services.openssh.enable or false;
        passwordAuthentication =
          config.services.openssh.settings.PasswordAuthentication or true;
        permitRootLogin =
          config.services.openssh.settings.PermitRootLogin or "yes";
      };
    };

    networking = {
      firewall = {
        enable = config.networking.firewall.enable or false;
        allowedTCPPorts = config.networking.firewall.allowedTCPPorts or [ ];
      };
    };
  };

  # Deterministic rendering
  render =
    value:
      if builtins.isAttrs value then
        let
          names = builtins.sort builtins.lessThan (builtins.attrNames value);
        in
          "{${concatStringsSep "," (map (n: "${n}=${render value.${n}}") names)}}"
      else if builtins.isList value then
        "[${concatStringsSep "," (map render value)}]"
      else
        builtins.toJSON value;

  canonicalProjectedConfig = render projectedConfig;
  candidateRoot = builtins.hashString "sha256" canonicalProjectedConfig;

  projectedConfigFile =
    builtins.toFile "attested-projected-config.json"
      (builtins.toJSON projectedConfig);

  candidateRootFile =
    builtins.toFile "candidate-root.txt" "${candidateRoot}\n";

  verifyDrv = pkgs.runCommand "verify-attestation" {
    nativeBuildInputs = [
      pkgs.python3
      pkgs.python3Packages.pynacl
    ];

    verifier = ../scripts/verify_attestation.py;

    attestationFile = cfg.attestationFile;
    publicKeyFile = cfg.publicKeyFile;
    trustedCurrentRootFile = cfg.trustedCurrentRootFile;
    inherit projectedConfigFile candidateRootFile;
    deviceId = cfg.deviceId;
  } ''
    set -euo pipefail

    # Fail if required files are missing.
    test -f "$attestationFile"
    test -f "$publicKeyFile"
    test -f "$trustedCurrentRootFile"

    python "$verifier" \
      --attestation "$attestationFile" \
      --public-key "$publicKeyFile" \
      --trusted-current-root "$trustedCurrentRootFile" \
      --candidate-root "$candidateRootFile" \
      --projected-config "$projectedConfigFile" \
      --device-id "$deviceId"

    mkdir -p "$out"
    cp "$candidateRootFile" "$out/next-root"
    cp "$projectedConfigFile" "$out/projected-config.json"
  '';

in
{
  options.my.attestation = {
    enable = mkEnableOption "generation attestation enforcement";

    deviceId = mkOption {
      type = types.str;
      example = "device-01";
    };

    endpoint = mkOption {
      type = types.str;
      default = "";
      example = "https://attest.example.com";
      description = "Used by the wrapper script; included in attested projection.";
    };

    publicKeyFile = mkOption {
      type = types.path;
      example = "/etc/nixos/attestation/server.pub";
    };

    attestationFile = mkOption {
      type = types.path;
      default = "/var/lib/attestation/attestation.json";
    };

    trustedCurrentRootFile = mkOption {
      type = types.path;
      default = "/var/lib/attestation/current-root";
    };
  };

  config = mkIf cfg.enable {

    # Force rebuild to verify the attestation
    system.extraDependencies = [ verifyDrv ];

    systemd.tmpfiles.rules = [
      "d /var/lib/attestation 0755 root root - -"
    ];

    environment.etc."attestation/next-root".source = "${verifyDrv}/next-root";

    environment.etc."attestation/projected-config.json".source =
      "${verifyDrv}/projected-config.json";

    system.activationScripts.attestationAdvanceTrustedRoot.text = ''
      set -eu

      state_dir=/var/lib/attestation
      next_root_file=/etc/attestation/next-root
      trusted_root_file=${lib.escapeShellArg (toString cfg.trustedCurrentRootFile)}

      mkdir -p "$state_dir"

      if [ ! -f "$next_root_file" ]; then
        echo "attestation: missing next root file: $next_root_file" >&2
        exit 1
      fi

      tmp="$(mktemp "$state_dir/current-root.tmp.XXXXXX")"
      cp "$next_root_file" "$tmp"
      chmod 0644 "$tmp"
      mv "$tmp" "$trusted_root_file"
    '';

    assertions = [
      {
        assertion = cfg.deviceId != "";
        message = "my.attestation.deviceId must be set";
      }
      {
        assertion = cfg.endpoint != "";
        message = "my.attestation.endpoint must be set";
      }
    ];
  };
}
