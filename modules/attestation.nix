{ config, lib, pkgs, ... }:

let
  cfg = config.my.attestation;

  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types;

  projectedConfig = {
    attestation = {
      enable = cfg.enable;
      deviceId = cfg.deviceId;
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

  projectedConfigJsonFile =
    builtins.toFile "projected-config.json" (builtins.toJSON projectedConfig);

  verifier = pkgs.writeShellScriptBin "attestation-verify-switch" ''
    set -euo pipefail

    ${pkgs.python3.withPackages (pack: [ pack.pynacl ])}/bin/python \
      ${../scripts/verify_attestation_poc.py} \
      --attestation ${lib.escapeShellArg cfg.attestationFile} \
      --public-key ${lib.escapeShellArg cfg.publicKeyFile} \
      --device-id ${lib.escapeShellArg cfg.deviceId} \
      --projected-config ${projectedConfigJsonFile}
  '';
in
{
  options.my.attestation = {
    enable = mkEnableOption "PoC config attestation verification";

    deviceId = mkOption {
      type = types.str;
      example = "device-01";
    };

    publicKeyFile = mkOption {
      type = types.str;
      default = "/var/lib/attestation/server.pub";
    };

    attestationFile = mkOption {
      type = types.str;
      default = "/var/lib/attestation/attestation.json";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.deviceId != "";
        message = "my.attestation.deviceId must be set";
      }
    ];

    systemd.tmpfiles.rules = [
      "d /var/lib/attestation 0755 root root - -"
    ];

    environment.etc."attestation/projected-config.json".source = projectedConfigJsonFile;

    system.activationScripts.verifyAttestation.text = ''
      echo "Verifying config attestation..."
      ${verifier}/bin/attestation-verify-switch
    '';
  };
}
