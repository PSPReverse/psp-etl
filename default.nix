{
  pkgs ? import (import ./npins).nixpkgs { },
}:

let
  python = pkgs.python312;
  pythonPackages = python.pkgs;

  psptoolRs = import (pkgs.fetchFromGitHub {
    owner = "vringar";
    repo = "psptool-rs";
    rev = "3df62fe878937007c76064db4934e3875ea1bb78";
    hash = "sha256-yPnjx7lLcq4f73VezBUutXzzVWHgSFFsZcxLNo4Je10=";
  });

  # Drop-in Rust replacement exposing `import psptool`.
  psptool = psptoolRs.pythonFor pythonPackages;

  psp-etl = pythonPackages.buildPythonPackage {
    pname = "psp-etl";
    version = "0.1.0";
    pyproject = true;

    src = pkgs.nix-gitignore.gitignoreSource [] ./.;

    build-system = with pythonPackages; [
      setuptools
    ];

    dependencies = with pythonPackages; [
      psptool
      click
      httpx
      beautifulsoup4
      rich
    ];

    doCheck = true;

    meta = with pkgs.lib; {
      description = "AMD PSP Firmware Extraction, Transformation & Loading Pipeline";
      license = licenses.gpl3Only;
    };
  };

in
{
  inherit psp-etl;

  shell = pkgs.mkShell {
    inputsFrom = [ psp-etl ];
    packages = with pkgs; [
      python
      uv
      ruff
      npins
      actionlint
    ];
    shellHook = ''
      if [ -e "$PWD/result/bin/psp-etl" ]; then
        export PATH="$PWD/result/bin:$PATH"
      fi
    '';
  };
}
