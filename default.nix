{
  pkgs ? import (import ./npins).nixpkgs { },
}:

let
  python = pkgs.python312;
  pythonPackages = python.pkgs;

  psptool = pythonPackages.buildPythonPackage rec {
    pname = "psptool";
    version = "3.4";
    pyproject = true;

    src = pythonPackages.fetchPypi {
      inherit pname version;
      hash = "sha256-/XEELA1A8nOsYbVIuRTEehyzcHSy1acn3yDh8Ckr9YM=";
    };

    build-system = with pythonPackages; [
      hatchling
      hatch-vcs
    ];

    dependencies = with pythonPackages; [
      cryptography
      prettytable
    ];

    # psptool has no test suite in the sdist
    doCheck = false;

    meta = with pkgs.lib; {
      description = "AMD PSP firmware parsing and extraction tool";
      homepage = "https://github.com/PSPReverse/PSPTool";
      license = licenses.gpl3Only;
    };
  };

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
