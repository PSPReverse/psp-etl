{ pkgs ? import (import ./npins).nixpkgs {} }:

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

    src = pkgs.lib.cleanSource ./.;

    build-system = with pythonPackages; [
      setuptools
      setuptools-scm
    ];

    dependencies = with pythonPackages; [
      psptool
      click
      httpx
      beautifulsoup4
      rich
    ];

    doCheck = false;  # TODO: enable once tests exist

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
    ];
  };
}
