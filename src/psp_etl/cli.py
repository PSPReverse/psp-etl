"""CLI entry point for psp-etl."""

import click


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """PSP-ETL: AMD PSP Firmware Extraction, Transformation & Loading Pipeline."""


if __name__ == "__main__":
    cli()
