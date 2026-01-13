import sys
import click
from fullmute.cli.commands import cli

def entrypoint():
    if len(sys.argv) == 1:
        sys.argv.append('--help')

    try:
        cli()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    entrypoint()
