import sys
import click
from fullmute.cli.commands import cli

def print_ascii_art():
    ascii_art = r"""
 _____ _     _     _     _      _    _____ _____
/    // \ /\/ \   / \   / \__/|/ \ /Y__ __Y  __/
|  __\| | ||| |   | |   | |\/||| | || / \ |  \  
| |   | \_/|| |_/\| |_/\| |  ||| \_/| | | |  /_ 
\_/   \____/\____/\____/\_/  \|\____/ \_/ \____\
    """
    print(ascii_art)
    print("FullMute - Advanced Web Scanner\n")

def entrypoint():
    if len(sys.argv) == 1:
        print_ascii_art()
        sys.argv.append('--help')

    try:
        if len(sys.argv) > 1 and sys.argv[1] not in ['--help', '-h', 'help']:
            print_ascii_art()
        cli()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    entrypoint()
