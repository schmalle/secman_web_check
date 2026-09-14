"""Package entry point."""

from .cli import app


def main() -> None:
    """Run the command-line client."""
    app()


if __name__ == "__main__":
    main()
