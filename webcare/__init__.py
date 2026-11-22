"""supabase-web-care: read-only checks for Supabase and Postgres-backed sites."""

__version__ = "1.20.0"

# The pgrls release this toolkit was reviewed and tested against. The wheel on
# PyPI for this version was compared file-by-file with the upstream v0.57.1
# tag before it was pinned here.
PINNED_PGRLS_VERSION = "0.57.1"


def sql_dir():
    """The folder that holds the toolkit's SQL files.

    In a checkout it is `sql/` beside this package; an installed copy carries the
    same files inside the package as `webcare/sql_files/`.
    """
    from pathlib import Path

    here = Path(__file__).resolve().parent
    checkout = here.parent / "sql"
    return checkout if (checkout / "extra-checks.sql").is_file() else here / "sql_files"
