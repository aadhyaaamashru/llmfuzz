#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
command -v python3 >/dev/null || { echo "python3 not found, install Python 3.9+ first"; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || { echo "Python 3.9+ needed, found $(python3 -V)"; exit 1; }
exec python3 main.py "$@"
