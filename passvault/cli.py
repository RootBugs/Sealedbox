"""Command-line interface for passvault.

Password sources, in order of precedence:

1. ``--password`` / ``--new-password`` (demo convenience; prefer env),
2. environment variables ``PASSVAULT_MASTER`` / ``PASSVAULT_NEW`` (and
   ``PASSVAULT_VALUE`` for the secret being stored),
3. an interactive ``getpass`` prompt.

Example::

    python -m passvault init --path demo.pvault
    python -m passvault add  --path demo.pvault --name github --value s3cret
    python -m passvault list --path demo.pvault
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from .vault import (
    DEFAULT_ITERATIONS,
    Vault,
    VaultError,
)

__all__ = ["main", "build_parser"]


def _read_master(args: argparse.Namespace, *, prompt: str = "Master password: ") -> bytes:
    if getattr(args, "password", None):
        return args.password.encode("utf-8")
    env = os.environ.get("PASSVAULT_MASTER")
    if env:
        return env.encode("utf-8")
    return getpass.getpass(prompt).encode("utf-8")


def _read_new_master(args: argparse.Namespace) -> bytes:
    if getattr(args, "new_password", None):
        return args.new_password.encode("utf-8")
    env = os.environ.get("PASSVAULT_NEW")
    if env:
        return env.encode("utf-8")
    return getpass.getpass("New master password: ").encode("utf-8")


def _read_value(args: argparse.Namespace) -> str:
    if getattr(args, "value", None) is not None:
        return args.value
    env = os.environ.get("PASSVAULT_VALUE")
    if env is not None:
        return env
    return getpass.getpass("Secret value: ")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--path",
        default="vault.pvault",
        help="vault file path (default: vault.pvault)",
    )
    common.add_argument(
        "--password",
        default=None,
        help="master password (demo only; prefer PASSVAULT_MASTER)",
    )
    parser = argparse.ArgumentParser(
        prog="passvault",
        description="Encrypted password vault (PBKDF2 + HMAC stream cipher).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser(
        "init", parents=[common], help="create a new empty vault"
    )
    p_init.add_argument("--force", action="store_true", help="overwrite an existing file")
    p_init.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"PBKDF2 iterations (default {DEFAULT_ITERATIONS})",
    )

    p_add = sub.add_parser("add", parents=[common], help="add or overwrite an entry")
    p_add.add_argument("--name", required=True)
    p_add.add_argument("--username", default="")
    p_add.add_argument("--notes", default="")
    p_add.add_argument("--value", default=None, help="secret value (or PASSVAULT_VALUE)")
    p_add.add_argument("--overwrite", action="store_true")

    p_get = sub.add_parser("get", parents=[common], help="print one entry")
    p_get.add_argument("--name", required=True)

    sub.add_parser("list", parents=[common], help="list entry names")

    p_rm = sub.add_parser("remove", parents=[common], help="delete an entry")
    p_rm.add_argument("--name", required=True)

    p_pw = sub.add_parser("passwd", parents=[common], help="change the master password")
    p_pw.add_argument("--new-password", default=None, help="demo only; prefer PASSVAULT_NEW")
    p_pw.add_argument(
        "--iterations",
        type=int,
        default=None,
        help="new PBKDF2 iteration count (default: keep current)",
    )
    return parser


def _cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"error: {path} already exists (use --force)", file=sys.stderr)
        return 1
    password = _read_master(args)
    vault = Vault.create(password, iterations=args.iterations)
    vault.save(path)
    print(f"created {path} (0 entries, {args.iterations} PBKDF2 iterations)")
    return 0


def _cmd_add(args: argparse.Namespace) -> int:
    vault = Vault.load(args.path, _read_master(args))
    value = _read_value(args)
    vault.add(
        args.name,
        value,
        username=args.username,
        notes=args.notes,
        overwrite=args.overwrite,
    )
    vault.save(args.path)
    print(f"stored entry {args.name!r} in {args.path}")
    return 0


def _cmd_get(args: argparse.Namespace) -> int:
    vault = Vault.load(args.path, _read_master(args))
    entry = vault.get(args.name)
    print(f"name:     {args.name}")
    if entry.get("username"):
        print(f"username: {entry['username']}")
    print(f"value:    {entry['password']}")
    if entry.get("notes"):
        print(f"notes:    {entry['notes']}")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    vault = Vault.load(args.path, _read_master(args))
    names = vault.list_names()
    if not names:
        print("(vault is empty)")
        return 0
    for name in names:
        entry = vault.get(name)
        user = entry.get("username") or "-"
        print(f"{name:<24} {user}")
    print(f"{len(names)} entr{'y' if len(names) == 1 else 'ies'}")
    return 0


def _cmd_remove(args: argparse.Namespace) -> int:
    vault = Vault.load(args.path, _read_master(args))
    vault.delete(args.name)
    vault.save(args.path)
    print(f"removed entry {args.name!r}")
    return 0


def _cmd_passwd(args: argparse.Namespace) -> int:
    vault = Vault.load(args.path, _read_master(args))
    vault.change_password(_read_new_master(args), iterations=args.iterations)
    vault.save(args.path)
    print(f"re-keyed {args.path} ({len(vault)} entries preserved)")
    return 0


_COMMANDS = {
    "init": _cmd_init,
    "add": _cmd_add,
    "get": _cmd_get,
    "list": _cmd_list,
    "remove": _cmd_remove,
    "passwd": _cmd_passwd,
}


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; returns a process exit code (never raises VaultError)."""
    args = build_parser().parse_args(argv)
    try:
        return _COMMANDS[args.command](args)
    except VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
