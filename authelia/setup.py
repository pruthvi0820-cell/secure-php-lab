"""One-time setup for Authelia: creates the secret files and your user account file.

Run from the project folder:   python authelia/setup.py

It never overwrites existing files, and both outputs are in .gitignore so they cannot reach GitHub.
"""

import re
import secrets
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SECRETS = HERE / "secrets"
USERS = HERE / "users_database.yml"
SECRET_NAMES = ("session_secret", "storage_encryption_key", "jwt_secret")
HASH_COMMAND = "docker run --rm -it authelia/authelia:4.39.28 authelia crypto hash generate argon2"


def clear_docker_placeholder(path: Path) -> None:
    """If `docker compose up` ran before this script, Docker created an empty FOLDER where a file belongs."""
    if path.is_dir():
        if any(path.iterdir()):
            sys.exit(f"{path} is a folder with files in it. Move it away and run this script again.")
        shutil.rmtree(path)


def make_secrets() -> None:
    SECRETS.mkdir(exist_ok=True)
    for name in SECRET_NAMES:
        path = SECRETS / name
        clear_docker_placeholder(path)
        if path.exists():
            print(f"  kept     authelia/secrets/{name} (already exists)")
            continue
        path.write_text(secrets.token_hex(32))          # 64 random hex characters
        print(f"  created  authelia/secrets/{name}")


def ask(prompt: str, pattern: str, hint: str) -> str:
    while True:
        value = input(prompt).strip()
        if re.fullmatch(pattern, value):
            return value
        print(f"    {hint}")


def yaml_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def make_users() -> None:
    clear_docker_placeholder(USERS)
    if USERS.exists():
        print("  kept     authelia/users_database.yml (already exists; delete it to start over)")
        return
    print("\nYour gateway account (this is separate from the PHP app's admin account).")
    username = ask("  Username (lowercase, e.g. pruthvi): ", r"[a-z0-9_.-]{2,32}", "2-32 lowercase letters, digits, . _ -")
    name = ask("  Display name (e.g. Pruthvi DR): ", r"[^\n'\"]{1,60}", "1-60 characters, no quotes")
    email = ask("  Email (only used for the lab's file notifier): ", r"[^@\s]+@[^@\s]+\.[^@\s]+", "a valid email")
    print("\n  Now create your password hash. In ANOTHER Command Prompt run:\n")
    print(f"    {HASH_COMMAND}\n")
    print("  Type your new gateway password twice (nothing shows while typing), then copy the line")
    print("  that starts with  $argon2id$  (everything after 'Digest: ').\n")
    digest = ask("  Paste the digest here: ", r"\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+",
                 "that is not an argon2id digest; copy the whole value starting with $argon2id$")
    USERS.write_text(
        "# Created by authelia/setup.py. Contains a password hash: never commit this file.\n"
        "users:\n"
        f"  {username}:\n"
        "    disabled: false\n"
        f"    displayname: {yaml_quote(name)}\n"
        f"    password: {yaml_quote(digest)}\n"
        f"    email: {yaml_quote(email)}\n"
        "    groups:\n"
        "      - 'admins'\n",
        encoding="utf-8",
    )
    print("  created  authelia/users_database.yml")


def main() -> None:
    print("Authelia setup\n")
    make_secrets()
    make_users()
    print("\nDone. Next: docker compose up")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        sys.exit("\nCancelled. Nothing else was changed.")
