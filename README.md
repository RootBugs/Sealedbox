# passvault

An encrypted password vault with a file format small enough to audit in
one sitting — PBKDF2 stretching, an HMAC-SHA256 stream cipher, and
encrypt-then-MAC integrity, all from the Python standard library.

## Why it's special

- **Fail-closed by construction.** Every wrong password and every
  tampered byte (ciphertext, tag, *or* header) raises
  `AuthenticationError` — never garbage plaintext, never a silent
  partial read.
- **Tamper checks can't burn CPU.** The MAC key is derived independently
  of the attacker-controlled header, so the integrity tag is verified
  *before* the stored PBKDF2 iteration count is honoured. Flipping one
  header byte fails instantly instead of stalling the loader for
  millions of PBKDF2 rounds (a real bug this project's tests caught
  during development). A runaway iteration count in an authenticated
  header is still bounded by `MAX_ITERATIONS`.
- **Deterministic when you need it to be.** Salt, nonce, iteration count
  and the wall clock are all injectable, so tests (and forensic
  re-encryption) can reproduce byte-identical vaults.
- **Atomic persistence.** `save()` writes a temp file and `os.replace`s
  it into place, so a crash mid-write never truncates the vault.

## Architecture

```
passvault/
  crypto.py    PBKDF2 key derivation, HMAC counter-mode keystream, HMAC tag
  vault.py     file format (48-byte header | ciphertext | 32-byte tag),
               entry store, create/load/save/add/get/delete/re-key
  cli.py       init | add | get | list | remove | passwd
  __main__.py  python -m passvault
```

File layout (big-endian):

| offset | size | field                          |
|-------:|-----:|--------------------------------|
| 0      | 8    | magic `PASSVLT1`               |
| 8      | 4    | PBKDF2 iterations (uint32)     |
| 12     | 16   | salt                           |
| 28     | 16   | nonce                          |
| 44     | 4    | ciphertext length (uint32)     |
| 48     | n    | ciphertext (keystream XOR)     |
| 48+n   | 32   | HMAC-SHA256 tag                |

The tag covers `header || ciphertext`. The plaintext is compact JSON:
`{"entries": {...}, "format": "passvault/1"}`.

## Runnable example

```console
PS> $env:PASSVAULT_MASTER = 'correct horse battery staple'
PS> python -m passvault init --path demo.pvault --iterations 10000
created demo.pvault (0 entries, 10000 PBKDF2 iterations)
PS> python -m passvault add --path demo.pvault --name github --value 'hunter2' --username alice
stored entry 'github' in demo.pvault
PS> python -m passvault add --path demo.pvault --name email --value 'pa55word' --notes 'work'
stored entry 'email' in demo.pvault
PS> python -m passvault list --path demo.pvault
email                    -
github                   alice
2 entries
PS> python -m passvault get --path demo.pvault --name github
name:     github
username: alice
value:    hunter2
PS> python -m passvault remove --path demo.pvault --name email
removed entry 'email'
PS> python -m passvault list --path demo.pvault
github                   alice
1 entry
```

A wrong master password fails cleanly:

```console
PS> $env:PASSVAULT_MASTER = 'wrong'
PS> python -m passvault list --path demo.pvault
error: wrong master password or tampered vault
```

## Tests

```console
PS> python -m unittest discover -s tests -v
```

33 tests cover roundtrips, tamper/attack detection (ciphertext, tag,
header, truncation, bad magic), deterministic byte output, re-keying,
leak checks, entry semantics and the CLI end to end.
