Git Hackme is intended for spontaneous collaboration with `mob`.

It will turn a local repository into an collaboration server, allowing login
from your current local network via a public SSH certificate. It intended use
case are maker meetup events where someone's project is worked on by a trusted
group which do not have or need access to the authoritative code repository.

## Known Problems

- [ ] Does not support the Windows target, even for contributors. I have no
  clue how to programmatically write a key with proper permissions and
  configure its use. Maybe just WSL the problem away.
- [ ] The `unshare` command is not yet implement, delete the mnemonic directory
  in the runtime directory as a workaround. (Slightly problematic, does not
  validate against reuse of that mnemonic).

## Quick start for sharing

```
cargo install --git https://github.com/HeroicKatora/git-hackme
git hackme init

# Assuming you're in a git repository:
git hackme start
```

Then spin up a web server such as `python -m http.server` to the indicated path
and see its instructions for joining. Use `init` anytime to regenerate the HTML
index page etc.

## Quick start for contributing

See the web page (`/index.html`) shared by a hosting person. Boils down to
something similar as:

```
# Only once and for updates:
cargo install --git https://github.com/HeroicKatora/git-hackme

git hackme clone "http://andreas@192.168.0.1:8000//flip-fix-blade-fantasy"
```

## Requirements

You need:

- Linux
- The `ssh-keygen` utility and `openssh` in general
- `git` obviously
