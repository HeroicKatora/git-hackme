Git Hackme is intended for spontaneous collaboration with `mob`.

It will turn a local repository into an collaboration server, allowing login
from your current local network via a public SSH certificate. It intended use
case are maker meetup events where someone's project is worked on by a trusted
group which do not have or need access to the authoritative code repository.

## Quick start

```
cargo install --git https://github.com/HeroicKatora/git-hackme
git-hackme init

# Assuming you're in a git repository:
git hackme start
```

Then spin up a web server such as `python -m http.server` to the indicated path
and see its instructions for joining.

## 

You need:

- Linux
- The `ssh-keygen` utility and `openssh`
- 
