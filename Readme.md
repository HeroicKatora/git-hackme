Git Hackme is intended for spontaneous collaboration with `mob`¹.

It will turn a local repository into an collaboration server, allowing login
from your current local network via a public SSH certificate. It intended use
case are maker meetup events where someone's project is worked on by a trusted
group which do not have or need access to the authoritative code repository.

## Quick start for contributing

See the web page shared by a hosting person. Boils down to something similar
to the commands:

```
# Only once and for updates:
cargo install git-hackme@1.0.0-beta.8

# Adjust as listed on the hosting person's web page:
git hackme clone "http://aurelia@192.168.0.1:8000/flip-fix-blade-fantasy"
```

## Quick start for sharing

```
# Only once and for updates:
cargo install git-hackme@1.0.0-beta.8
git hackme init

# Then, assuming you're in a git repository:
git hackme share
```

Then spin up a web server such as `python -m http.server` to the indicated path
and see its instructions for joining. Use `init` anytime to regenerate the HTML
index page etc.

¹Note that the `mob` program creates a temporary branch, derived from the main
branch of which it is created. This effectively mitigates an issue with sharing
a local repository, which is that one can not pushed to a branch checked-out in
a non-bare git remote. One simply has to ensure that `mob stop` is ran by the
hosting person.

## Known and Fixed Problems (beta.8)

- [ ] Sharing an existing project does not *always* update the mnemonic folder.
  This is an optimization but might cause the key file to be out-of-date or its
  signature to be invalid. We should somehow validate freshness.

- [x] The share command should check if SSH is running and reachable, not only
  an HTTP server. This can detect if the CA is changed or the sshd daemon down.

- [x] The original repository name could be used as the target directory name,
  avoid confusion when looking through previous repositories.

- [x] The index page should copy repository ~~descriptions and~~ names.

- [x] The index page should get better UX optimized for sharing. The color
  scheme should remain readable when text is selected since this is the most
  basic workflow. There should be a 'Copy' button.

- [x] The shell doesn't diagnose a missing directory. If the remote deletes or
  unshares the repository it should nudge you towards the `reset` command.

- [x] Does not support OS-X.

- [x] The `unshare` command is not yet implement, delete the mnemonic directory
  in the runtime directory as a workaround. (Slightly problematic, does not
  validate against reuse of that mnemonic).

## Unsupported Problems (please contribute)

- [ ] Does not support the Windows target, even for contributors. I have no
  clue how to programmatically write a key with proper permissions and
  configure its use. Maybe just WSL the problem away.

## Requirements

You need:

- Linux or OS X
- `openssh` and `ssh-keygen`
- `git`
