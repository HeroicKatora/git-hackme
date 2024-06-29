Documentation on operating a server.

The server makes modifications to your computer in the following ways:

- A user-specific runtime directory (or a temporary directory on OS X) is
  created. This directory contains HTML data which should be hosted as a web
  page. It can be regenerated with `git hackme init`. The structure is
  - One directory for each shared project named after the mnemonic
    - Each with a `key`, `key-cert.pub`, `key.pub`.
    - And `project.json` with information on the project itself.
  - One directory `.ssh-join` to simulated joining
  - An `index.html` and `style.css` that should be hosted
- The configuration folder, e.g. `.config/git-hackme/git-hackme`
  - A central configuration file `config.json`
  - The Certificate Authority files for sharing `ca`, `ca.pub`

## The share command

Running `git hackme share` on a folder:
- Searches the runtime directory for any existing share of this project.
  - Ensures the mnemonic folder gets a copy of the key files private and
    public, and its signature
  - Creates and signs a new key otherwise

