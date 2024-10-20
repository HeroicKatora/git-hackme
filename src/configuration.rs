use base64::{engine::general_purpose::STANDARD_NO_PAD as B64_STANDARD, Engine as _};
use bip39_lexical_data::WL_BIP39;
use directories::{ProjectDirs, UserDirs};

use std::{
    fs,
    io::Error,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use crate::{
    cli::{Cli, GitShellWrapper, LocalInterface},
    template::Templates,
};

pub struct Configuration {
    pub base: ProjectDirs,
    pub user: Option<UserDirs>,
    options: OnceLock<Options>,
    username: OnceLock<String>,
    tempdir: OnceLock<Result<RuntimeDirectory, Error>>,
}

enum RuntimeDirectory {
    AppDir(PathBuf),
    Tempdir(PathBuf),
}

#[derive(serde::Deserialize)]
pub struct Options {
    /// The `ssh-keygen` program or wrapper to invoke.
    #[serde(default = "Options::default_keygen")]
    pub ssh_keygen: Vec<PathBuf>,
    pub isolate: Option<Isolate>,
}

#[derive(serde::Deserialize)]
pub enum Isolate {
    #[serde(rename = "systemd-run")]
    SystemdRun,
}

pub struct IdentityFile {
    pub config_folder: PathBuf,
    pub path: PathBuf,
}

pub struct CertificateAuthority {
    pub path: PathBuf,
    /// The public data, as a single base64 string without spaces.
    pub pub_b64: String,
    pub keytype: CertificateAuthorityType,
}

pub enum CertificateAuthorityType {
    Ed25519,
}

pub struct SignedEphemeralKey {
    /// Path to the private key, as specified in the ssh-keygen command.
    pub path: PathBuf,
    /// The key mnemonic for the one generated.
    pub mnemonic: String,
}

static SINGLETON: OnceLock<Configuration> = OnceLock::new();

impl Configuration {
    pub fn get() -> Result<&'static Self, Error> {
        let base = ProjectDirs::from("com.github", "HeroicKatora", env!("CARGO_PKG_NAME")).unwrap();

        Ok(SINGLETON.get_or_init(|| Configuration {
            base,
            user: UserDirs::new(),
            options: OnceLock::new(),
            username: OnceLock::new(),
            tempdir: OnceLock::new(),
        }))
    }

    pub fn options(&self) -> Result<&Options, Error> {
        if let Some(opt) = self.options.get() {
            return Ok(opt);
        }

        let file = self.base.config_dir().join("config.json");

        if !file.try_exists()? {
            return Ok(self.options.get_or_init(Options::default));
        }

        let file = fs::File::open(file)?;
        let options: Options = serde_json::de::from_reader(file)?;
        Ok(self.options.get_or_init(|| options))
    }

    pub fn runtime_dir(&self) -> Result<&Path, &std::io::Error> {
        let result = self.tempdir.get_or_init(|| {
            self.base
                .runtime_dir()
                .ok_or_else(|| self.base.state_dir())
                .map_or_else(
                    |_err| {
                        let dir = std::env::temp_dir().join(env!("CARGO_PKG_NAME"));
                        Ok(RuntimeDirectory::Tempdir(dir))
                    },
                    |appdir| Ok(RuntimeDirectory::AppDir(appdir.to_path_buf())),
                )
        });

        result.as_ref().map(|v| match v {
            RuntimeDirectory::AppDir(dir) | RuntimeDirectory::Tempdir(dir) => dir.as_path(),
        })
    }

    pub fn username(&self) -> &str {
        self.username.get_or_init(whoami::username)
    }

    pub fn identity_file(&self) -> IdentityFile {
        // The identity certificate is *local* to the project.
        let config_folder = self.base.config_local_dir().to_path_buf();
        let path = config_folder.join("ca");
        IdentityFile {
            config_folder,
            path,
        }
    }
}

impl IdentityFile {
    pub fn exists(&self) -> Result<bool, Error> {
        self.path.try_exists()
    }

    pub fn generate(&self, opt: &Options) -> Result<(), Error> {
        std::fs::create_dir_all(&self.config_folder)?;

        let (ssh_keygen, opts) = opt.ssh_keygen.split_first().unwrap();
        let mut keygen = std::process::Command::new(ssh_keygen);

        keygen
            .args(opts)
            .arg("-f")
            .arg(&self.path)
            .args([
                "-C",
                concat!(
                    "Generated certificate authority by and for ",
                    env!("CARGO_PKG_NAME")
                ),
            ])
            // FIXME: support ed25519-sk for security keys, which also makes `-w` relevant for the
            // library supplying those keys.
            .args(["-t", "ed25519"]);

        shell_out_to_command_success(keygen)?;

        Ok(())
    }

    pub fn into_ca(self, opt: &Options) -> Result<CertificateAuthority, Error> {
        let (ssh_keygen, opts) = opt.ssh_keygen.split_first().unwrap();

        let mut public_key = std::process::Command::new(ssh_keygen);

        public_key
            .args(opts)
            .args(["-e", "-m", "rfc4716"])
            .arg("-f")
            .arg(&self.path);

        let output = public_key.output()?;
        let pub_b64 = CertificateAuthority::parse_rfc4716(&output.stdout)?;

        let mut fingerprint = std::process::Command::new(ssh_keygen);
        fingerprint.args(opts).arg("-l").arg("-f").arg(&self.path);
        let output = fingerprint.output()?;

        let keytype = CertificateAuthority::parse_keytype(&output.stdout)?;

        Ok(CertificateAuthority {
            path: self.path,
            keytype,
            pub_b64,
        })
    }
}

impl CertificateAuthority {
    pub fn create_key(
        &self,
        this_program_as_shell: &GitShellWrapper,
        sources: &[LocalInterface],
        opt: &Options,
        path: PathBuf,
    ) -> Result<SignedEphemeralKey, Error> {
        const FORBID_ALL: &[&str] = &[
            "no-agent-forwarding",
            "no-port-forwarding",
            "no-pty",
            "no-user-rc",
            "no-x11-forwarding",
        ];

        let (ssh_keygen, opts) = opt.ssh_keygen.split_first().unwrap();

        let mut create_key = std::process::Command::new(ssh_keygen);

        create_key
            .args(opts)
            .args(["-t", "ed25519"])
            .args(["-C", "Ephemerally valid key for ssh-now clients. Do NOT use this in your authorized_keys"])
            // Ephemerally valid key won't need a passphrase!
            .args(["-N", ""])
            .arg("-q")
            .arg("-f")
            .arg(&path);

        shell_out_to_command_success(create_key)?;

        let mut sign_key = std::process::Command::new(ssh_keygen);

        sign_key
            .args(opts)
            .arg("-q")
            .arg("-s")
            .arg(&self.path)
            .args(["-I", "ssh-now-ephemeral-key"])
            .args(["-V", "-1h:+24h"]);

        for forbid in FORBID_ALL {
            sign_key.args(["-O", forbid]);
        }

        let digest = SignedEphemeralKey::digest_at(&path, opt)?;
        let mnemonic = SignedEphemeralKey::digest_to_mnemonic(digest);

        assert!(
            mnemonic.chars().all(|c| c.is_ascii_graphic()),
            "Would have needed escaping"
        );

        let force_command = format!(
            "force-command=SSH_ORIGINAL_COMMAND=\"{}\" {var}={mnemonic} \"{}\" shell",
            "$SSH_ORIGINAL_COMMAND",
            this_program_as_shell.canonical.display(),
            var = Cli::VAR_PROJECT,
            mnemonic = mnemonic,
        );

        let address_list = sources
            .iter()
            .map(|intf| format!("{}/{}", intf.masked_addr, intf.prefix_len))
            .collect::<Vec<_>>()
            .join(",");

        let address_list = format!("source-address={address_list}");

        sign_key
            .args(["-O", &force_command])
            .args(["-O", &address_list])
            .arg(&path);

        shell_out_to_command_success(sign_key)?;

        Ok(SignedEphemeralKey { path, mnemonic })
    }

    pub fn validate_key(&self, key: &Path, config: &Configuration) -> Result<bool, Error> {
        let opt = config.options()?;

        let (ssh_keygen, opts) = opt.ssh_keygen.split_first().unwrap();
        let mut check_key = std::process::Command::new(ssh_keygen);

        check_key
            .args(opts)
            .args(["-L", "-f"])
            .arg(key)
            .stdout(std::process::Stdio::piped());

        shell_out_to_command_success(check_key)?;

        Ok(true)
    }

    /// Generate the line to add to `authorized_keys`.
    ///
    /// Note that we do *not* add any forced command here but rather to the generated certificates.
    /// We want to touch the `authorized_keys` file as little as possible. It's a precious file and
    /// we do not even expect the user to make it available to us so directions for its contents
    /// are all we limit ourselves to.
    ///
    /// The implication is that we can not modify it often and thus not specifically for each
    /// project. Unfortunately there is no 'pattern' restriction for the command, only a perfect
    /// match. Still the restriction on the certificate are expected to be as strict as we need
    /// them. There isn't any possibility to run commands outside our control. Interestingly this
    /// allows us to pass project-specific settings to certificates such as jailing. If you like
    /// systemd then you might execute everything in an ephemeral unit with full system isolation
    /// to everything except that directory. (To be added as an option, I really like that idea but
    /// not everyone likes or has systemd while other executors for namespace isolation are just as
    /// valid).
    pub fn cert_line(&self, templates: &Templates) -> String {
        templates.authorized_keys("ssh-ed25519", &self.pub_b64)
    }

    fn parse_rfc4716(out: &[u8]) -> Result<String, Error> {
        const START: &str = "---- BEGIN SSH2 PUBLIC KEY ----";
        const END: &str = "---- END SSH2 PUBLIC KEY ----";

        let st = std::str::from_utf8(out)
            .map_err(|err| Error::new(std::io::ErrorKind::InvalidData, err))?;

        let mut data = None;
        let mut lines = st.lines();

        let Some(START) = lines.next() else {
            panic!("Error with wrong start");
        };

        // Looping manually to forward more lines.
        while let Some(mut line) = lines.next() {
            if line.contains(": ") {
                while line.ends_with('\\') {
                    let Some(continuation) = lines.next() else {
                        panic!("Error with invalid continuation")
                    };

                    line = continuation;
                }

                continue;
            }

            let mut buffer = vec![line];
            loop {
                let rest = match lines.next() {
                    Some(END) => {
                        break;
                    }
                    Some(rest) => rest,
                    None => {
                        panic!("Error with wrong end");
                    }
                };

                buffer.push(rest);
            }

            data = Some(buffer.join(""));
        }

        if lines.next().is_some() {
            panic!("Error with pre-end");
        }

        if let Some(data) = data {
            Ok(data)
        } else {
            panic!("Error with missing keydata");
        }
    }

    fn parse_keytype(out: &[u8]) -> Result<CertificateAuthorityType, Error> {
        if out.ends_with(b"(ED25519)\n") {
            Ok(CertificateAuthorityType::Ed25519)
        } else {
            Err(Error::new(
                std::io::ErrorKind::Other,
                "Unrecognized key type in fingerprint for certificate authority",
            ))
        }
    }
}

impl SignedEphemeralKey {
    pub fn digest(&self, opt: &Options) -> Result<[u8; 32], Error> {
        Self::digest_at(&self.path, opt)
    }

    pub fn mnemonic(&self, opt: &Options) -> Result<String, Error> {
        self.digest(opt).map(Self::digest_to_mnemonic)
    }

    pub fn digest_to_mnemonic(digest: [u8; 32]) -> String {
        const STEP: usize = {
            let step = WL_BIP39.len() / 256;
            assert!(step > 0);
            step
        };

        let words: [u8; 4] = digest[..4].try_into().unwrap();
        let words = words.map(|b| WL_BIP39[usize::from(b) * STEP]);
        words.join("-")
    }

    fn digest_at(path: &PathBuf, opt: &Options) -> Result<[u8; 32], Error> {
        let (ssh_keygen, opts) = opt.ssh_keygen.split_first().unwrap();
        let mut describe_key = std::process::Command::new(ssh_keygen);

        describe_key
            .args(opts)
            .arg("-l")
            .arg("-f")
            .arg(path)
            .args(["-E", "sha256"]);

        let output = describe_key.output()?;
        Self::parse_fingerprint(&output.stdout)
    }

    fn parse_fingerprint(stdout: &[u8]) -> Result<[u8; 32], Error> {
        let text = std::str::from_utf8(stdout)
            .map_err(|err| Error::new(std::io::ErrorKind::InvalidData, err))?;

        let start = text.find("SHA256:").unwrap();
        let text = &text[start + 7..];
        let end = text.find(" ").unwrap();
        let text = &text[..end];

        let asb64: Vec<u8> = B64_STANDARD
            .decode(text)
            .map_err(|err| Error::new(std::io::ErrorKind::InvalidData, err))?;

        Ok(asb64.as_slice().try_into().unwrap())
    }
}

impl Options {
    fn default_keygen() -> Vec<PathBuf> {
        vec!["ssh-keygen".into()]
    }
}

impl Default for Options {
    fn default() -> Self {
        serde_json::de::from_str("{}").unwrap()
    }
}

fn shell_out_to_command_success(mut command: std::process::Command) -> Result<(), Error> {
    if !command.status()?.success() {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ssh-keygen failed",
        ))
    } else {
        Ok(())
    }
}

#[test]
fn can_default_options() {
    let _opt: Options = Default::default();
}
