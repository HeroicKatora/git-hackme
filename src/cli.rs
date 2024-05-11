use std::{ffi::OsString, fs, io::Error, path::PathBuf};

use crate::{
    configuration::{
        CertificateAuthority, Configuration, IdentityFile, Options, SignedEphemeralKey,
    },
    template::Templates,
};

use directories::ProjectDirs;

pub struct Cli {
    binary: GitShellWrapper,
    interfaces: Vec<LocalInterface>,
    templates: Templates,
}

pub struct GitShellWrapper {
    pub canonical: PathBuf,
}

pub struct LocalInterface {
    pub prefix_len: u8,
    pub masked_addr: core::net::IpAddr,
}

impl Cli {
    pub fn new(_: &Options) -> Result<Self, Error> {
        let mut args = std::env::args_os();
        let binary = PathBuf::from(args.next().unwrap());

        let arguments: Vec<_> = args.collect();
        let args_str: Vec<_> = arguments.iter().map(|os| os.to_str()).collect();

        match args_str[..] {
            [] | [Some("--help")] => Self::exit_help(&binary),
            [Some("shell")] => return Err(Self::exec_shell()),
            [Some("init")] => {}
            _ => Self::exit_fail(&binary, arguments),
        }

        let templates = Templates::load();

        let binary = GitShellWrapper {
            canonical: binary.canonicalize()?,
        };

        let interfaces = netdev::get_interfaces()
            .into_iter()
            .flat_map(|intf| {
                // FIXME: apply some filter lists here, maybe.
                let ipv4 = intf.ipv4.iter().map(|&ip| netdev::ip::IpNet::from(ip));
                let ipv6 = intf.ipv6.iter().map(|&ip| netdev::ip::IpNet::from(ip));

                ipv4.chain(ipv6)
                    .map(|net| LocalInterface {
                        prefix_len: net.prefix_len(),
                        // The documentation says 'address/netmask' pair but really they mean
                        // address-masked-down-to-length-pair. So the network's portion. It
                        // complains about it being inconsistent if we include any bits that should
                        // be masked off?
                        masked_addr: net.network(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        Ok(Cli {
            binary,
            interfaces,
            templates,
        })
    }

    fn exit_help(bin: &PathBuf) -> ! {
        eprintln!("Usage: {} [init | shell]", bin.display());
        std::process::exit(0)
    }

    fn exit_fail(bin: &PathBuf, _arguments: Vec<OsString>) {
        eprintln!("Did not understand you there");
        eprintln!("Usage: {} [init | shell]", bin.display());
        std::process::exit(1)
    }

    fn exec_shell() -> Error {
        use std::os::unix::process::CommandExt as _;

        let cmd = std::env::var_os("SSH_ORIGINAL_COMMAND").unwrap();
        std::process::Command::new("git-shell")
            .arg("-c")
            .arg(cmd)
            .exec()
    }

    pub fn create_ca(
        &self,
        opt: &Options,
        id: IdentityFile,
    ) -> Result<CertificateAuthority, Error> {
        if !id.exists()? {
            eprintln!("Creating Certificate Authority: {}", id.path.display());
            id.generate(opt)?;
        }

        id.into_ca(opt)
    }

    pub(crate) fn generate_and_sign_key(
        &self,
        dirs: &ProjectDirs,
        options: &Options,
        ca: &CertificateAuthority,
    ) -> Result<SignedEphemeralKey, Error> {
        let basedir = dirs.runtime_dir().ok_or_else(|| dirs.state_dir());
        let basedir = basedir.unwrap();

        std::fs::create_dir_all(basedir)?;

        let path = basedir.join("ssh-new-ephemeral");
        if path.try_exists()? {
            std::fs::remove_file(&path)?;
        }

        ca.create_key(&self.binary, &self.interfaces, options, path)
    }

    pub(crate) fn find_ca_or_warn(
        &self,
        dirs: &Configuration,
        ca: &CertificateAuthority,
    ) -> Result<(), Error> {
        let authorized_keys = Self::find_authorized_keys(dirs);
        let expected_line = ca.cert_line(&self.templates);

        if authorized_keys.is_empty() {
            eprintln!("Could not determined authorized_keys file.");
            eprintln!("Insert:");
            eprintln!("{expected_line}");
            return Ok(());
        }

        for file in &authorized_keys {
            if let Ok(file) = fs::File::open(file) {
                let file = std::io::BufReader::new(file);
                for line in std::io::BufRead::lines(file) {
                    if line? == expected_line {
                        return Ok(());
                    }
                }
            }
        }

        eprintln!("Your authorized_keys configuration does not authorize the ssh-now authority.");
        eprintln!("Insert:");
        eprintln!("{expected_line}");

        if let [file] = &authorized_keys[..] {
            eprintln!("in your authorized_keys file `{}`", file.display());
        } else {
            eprintln!("in your authorized keys files.");
        }

        Ok(())
    }

    fn find_authorized_keys(dirs: &Configuration) -> Vec<PathBuf> {
        if let Some(user) = &dirs.user {
            // FIXME: Inspect `/etc/ssh/sshd_config` for `AuthorizedKeysFile`.
            vec![user.home_dir().join(".ssh/authorized_keys")]
        } else {
            vec![]
        }
    }
}
