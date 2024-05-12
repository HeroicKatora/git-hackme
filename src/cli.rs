use std::{ffi::OsString, fs, io::Error, path::Path, path::PathBuf};

use std::os::unix::{fs::OpenOptionsExt as _, process::CommandExt as _};

use crate::{
    configuration::{
        CertificateAuthority, Configuration, IdentityFile, Options, SignedEphemeralKey,
    },
    template,
};

use directories::ProjectDirs;

pub struct Cli {
    binary: GitShellWrapper,
    interfaces: Vec<LocalInterface>,
    templates: template::Templates,
    create_key_for: Option<PathBuf>,
    join_http: Option<url::Url>,
}

pub struct GitShellWrapper {
    pub canonical: PathBuf,
}

pub struct LocalInterface {
    pub prefix_len: u8,
    pub masked_addr: core::net::IpAddr,
}

impl Cli {
    pub fn new(config: &Configuration) -> Result<Self, Error> {
        let mut args = std::env::args_os();
        let binary = PathBuf::from(args.next().unwrap());

        let arguments: Vec<_> = args.collect();
        let args_str: Vec<_> = arguments.iter().map(|os| os.to_str()).collect();

        let create_key_for;
        let join_http;

        match args_str[..] {
            [] | [Some("--help")] => Self::exit_help(&binary),
            [Some("shell")] => return Err(Self::exec_shell(&config.base)),
            [Some("init")] => {
                create_key_for = None;
                join_http = None;
            }
            [Some("start")] => {
                create_key_for = Some(std::env::current_dir()?);
                join_http = None;
            }
            [Some("join"), Some(url)] => {
                create_key_for = None;
                let from_url: url::Url = url.parse().unwrap();

                assert!(
                    ["http", "https"].contains(&from_url.scheme()),
                    "Unhandled protocol to join"
                );

                join_http = Some(from_url);
            }
            _ => Self::exit_fail(&binary, arguments),
        };

        let templates = template::Templates::load();

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
            create_key_for,
            join_http,
        })
    }

    fn exit_help(bin: &PathBuf) -> ! {
        eprintln!("Usage: {} [init | shell]", bin.display());
        std::process::exit(0)
    }

    fn exit_fail(bin: &PathBuf, _arguments: Vec<OsString>) -> ! {
        eprintln!("Did not understand you there");
        eprintln!("Usage: {} [init | shell]", bin.display());
        std::process::exit(1)
    }

    fn exec_shell(dirs: &ProjectDirs) -> Error {
        let cmd = std::env::var_os("SSH_ORIGINAL_COMMAND").unwrap();
        let mnemonic = std::env::var_os(Cli::VAR_PROJECT).unwrap();

        let basedir = dirs.runtime_dir().ok_or_else(|| dirs.state_dir());
        let basedir = basedir.unwrap();

        let src_dir = basedir.join(&mnemonic).join(&mnemonic);

        eprintln!("{}", src_dir.display());

        let src_dir = src_dir.canonicalize().unwrap();

        std::process::Command::new("git-shell")
            .arg("-c")
            .arg(cmd)
            .current_dir(src_dir)
            .exec()
    }

    pub fn create_key_for(&self) -> Option<&Path> {
        self.create_key_for.as_deref()
    }

    pub fn join_url(&self) -> Option<&url::Url> {
        self.join_http.as_ref()
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

    pub fn generate_and_sign_key(
        &self,
        dirs: &ProjectDirs,
        options: &Options,
        ca: &CertificateAuthority,
    ) -> Result<SignedEphemeralKey, Error> {
        let basedir = dirs.runtime_dir().ok_or_else(|| dirs.state_dir());
        let basedir = basedir.unwrap();

        std::fs::create_dir_all(basedir)?;

        let path = basedir.join(".ssh-new-ephemeral");
        if path.try_exists()? {
            std::fs::remove_file(&path)?;
        }

        let temporary = ca.create_key(&self.binary, &self.interfaces, options, path)?;
        let digest = temporary.digest(options)?;
        let mnemonic = SignedEphemeralKey::digest_to_mnemonic(digest);

        let fulldir = basedir.join(&mnemonic);
        std::fs::create_dir(&fulldir)?;

        let path = fulldir.join("key");

        std::fs::rename(basedir.join(".ssh-new-ephemeral"), &path)?;
        std::fs::rename(
            basedir.join(".ssh-new-ephemeral.pub"),
            fulldir.join("key.pub"),
        )?;
        std::fs::rename(
            basedir.join(".ssh-new-ephemeral-cert.pub"),
            fulldir.join("key-cert.pub"),
        )?;

        // Create the project's direct link to the source repository
        std::os::unix::fs::symlink(std::env::current_dir()?, fulldir.join(&mnemonic))?;

        Ok(SignedEphemeralKey { path })
    }

    pub fn recreate_index(&self, config: &Configuration) -> Result<(), Error> {
        let dirs = &config.base;
        // FIXME: duplicate code to access this directory, should be cached and unified in
        // `Configuration` with proper error handling if we can not find a base directory. Some
        // code might also rely on the automatic cleanup we can do here? Or should we perform one
        // manually when key signatures get invalidated?
        let basedir = dirs.runtime_dir().ok_or_else(|| dirs.state_dir());
        let basedir = basedir.unwrap();

        let mut projects = vec![];
        for project in std::fs::read_dir(basedir)? {
            let Ok(project) = project else {
                continue;
            };

            let entry_name = project.file_name();
            // Find out if this may be a valid entry by inspecting the name. It should be generated
            // according to our mnemonic file name patterns.
            let Some(name) = entry_name.to_str() else {
                continue;
            };

            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                continue;
            }

            let mnemonic = name.to_owned();
            projects.push(template::Project { mnemonic });
        }

        let index = self.templates.index(&projects);

        std::fs::create_dir_all(basedir)?;
        std::fs::write(basedir.join("index.html"), index)?;

        if Self::detect_python() {
            eprintln!("Have data ready to serve, suggesting a server with Python");

            let servedir = basedir.display().to_string();
            eprintln!(
                "python3 -m http.server -d \"{}\"",
                servedir.replace('"', "\\\"")
            );
        }

        let interfaces = netdev::get_interfaces();
        let mut likely_if: Vec<_> = interfaces
            .into_iter()
            .filter_map(|intf| {
                match intf.if_type {
                    netdev::interface::InterfaceType::Ethernet
                    | netdev::interface::InterfaceType::Wireless80211 => {}
                    _ => return None,
                }

                let ipv4 = intf.ipv4.iter().map(|&ip| netdev::ip::IpNet::from(ip));
                let ipv6 = intf.ipv6.iter().map(|&ip| netdev::ip::IpNet::from(ip));

                let Some(addr) = ipv4.chain(ipv6).next() else {
                    // Not up.
                    return None;
                };

                Some((intf, addr))
            })
            .collect();

        if !likely_if.is_empty() {
            // Most likely should be last so we min-sort on this.
            likely_if.sort_by_key(|(intf, _)| (intf.default, intf.transmit_speed));

            eprintln!("Reachable via the following interfaces:");
            for (intf, network) in likely_if {
                let name = intf.friendly_name.as_ref().unwrap_or(&intf.name);
                eprintln!("if {} at {}", name, network.addr());
            }
        }

        Ok(())
    }

    fn detect_python() -> bool {
        std::process::Command::new("python3")
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_or(false, |_| true)
    }

    pub fn join(&self, config: &Configuration, url: &url::Url) -> Result<(), Error> {
        let dirs = &config.base;

        let Some(segments) = url.path_segments() else {
            panic!("Trying to join cannot-be-base URL, should be caught earlier");
        };

        let Some(horse_battery) = segments.last() else {
            panic!("Not an encoded name, obviously");
        };

        assert!(horse_battery.chars().all(|ch| ch.is_ascii_graphic()));

        let basedir = dirs.runtime_dir().ok_or_else(|| dirs.state_dir());
        let basedir = basedir.unwrap();

        // FIXME: duplicate code that may diverge.
        let ssh_config_file = config.base.config_local_dir().join("ssh_config");
        let ssh_config = self.templates.ssh_config(&basedir);
        std::fs::write(ssh_config_file, ssh_config)?;

        let joindir = basedir.join(format!(".join/{horse_battery}"));
        std::fs::create_dir_all(&joindir)?;

        #[deprecated = "Network errors from ureq should not panic!"]
        fn _ureq(err: ureq::Error) -> std::io::Error {
            panic!("Ureq handling {}", err)
        }

        for part in ["key", "key.pub", "key-cert.pub"] {
            let file = joindir.join(part);
            let mut url = url.clone();

            {
                let mut segments = url.path_segments_mut().unwrap();
                segments.pop_if_empty();
                segments.push(part);
            }

            let response = ureq::request_url("GET", &url).call().map_err(_ureq)?;

            assert!(response.status() == 200);
            let mut reader = response.into_reader();
            let mut writer = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .mode(0o600)
                .open(&file)?;

            std::io::copy(&mut reader, &mut writer)?;
        }

        let key_config = self.templates.key_ssh_config(url, horse_battery);
        std::fs::write(joindir.join("ssh_config"), key_config)?;

        Ok(())
    }

    pub const VAR_RUNTIME: &'static str = "GIT_HACKME_RUNTIME_DIR";
    pub const VAR_PROJECT: &'static str = "GIT_HACKME_PROJECT";

    pub fn find_ca_or_warn(
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

    pub fn find_include_or_warn(&self, dirs: &Configuration) -> Result<(), Error> {
        let Some(config) = Self::find_ssh_config(dirs) else {
            return Ok(());
        };

        let ssh_config_file = dirs.base.config_local_dir().join("ssh_config");
        let expected_line = match Self::include_line(dirs, &ssh_config_file) {
            Ok(path) => {
                let arg = path.display().to_string().replace('\"', "\\\"");
                format!("Include \"~/{}\"", arg)
            }
            Err(path) => {
                let arg = path.display().to_string().replace('\"', "\\\"");
                format!("Include \"{}\"", arg)
            }
        };

        if let Ok(file) = fs::File::open(&config) {
            let file = std::io::BufReader::new(file);
            for line in std::io::BufRead::lines(file) {
                if line? == expected_line {
                    return Ok(());
                }
            }
        }

        eprintln!("Your ssh config does not include the dynamically provided identities.");
        eprintln!("Insert:");
        eprintln!("{expected_line}");
        eprintln!("in your authorized_keys file `{}`", config.display());

        Ok(())
    }

    pub fn find_env_or_warn(&self, dirs: &Configuration) -> Result<(), Error> {
        let Some(runtime) = dirs.base.runtime_dir() else {
            return Ok(());
        };

        let expected_line = std::ffi::OsString::from(&runtime);
        let real_env = std::env::var_os(Self::VAR_RUNTIME);

        if real_env == Some(expected_line) {
            return Ok(());
        }

        eprintln!("Your environment config does not specify the expected runtime directory");
        // We print this so one can source this command!
        println!("export {}={}", Self::VAR_RUNTIME, runtime.display());

        Ok(())
    }

    fn include_line<'lt>(dirs: &'lt Configuration, file: &'lt Path) -> Result<PathBuf, &'lt Path> {
        fn strip_home(dirs: &Configuration, file: &Path) -> Option<PathBuf> {
            let home = dirs.user.as_ref()?.home_dir();
            let relative = file.strip_prefix(home).ok()?;
            Some(relative.to_path_buf())
        }

        strip_home(dirs, file).ok_or(file)
    }

    fn find_authorized_keys(dirs: &Configuration) -> Vec<PathBuf> {
        if let Some(user) = &dirs.user {
            // FIXME: Inspect `/etc/ssh/sshd_config` for `AuthorizedKeysFile`.
            vec![user.home_dir().join(".ssh/authorized_keys")]
        } else {
            vec![]
        }
    }

    fn find_ssh_config(dirs: &Configuration) -> Option<PathBuf> {
        if let Some(user) = &dirs.user {
            // FIXME: Inspect `/etc/ssh/sshd_config` etc.
            Some(user.home_dir().join(".ssh/config"))
        } else {
            None
        }
    }
}
