use core::net::{IpAddr, SocketAddr};
use std::{ffi::OsString, fs, io::Error, path::Path, path::PathBuf};

use std::os::unix::{fs::OpenOptionsExt as _, process::CommandExt as _};

use crate::configuration::Isolate;
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
    action: ActionFn,
}

type ActionFn = fn(&Cli, &Configuration) -> Result<(), std::io::Error>;

pub struct GitShellWrapper {
    pub canonical: PathBuf,
}

pub struct LocalInterface {
    pub prefix_len: u8,
    pub masked_addr: IpAddr,
}

#[must_use]
struct Joined {
    pub mnemonic_host: String,
    pub ssh_config: PathBuf,
}

impl Cli {
    pub fn new(config: &Configuration) -> Result<Self, Error> {
        let mut args = std::env::args_os();
        let binary = PathBuf::from(args.next().unwrap());

        let arguments: Vec<_> = args.collect();
        let args_str: Vec<_> = arguments.iter().map(|os| os.to_str()).collect();

        let create_key_for;
        let join_http;
        let action: ActionFn;

        match args_str[..] {
            [] | [Some("--help")] => Self::exit_help(&binary),
            [Some("shell")] => return Err(Self::exec_shell(config)),
            [Some("init")] => {
                create_key_for = None;
                join_http = None;
                action = Self::action_check_init;
            }
            [Some("share")] => {
                create_key_for = Some(std::env::current_dir()?);
                join_http = None;
                action = Self::action_start;
            }
            [Some("clone"), Some(url)] => {
                create_key_for = None;
                let from_url: url::Url = url.parse().unwrap();

                assert!(
                    ["http", "https"].contains(&from_url.scheme()),
                    "Unhandled protocol to join"
                );

                join_http = Some(from_url);
                action = Self::action_clone;
            }
            _ => Self::exit_fail(&binary, arguments),
        };

        let templates = template::Templates::load();

        let binary = GitShellWrapper {
            canonical: {
                let dev_or_full = binary.canonicalize().map_or_else(
                    |err| {
                        if err.kind() == std::io::ErrorKind::NotFound {
                            Ok(None)
                        } else {
                            Err(err)
                        }
                    },
                    |canonical| Ok(Some(canonical)),
                )?;

                if let Some(canonical) = dev_or_full {
                    canonical
                } else {
                    // Surely we find ourselves, eh?
                    which::which(env!("CARGO_BIN_NAME")).unwrap()
                }
            },
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
            action,
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

    fn exec_shell(config: &Configuration) -> Error {
        let cmd = std::env::var_os("SSH_ORIGINAL_COMMAND").unwrap();
        let mnemonic = std::env::var_os(Cli::VAR_PROJECT).unwrap();

        let options = config.options().unwrap();

        let dirs = &config.base;
        let basedir = dirs.runtime_dir().ok_or_else(|| dirs.state_dir());
        let basedir = basedir.unwrap();

        let src_dir = basedir.join(&mnemonic).join(&mnemonic);
        // As promised this should be a link.
        let original_dir = src_dir.read_link().unwrap();

        /* What does not work for isolation:
        *
        * systemd-run with
           .args([
                 "--user",
                 "--service-type=exec",
                 "--wait",
                 "--collect",
           ])
        * This fails to pipe input and output so it doesn't do anything.
        *
        * unshare
        *   requests a tty and then git complains rightfully about no-login
        *
        * systemd-nspawn
        *   requires privileges
        */

        match options.isolate {
            None => {
                let src_dir = src_dir.canonicalize().unwrap();
                std::process::Command::new("git-shell")
                    .arg("-c")
                    .arg(cmd)
                    .current_dir(src_dir)
                    .exec()
            }
            Some(Isolate::SystemdRun) => {
                eprintln!("Isolating with systemd-run and read-only paths");
                std::process::Command::new("systemd-run")
                    .args([
                        "--user",
                        "--service-type=exec",
                        "--wait",
                        "--collect",
                        "--pipe",
                        "-p",
                        &format!("WorkingDirectory={}", src_dir.display()),
                        "-p",
                        "ReadOnlyPaths=/",
                        "-p",
                        "ProtectHome=tmpfs",
                        // "-p",
                        // &format!("ReadWritePaths={}", src_dir.display()),
                        "-p",
                        "ProtectSystem=strict",
                        "-p",
                        "TemporaryFileSystem=/",
                        "-p",
                        &format!("BindPaths={}:{}", original_dir.display(), src_dir.display()),
                    ])
                    .arg("git-shell")
                    .arg("-c")
                    .arg(cmd)
                    .current_dir(src_dir)
                    .exec()
            }
        }
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
        let mnemonic = temporary.mnemonic(options)?;

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

    pub fn recreate_index(
        &self,
        config: &Configuration,
        find_project: Option<&str>,
    ) -> Result<(), Error> {
        let dirs = &config.base;
        // FIXME: duplicate code to access this directory, should be cached and unified in
        // `Configuration` with proper error handling if we can not find a base directory. Some
        // code might also rely on the automatic cleanup we can do here? Or should we perform one
        // manually when key signatures get invalidated?
        let basedir = dirs.runtime_dir().ok_or_else(|| dirs.state_dir());
        let basedir = basedir.unwrap();

        std::fs::create_dir_all(basedir)?;

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

        let index = self.templates.index(config.username(), &projects);
        let style = self.templates.style(Self::LOGO_GITHUB);

        std::fs::create_dir_all(basedir)?;
        std::fs::write(basedir.join("index.html"), index)?;
        std::fs::write(basedir.join("style.css"), style)?;

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

        // Most likely should be last so we min-sort on this.
        likely_if.sort_by_key(|(intf, _)| (intf.default, intf.transmit_speed));
        let Some((_, most_likely_addr)) = likely_if.last() else {
            return Ok(());
        };

        // The Python default port. FIXME: option to user-define this guess based on a suggested
        // server or even some trigger for start the server service.
        let most_likely_sock = SocketAddr::new(most_likely_addr.addr(), 8000);
        if Self::detect_server(most_likely_sock, find_project) {
            eprintln!("Have data ready to serve, server appears running at {}", {
                let mut url: url::Url = "http://dummy.local/".parse().unwrap();
                url.set_ip_host(most_likely_sock.ip()).unwrap();
                url.set_port(Some(most_likely_sock.port())).unwrap();
                url
            });

            return Ok(());
        };

        if Self::detect_python() {
            eprintln!("Have data ready to serve, suggesting a server with Python");

            let servedir = basedir.display().to_string();
            eprintln!(
                "python3 -m http.server -d \"{}\"",
                servedir.replace('"', "\\\"")
            );
        }

        eprintln!("Reachable via the following interfaces:");
        for (intf, network) in likely_if {
            let name = intf.friendly_name.as_ref().unwrap_or(&intf.name);
            eprintln!("if {} at {}", name, network.addr());
        }

        Ok(())
    }

    pub fn act(&self, config: &Configuration) -> Result<(), std::io::Error> {
        (self.action)(self, config)
    }

    fn action_check_init(&self, config: &Configuration) -> Result<(), std::io::Error> {
        let options = config.options()?;
        let ca = self.create_ca(options, config.identity_file())?;
        self.find_ca_or_warn(&config, &ca)?;
        self.recreate_index(&config, None)?;

        Ok(())
    }

    fn action_start(&self, config: &Configuration) -> Result<(), std::io::Error> {
        let options = config.options()?;
        let ca = self.create_ca(options, config.identity_file())?;

        if let Some(_path) = self.create_key_for() {
            let signed = self.generate_and_sign_key(&config.base, options, &ca)?;
            let mnemonic = signed.mnemonic(options)?;
            eprintln!("Generated new keyfile in {}", signed.path.display());
            self.recreate_index(&config, Some(&mnemonic))?;
        }

        Ok(())
    }

    fn action_clone(&self, config: &Configuration) -> Result<(), std::io::Error> {
        let Some(join) = self.join_url() else {
            return Ok(());
        };

        let joined = self.join(&config, join)?;
        self.checkout(joined)?;

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

    fn detect_server(sock: SocketAddr, project: Option<&str>) -> bool {
        let mut url: url::Url = "http://dummy.local/".parse().unwrap();
        url.set_ip_host(sock.ip()).unwrap();
        url.set_port(Some(sock.port())).unwrap();

        if let Some(mnemonic) = project {
            url.set_path(&format!("{mnemonic}/key-cert.pub"));
        }

        ureq::request_url("GET", &url)
            .call()
            .map_or(false, |response| response.status() == 200)
    }

    fn join(&self, config: &Configuration, url: &url::Url) -> Result<Joined, Error> {
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

        let mnemonic_host = format!("{horse_battery}.hackme.local");
        let ssh_config = joindir.join("ssh_config");

        let key_config = self.templates.key_ssh_config(&basedir, url, horse_battery);
        std::fs::write(&ssh_config, key_config)?;

        Ok(Joined {
            mnemonic_host,
            ssh_config,
        })
    }

    fn checkout(&self, join: Joined) -> Result<(), std::io::Error> {
        let ssh_command = format!(
            "ssh -F \"{}\"",
            join.ssh_config.display().to_string().replace('"', "\\\"")
        );

        let _clone = std::process::Command::new("git")
            .arg("-c")
            .arg(format!("core.sshCommand={ssh_command}"))
            .arg("clone")
            .arg(format!("{}:", join.mnemonic_host))
            .status()?;

        Ok(())
    }

    pub const VAR_PROJECT: &'static str = "GIT_HACKME_PROJECT";
    pub const LOGO_GITHUB: &'static str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/template/Github-03.svg"));

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

    fn find_authorized_keys(dirs: &Configuration) -> Vec<PathBuf> {
        if let Some(user) = &dirs.user {
            // FIXME: Inspect `/etc/ssh/sshd_config` for `AuthorizedKeysFile`.
            vec![user.home_dir().join(".ssh/authorized_keys")]
        } else {
            vec![]
        }
    }
}
