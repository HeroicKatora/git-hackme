use crate::configuration::{CertificateAuthority, IdentityFile, Options, SignedEphemeralKey};
use directories::ProjectDirs;

pub struct Cli;

impl Cli {
    pub fn create_ca(
        &self,
        opt: &Options,
        id: IdentityFile,
    ) -> Result<CertificateAuthority, std::io::Error> {
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
    ) -> Result<SignedEphemeralKey, std::io::Error> {
        let path = dirs.runtime_dir().ok_or_else(|| dirs.state_dir());
        let path = path.unwrap();

        std::fs::create_dir_all(path)?;

        let path = path.join("ssh-new-ephemeral");
        if path.try_exists()? {
            std::fs::remove_file(&path)?;
        }

        ca.create_key(options, path)
    }
}
