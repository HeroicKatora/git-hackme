/// All the IO and administration with the user.
mod cli;
mod configuration;
mod key;
mod template;

fn main() -> Exit {
    Exit::from(_do)
}

enum Exit {
    Ok,
    Error(std::io::Error),
    Bug(Box<dyn core::any::Any + Send + 'static>),
}

fn _do() -> Result<(), std::io::Error> {
    let config = configuration::Configuration::get()?;
    let options = config.options()?;

    let cli = cli::Cli::new(options)?;

    let ca = cli.create_ca(options, config.identity_file())?;

    cli.find_ca_or_warn(&config, &ca)?;

    if let Some(_path) = cli.create_key_for() {
        let signed = cli.generate_and_sign_key(&config.base, options, &ca)?;
        eprintln!("Generated new keyfile in {}", signed.path.display());
    }

    if let Some(join) = cli.join_url() {
        cli.find_include_or_warn(&config)?;
        cli.find_env_or_warn(&config)?;

        cli.join(&config, join)?;
    }

    Ok(())
}

impl<F> From<F> for Exit
where
    F: FnOnce() -> Result<(), std::io::Error> + std::panic::UnwindSafe,
{
    fn from(value: F) -> Self {
        match std::panic::catch_unwind(value) {
            Ok(Ok(())) => Exit::Ok,
            Ok(Err(err)) => Exit::Error(err),
            Err(bug) => Exit::Bug(bug),
        }
    }
}

impl std::process::Termination for Exit {
    fn report(self) -> std::process::ExitCode {
        match self {
            Exit::Ok => std::process::ExitCode::SUCCESS,
            Exit::Error(err) => {
                eprintln!("{err}");
                std::process::ExitCode::FAILURE
            }
            Exit::Bug(bug) => {
                eprintln!("Unhandled termination. We would appreciate a bug report for this");
                std::panic::resume_unwind(bug)
            }
        }
    }
}
