/// All the IO and administration with the user.
mod cli;
mod configuration;
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
    // Always verify options first.
    let _options = config.options()?;

    let cli = cli::Cli::new(&config)?;
    cli.act(&config)?;

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
