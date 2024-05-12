use serde_json::Value;
use std::path::Path;
use tinytemplate::{error::Error, TinyTemplate};

pub struct Templates {
    tiny: TinyTemplate<'static>,
}

#[derive(serde::Serialize)]
pub struct Project {
    pub mnemonic: String,
}

impl Templates {
    const TEMPLATE_AUTH: &'static str = "ssh-authorized_keys";
    const TEMPLATE_SSH_CONFIG: &'static str = "ssh-config";
    const TEMPLATE_KEY_CONFIG: &'static str = "key-config";
    const TEMPLATE_INDEX: &'static str = "index-html";

    pub fn load() -> Self {
        let mut tiny = TinyTemplate::new();

        tiny.add_template(
            Self::TEMPLATE_AUTH,
            include_str!("../template/autorized_keys").trim_end(),
        )
        .unwrap();

        tiny.add_template(
            Self::TEMPLATE_SSH_CONFIG,
            include_str!("../template/ssh_config").trim_end(),
        )
        .unwrap();

        tiny.add_template(
            Self::TEMPLATE_KEY_CONFIG,
            include_str!("../template/key-ssh_config").trim_end(),
        )
        .unwrap();

        tiny.add_template(
            Self::TEMPLATE_INDEX,
            include_str!("../template/index.html").trim_end(),
        )
        .unwrap();

        tiny.add_formatter("arg_escape", Self::arg_escape);

        Templates { tiny }
    }

    pub fn authorized_keys(&self, keytype: &str, certkey: &str) -> String {
        assert!(
            keytype.chars().all(|ch| ch.is_ascii_graphic()),
            "Expected keytype to be from a small number of options, got {}",
            keytype
        );

        assert!(
            certkey
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '/' || ch == '+'),
            "Expected base64 encoded key, got {}",
            certkey
        );

        #[derive(serde::Serialize)]
        struct Value<'a> {
            keytype: &'a str,
            certkey: &'a str,
        }

        let value = Value { keytype, certkey };
        self.tiny.render(Self::TEMPLATE_AUTH, &value).unwrap()
    }

    pub fn ssh_config(&self, basedir: &Path) -> String {
        #[derive(serde::Serialize)]
        struct Value<'a> {
            basedir: &'a Path,
        }

        let value = Value { basedir };
        self.tiny.render(Self::TEMPLATE_SSH_CONFIG, &value).unwrap()
    }

    pub fn key_ssh_config(&self, url: &url::Url, mnemonic: &str) -> String {
        use crate::cli::Cli;

        #[derive(serde::Serialize)]
        struct Value<'a> {
            mnemonic: &'a str,
            host: &'a str,
            user: &'a str,
            runtime_var: &'a str,
        }

        let host = url.host_str().unwrap();
        let user = url.username();
        let runtime_var = format!("${{{}}}", Cli::VAR_RUNTIME);

        let value = Value {
            mnemonic,
            host,
            user,
            runtime_var: &runtime_var,
        };

        self.tiny.render(Self::TEMPLATE_KEY_CONFIG, &value).unwrap()
    }

    pub fn index(&self, username: &str, projects: &[Project]) -> String {
        #[derive(serde::Serialize)]
        struct Value<'a> {
            username: &'a str,
            projects: &'a [Project],
        }

        let value = Value { username, projects };
        self.tiny.render(Self::TEMPLATE_INDEX, &value).unwrap()
    }

    fn arg_escape(val: &Value, into: &mut String) -> Result<(), Error> {
        let Value::String(st) = val else {
            return Err(Error::GenericError {
                msg: "can only format strings".into(),
            });
        };

        into.push_str(&st.replace('\"', "\\\""));
        Ok(())
    }
}
