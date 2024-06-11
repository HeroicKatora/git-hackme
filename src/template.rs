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
    const TEMPLATE_KEY_CONFIG: &'static str = "key-config";
    const TEMPLATE_INDEX: &'static str = "html-index";
    const TEMPLATE_STYLE: &'static str = "html-style-css";

    pub fn load() -> Self {
        let mut tiny = TinyTemplate::new();

        tiny.add_template(
            Self::TEMPLATE_AUTH,
            include_str!("../template/autorized_keys").trim_end(),
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

        tiny.add_template(
            Self::TEMPLATE_STYLE,
            include_str!("../template/style.css").trim_end(),
        )
        .unwrap();

        tiny.add_formatter("arg_escape", Self::arg_escape);
        tiny.add_formatter("base64_document", Self::arg_base64_url);
        tiny.add_formatter("format_unescaped", tinytemplate::format_unescaped);

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

    pub fn key_ssh_config(&self, runtime: &Path, url: &url::Url, mnemonic: &str) -> String {
        #[derive(serde::Serialize)]
        struct Value<'a> {
            mnemonic: &'a str,
            host: &'a str,
            user: &'a str,
            runtime: &'a Path,
        }

        let host = url.host_str().unwrap();
        let user = url.username();

        let value = Value {
            mnemonic,
            host,
            user,
            runtime,
        };

        self.tiny.render(Self::TEMPLATE_KEY_CONFIG, &value).unwrap()
    }

    pub fn index(&self, username: &str, projects: &[Project]) -> String {
        #[derive(serde::Serialize)]
        struct Value<'a> {
            username: &'a str,
            projects: &'a [Project],
            repository: &'a str,
            spa_script: &'a str,
        }

        let value = Value {
            username,
            projects,
            repository: env!("CARGO_PKG_REPOSITORY"),
            spa_script: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/template/index.js")),
        };

        self.tiny.render(Self::TEMPLATE_INDEX, &value).unwrap()
    }

    pub fn style(&self, logo_github: &str) -> String {
        #[derive(serde::Serialize)]
        struct Value<'a> {
            logo_github: &'a str,
        }

        let value = Value { logo_github };
        self.tiny.render(Self::TEMPLATE_STYLE, &value).unwrap()
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

    fn arg_base64_url(val: &Value, into: &mut String) -> Result<(), Error> {
        let Value::String(st) = val else {
            return Err(Error::GenericError {
                msg: "can only format strings".into(),
            });
        };

        let engine = base64::engine::general_purpose::STANDARD;
        let formatable = base64::display::Base64Display::new(st.as_bytes(), &engine);
        into.push_str(&format_args!("data:image/svg+xml;base64,{}", formatable).to_string());

        Ok(())
    }
}
