use serde_json::Value;
use tinytemplate::{error::Error, TinyTemplate};

pub struct Templates {
    tiny: TinyTemplate<'static>,
}

impl Templates {
    const TEMPLATE_AUTH: &'static str = "ssh-authorized_keys";

    pub fn load() -> Self {
        let mut tiny = TinyTemplate::new();

        tiny.add_template(
            Self::TEMPLATE_AUTH,
            include_str!("../template/autorized_keys").trim_end(),
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

        let value = Value {
            keytype,
            certkey,
        };

        self.tiny.render(Self::TEMPLATE_AUTH, &value).unwrap()
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
