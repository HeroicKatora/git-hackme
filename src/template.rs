use serde_json::Value;
use tinytemplate::{error::Result, TinyTemplate};

struct Templates {
    tiny: TinyTemplate<'static>,
}

impl Templates {
    const TEMPLATE_AUTH: &'static str = "ssh-authorized_keys";

    pub fn load() -> Self {
        let mut tiny = TinyTemplate::new();

        tiny.add_template(
            Self::TEMPLATE_AUTH,
            include_str!("../template/autorized_keys"),
        )
        .unwrap();

        tiny.add_formatter("arg_escape", Self::arg_escape);

        Templates { tiny }
    }

    fn arg_escape(val: &Value, into: &mut String) -> Result<()> {
        todo!()
    }
}
