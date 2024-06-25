use serde::{Deserialize, Serialize};
use std::{fs, io, path::Path};

#[derive(Deserialize, Serialize)]
pub struct Description {
    name: Option<String>,
}

impl Description {
    pub fn from_path(path: &Path) -> Self {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());

        Description { name }
    }

    pub fn read(path: &Path) -> io::Result<Self> {
        let reader = fs::OpenOptions::new()
            .read(true)
            .open(path)?;

        Ok(serde_json::de::from_reader(reader)?)
    }

    pub fn write(&self, path: &Path) -> io::Result<()> {
        let writer = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        serde_json::ser::to_writer(writer, self)?;
        Ok(())
    }
}
