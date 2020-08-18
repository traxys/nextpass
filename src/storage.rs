use crate::crypto::Key;
use nextcloud_passwords_client::password::Password;
use serde::{Deserialize, Serialize};
use crate::LazyApi;

#[derive(Serialize, Deserialize)]
pub struct Passwords {
    passwords: Vec<Password>,
}

impl Passwords {
    pub async fn open_or_fetch(
        path: impl AsRef<std::path::Path>,
        key: &Key,
        api: &LazyApi,
    ) -> anyhow::Result<Self> {
        if path.as_ref().exists() {
            Self::open(path, key)
        } else {
            Self::fetch(api).await
        }
    }

    pub fn open(path: impl AsRef<std::path::Path>, key: &Key) -> anyhow::Result<Self> {
        crate::crypto::open(path, key)
    }

    pub fn store(&self, path: impl AsRef<std::path::Path>, key: &Key) -> anyhow::Result<()> {
        crate::crypto::store(self, path, key)
    }

    pub fn query(&self, pattern: &str) -> impl Iterator<Item = &Password> {
        let pattern = pattern.to_lowercase();

        self.passwords.iter().filter(move |password| {
            password.versioned.url.to_lowercase().contains(&pattern)
                || password.versioned.label.to_lowercase().contains(&pattern)
        })
    }

    pub async fn fetch(api: &LazyApi) -> anyhow::Result<Self> {
        Ok(Self {
            passwords: api.get().await?.password().list(None).await?,
        })
    }
}
