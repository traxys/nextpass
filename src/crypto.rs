use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::Aes256Gcm;
use anyhow::Context;
use generic_array::{
    typenum::{U12, U32},
    GenericArray,
};

type Key = GenericArray<u8, U32>;

const SALT: &'static [u8] = b"powerwolf";

#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedData {
    nonce: GenericArray<u8, U12>,
    data: String,
}

pub fn hash_password(password: impl AsRef<[u8]>) -> anyhow::Result<Key> {
    let config = argon2::Config::default();
    Ok(Key::clone_from_slice(
        &argon2::hash_raw(password.as_ref(), SALT, &config)
            .with_context(|| "could not hash provided password")?[0..32],
    ))
}

fn gen_nonce() -> anyhow::Result<[u8; 12]> {
    let mut ret = [0; 12];
    getrandom::getrandom(&mut ret).with_context(|| "could fill random nonce")?;
    Ok(ret)
}

pub fn store<T: serde::Serialize>(
    item: &T,
    path: impl AsRef<std::path::Path>,
    password: &Key,
) -> anyhow::Result<()> {
    let repr = serde_json::to_vec(&item).with_context(|| "could not serialize item")?;
    let nonce = GenericArray::clone_from_slice(&gen_nonce()?);
    let cipher = Aes256Gcm::new(password);

    let data = EncryptedData {
        data: base64::encode(
            cipher
                .encrypt(&nonce, repr.as_ref())
                .map_err(|err| anyhow::anyhow!(format!("{}", err)))?,
        ),
        nonce,
    };
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)?;
    serde_json::to_writer(file, &data)?;
    Ok(())
}

pub fn open<T: serde::de::DeserializeOwned>(
    path: impl AsRef<std::path::Path>,
    password: &Key,
) -> anyhow::Result<T> {
    let file = std::fs::File::open(path).with_context(|| "could not open secret file")?;
    let cipher = Aes256Gcm::new(password);

    let data: EncryptedData =
        serde_json::from_reader(file).with_context(|| "could not read secret file")?;
    let item: T = serde_json::from_slice(
        &cipher
            .decrypt(
                &data.nonce,
                base64::decode(data.data)
                    .with_context(|| "could not decode base64 payload")?
                    .as_ref(),
            )
            .map_err(|_| anyhow::anyhow!("key could not open the secret"))?,
    )
    .with_context(|| "could not read decrypted secret")?;
    Ok(item)
}
