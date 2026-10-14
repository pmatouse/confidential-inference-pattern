// SPDX-License-Identifier: Apache-2.0
//! Guest-only SNP CPU test key provider. No listener or generic resource API.
//! Uses the pinned CoCo KBS protocol library behind an opaque authority permit.
use confidential_storage_client::{
    keys::{resource_uri, KeyPermit},
    AuthorityClient, Evidence,
};
use kbs_protocol::{evidence_provider::EvidenceProvider, KbsClientBuilder, KbsClientCapabilities};
use reqwest::{redirect, tls, Certificate, Url};
use std::{net::SocketAddr, time::Duration};
use zeroize::Zeroizing;

#[cfg(all(feature = "private-cdh", target_os = "linux"))]
pub mod private_cdh;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid measured storage KBS configuration")]
    Configuration,
    #[error("storage key authorization rejected")]
    Authorization,
    #[error("attested storage key retrieval failed")]
    Retrieval,
}
pub type Result<T> = std::result::Result<T, Error>;

/// All values must come from the measured boot configuration. Only the exact
/// resources listed here can be requested. GPU-required configurations fail.
pub struct Config {
    pub origin: String,
    pub certificate_der: Vec<u8>,
    pub address: Option<SocketAddr>,
    pub init_data_toml: String,
    pub allowed_resources: Vec<String>,
    pub require_gpu: bool,
}
/// Secret bytes are not Debug, Clone or serializable. The owned allocation is
/// wiped on drop; callers still must disable dumps/swap and avoid logging copies.
pub struct KeyMaterial(Zeroizing<Vec<u8>>);
impl KeyMaterial {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
pub struct SnpCpuKbs {
    config: Config,
    session: String,
    policy: String,
}
impl SnpCpuKbs {
    pub fn new<E: Evidence>(authority: &AuthorityClient<E>, config: Config) -> Result<Self> {
        let url = Url::parse(&config.origin).map_err(|_| Error::Configuration)?;
        let init_digest = initdata_digest(
            config.init_data_toml.as_bytes(),
            authority.init_data_digest(),
        )?;
        if config.require_gpu
            || url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.as_str().trim_end_matches('/') != config.origin
            || !config.origin.is_ascii()
            || config.init_data_toml.is_empty()
            || config.init_data_toml.len() > 64 * 1024
            || init_digest != authority.init_data_digest()
            || config.certificate_der.len() > 16384
            || config.allowed_resources.is_empty()
            || config.allowed_resources.len() > 16
            || config.allowed_resources.iter().any(|v| !resource_uri(v))
        {
            return Err(Error::Configuration);
        }
        Self::http(&config)?;
        Ok(Self {
            session: authority.session_sha256().into(),
            policy: authority.policy_sha256().into(),
            config,
        })
    }
    fn http(config: &Config) -> Result<reqwest::Client> {
        let url = Url::parse(&config.origin).map_err(|_| Error::Configuration)?;
        let certificate =
            Certificate::from_der(&config.certificate_der).map_err(|_| Error::Configuration)?;
        let mut builder = reqwest::Client::builder()
            .tls_certs_only([certificate])
            .min_tls_version(tls::Version::TLS_1_3)
            .max_tls_version(tls::Version::TLS_1_3)
            .https_only(true)
            .http1_only()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .cookie_store(true);
        if let Some(address) = config.address {
            builder = builder.resolve(url.host_str().unwrap(), address);
        }
        builder.build().map_err(|_| Error::Configuration)
    }
    /// Consumes a fresh permit; callers must authenticate the exact profile and
    /// sealed header before reopening. Each call creates a fresh RCAR/TEE key,
    /// without cached tokens or volume keys. Returned bytes are wiped on drop.
    pub async fn retrieve(&self, permit: KeyPermit) -> Result<KeyMaterial> {
        self.retrieve_inner(permit, Box::new(PrivateSnp)).await
    }
    async fn retrieve_inner(
        &self,
        permit: KeyPermit,
        provider: Box<dyn EvidenceProvider>,
    ) -> Result<KeyMaterial> {
        permit
            .check(&self.session, &self.policy, &self.config.allowed_resources)
            .map_err(|_| Error::Authorization)?;
        let mut client = KbsClientBuilder::with_evidence_provider(provider, &self.config.origin)
            .add_initdata(self.config.init_data_toml.clone())
            .with_http_client(Self::http(&self.config)?)
            .build()
            .map_err(|_| Error::Retrieval)?;
        let resource = permit
            .credential_uri()
            .try_into()
            .map_err(|_| Error::Authorization)?;
        let result = tokio::time::timeout(Duration::from_secs(25), client.get_resource(resource))
            .await
            .map_err(|_| Error::Retrieval)?
            .map_err(|_| Error::Retrieval)?;
        let key = Zeroizing::new(result);
        // Do not return a key if authorization expired while attestation ran.
        permit
            .check(&self.session, &self.policy, &self.config.allowed_resources)
            .map_err(|_| Error::Authorization)?;
        if key.len() != 32 {
            return Err(Error::Retrieval);
        }
        Ok(KeyMaterial(key))
    }
    /// Only for synthetic evidence fixtures. Exclude this feature from guests.
    #[cfg(feature = "test-fixture")]
    pub async fn retrieve_fixture(
        &self,
        permit: KeyPermit,
        provider: Box<dyn EvidenceProvider>,
    ) -> Result<KeyMaterial> {
        self.retrieve_inner(permit, provider).await
    }
}

/// Select from the administrator-pinned authority digest, never a server's
/// RCAR runtime-hash negotiation. Trustee separately parses the TOML algorithm
/// and verifies the resulting InitData against the hardware host_data binding.
fn initdata_digest(toml: &[u8], pinned_digest: &str) -> Result<String> {
    let algorithm = match pinned_digest.len() {
        64 => &ring::digest::SHA256,
        96 => &ring::digest::SHA384,
        128 => &ring::digest::SHA512,
        _ => return Err(Error::Configuration),
    };
    Ok(ring::digest::digest(algorithm, toml)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
struct PrivateSnp;
#[async_trait::async_trait]
impl EvidenceProvider for PrivateSnp {
    async fn primary_evidence(
        &self,
        runtime_data: Vec<u8>,
    ) -> kbs_protocol::Result<serde_json::Value> {
        let bytes = tokio::task::spawn_blocking(move || {
            confidential_storage_client::private_aa::PrivateAa.collect_digest(&runtime_data)
        })
        .await
        .map_err(|_| kbs_protocol::Error::AAEvidenceProvider("private collector failed".into()))?
        .map_err(|_| {
            kbs_protocol::Error::AAEvidenceProvider("private collector rejected".into())
        })?;
        serde_json::from_slice(&bytes).map_err(|_| {
            kbs_protocol::Error::AAEvidenceProvider("private evidence format rejected".into())
        })
    }
    async fn get_additional_evidence(
        &self,
        _runtime_data: Vec<u8>,
    ) -> kbs_protocol::Result<String> {
        Ok(String::new())
    }
    async fn get_tee_type(&self) -> kbs_protocol::Result<kbs_types::Tee> {
        Ok(kbs_types::Tee::Snp)
    }
}
