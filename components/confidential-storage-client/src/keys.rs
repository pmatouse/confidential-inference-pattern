// SPDX-License-Identifier: Apache-2.0
//! Opaque, short-lived authorization for the measured in-process key provider.
//! No network endpoint and no key bytes are exposed by this module.
use crate::{now, AuthorityClient, Error, Evidence, Result};
use confidential_storage_guest::receipt::{Expected, VerifiedGrant};

/// Constructed only by a fresh, verified authority response. Not Clone,
/// Deserialize or Debug. The key provider consumes it and rechecks expiry.
pub struct KeyPermit {
    session: String,
    policy: String,
    credential_uri: String,
    expires: u64,
}
impl KeyPermit {
    pub(crate) fn new(
        session: String,
        policy: String,
        credential_uri: String,
        expires: u64,
    ) -> Result<Self> {
        if !resource_uri(&credential_uri) || expires <= now()? {
            return Err(Error::Binding);
        }
        Ok(Self {
            session,
            policy,
            credential_uri,
            expires,
        })
    }
    pub fn check(&self, session: &str, policy: &str, allowed_resources: &[String]) -> Result<()> {
        if self.session != session
            || self.policy != policy
            || now()? >= self.expires
            || !allowed_resources.contains(&self.credential_uri)
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn credential_uri(&self) -> &str {
        &self.credential_uri
    }
}

/// Restrict storage credentials to an exact authority-less KBS resource ID.
/// No alternate host/plugin, query, encoding, traversal or endpoint selection.
pub fn resource_uri(value: &str) -> bool {
    let Some(path) = value.strip_prefix("kbs:///") else {
        return false;
    };
    let fields: Vec<_> = path.split('/').collect();
    value.len() <= 256
        && fields.len() == 3
        && fields.iter().all(|f| {
            !f.is_empty()
                && *f != "."
                && *f != ".."
                && f.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
}

impl<E: Evidence> AuthorityClient<E> {
    /// Obtain a new authority response for this retained session/request. A stale
    /// or caller-constructed grant cannot be turned into a key permit.
    pub fn authorize_reopen_key(&self, expected: &Expected) -> Result<(VerifiedGrant, KeyPermit)> {
        let profile_ok = match expected.access.as_str() {
            "rw" => confidential_storage_guest::profile::supports_binding(
                &expected.profile_sha256,
                &expected.destination,
            ),
            "ro" => confidential_storage_guest::ro_profile::supports_binding(
                &expected.profile_sha256,
                &expected.destination,
            ),
            _ => false,
        };
        if !profile_ok {
            return Err(Error::Binding);
        }
        let grant = self.reopen(expected)?;
        let c = grant.claims();
        let permit = KeyPermit::new(
            self.session.clone(),
            self.config.policy_sha256.clone(),
            c.credential_uri.clone(),
            c.exp,
        )?;
        Ok((grant, permit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resource_ids_cannot_select_endpoints_or_paths() {
        assert!(resource_uri("kbs:///storage-test/keys/model-v1"));
        for v in [
            "https://kbs/key",
            "kbs://evil/storage-test/keys/v1",
            "kbs:///a/b/c?x=y",
            "kbs:///a/b/..",
            "kbs:///a/b/%2f",
            "kbs:///a/b/c/d",
            "kbs:///a//c",
        ] {
            assert!(!resource_uri(v));
        }
    }
    #[test]
    fn permits_require_retained_session_policy_allowlist_and_time() {
        let uri = "kbs:///test/keys/v1".to_string();
        let mut p = KeyPermit::new(
            "a".repeat(64),
            "b".repeat(64),
            uri.clone(),
            now().unwrap() + 60,
        )
        .unwrap();
        assert!(p
            .check(&"a".repeat(64), &"b".repeat(64), std::slice::from_ref(&uri))
            .is_ok());
        assert!(p
            .check(&"c".repeat(64), &"b".repeat(64), std::slice::from_ref(&uri))
            .is_err());
        assert!(p
            .check(&"a".repeat(64), &"c".repeat(64), std::slice::from_ref(&uri))
            .is_err());
        assert!(p.check(&"a".repeat(64), &"b".repeat(64), &[]).is_err());
        p.expires = 0;
        assert!(p.check(&"a".repeat(64), &"b".repeat(64), &[uri]).is_err());
    }
}
