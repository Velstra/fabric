//! Per-caller authorization for the fabric-mutating admin/orchestrator surface
//! (H6). The admin/orchestrator channel carries writes — `AddHost`,
//! `CreatePort`, `MigratePort`, config overrides — that used to be authorized by
//! nothing more than "presented a cert signed by the shared CA". A single
//! agent's cert could therefore impersonate any host (idempotent `AddHost`) or
//! create ports on a node it doesn't own.
//!
//! This module scopes those writes to the caller's mTLS identity: the leaf
//! client-certificate Common Name. **Admin** CNs (operators/CI, listed at
//! startup) may perform any write; a **node** may only mutate its *own* host
//! (`CN == host-id`). Fleet-wide operations (networks, port migration between
//! hosts) are admin-only. When no policy is configured — the localhost-only
//! default with no client-CA — enforcement is off and every call is allowed, so
//! existing single-operator deployments are unchanged.

use std::collections::HashSet;

use tonic::Request;

/// Who is calling a mutating RPC, as established by the mTLS handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// A client that presented a certificate with this Common Name.
    Cert(String),
    /// No client certificate was presented (plaintext, or TLS without mTLS).
    Anonymous,
}

/// The authorization policy for the admin/orchestrator surface.
#[derive(Clone, Default)]
pub struct Authz {
    /// CNs allowed to perform ANY fabric write (operators / CI).
    admins: HashSet<String>,
    /// Whether authorization is enforced at all. Off ⇒ every call allowed
    /// (localhost-only default). On ⇒ callers must satisfy the rules below.
    enforced: bool,
}

impl Authz {
    /// A policy with `admins` allowed to do anything. `enforced` should be true
    /// whenever the admin channel requires client certs (mTLS) — that is the
    /// only configuration in which a caller identity exists to scope against.
    pub fn new(admins: impl IntoIterator<Item = String>, enforced: bool) -> Self {
        Self {
            admins: admins.into_iter().collect(),
            enforced,
        }
    }

    /// An open policy — authorization disabled (single-operator / localhost).
    pub fn disabled() -> Self {
        Self {
            admins: HashSet::new(),
            enforced: false,
        }
    }

    fn is_admin(&self, caller: &Caller) -> bool {
        matches!(caller, Caller::Cert(cn) if self.admins.contains(cn))
    }

    /// May `caller` perform a write scoped to a single host (`AddHost`,
    /// `RemoveHost`, `CreatePort`, per-node config)? Admins may write any host;
    /// a node may write only its own (`CN == host_id`).
    pub fn allow_host(&self, caller: &Caller, host_id: &str) -> bool {
        if !self.enforced {
            return true;
        }
        match caller {
            Caller::Cert(cn) => self.admins.contains(cn) || cn == host_id,
            Caller::Anonymous => false,
        }
    }

    /// May `caller` perform a fleet-wide write with no single owning host
    /// (`AddNetwork`/`RemoveNetwork`, `MigratePort`, `RemovePort`)? Admin-only.
    pub fn allow_admin(&self, caller: &Caller) -> bool {
        if !self.enforced {
            return true;
        }
        self.is_admin(caller)
    }
}

/// Extract the caller identity from a request's peer TLS certificates: the
/// Common Name of the leaf (first) client certificate. Absent certs, an
/// unparseable cert, or a cert with no CN all map to [`Caller::Anonymous`], which
/// an enforced policy denies.
pub fn caller_of<T>(req: &Request<T>) -> Caller {
    let Some(certs) = req.peer_certs() else {
        return Caller::Anonymous;
    };
    let Some(leaf) = certs.first() else {
        return Caller::Anonymous;
    };
    match common_name(leaf) {
        Some(cn) => Caller::Cert(cn),
        None => Caller::Anonymous,
    }
}

/// Parse a DER X.509 certificate and return its subject Common Name.
fn common_name(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin() -> Caller {
        Caller::Cert("ops-admin".into())
    }
    fn node(id: &str) -> Caller {
        Caller::Cert(id.into())
    }

    fn policy() -> Authz {
        Authz::new(["ops-admin".to_string()], true)
    }

    #[test]
    fn disabled_policy_allows_everything() {
        let a = Authz::disabled();
        assert!(a.allow_host(&Caller::Anonymous, "web-1"));
        assert!(a.allow_admin(&Caller::Anonymous));
    }

    #[test]
    fn admin_may_write_any_host_and_fleet_wide() {
        let a = policy();
        assert!(a.allow_host(&admin(), "web-1"));
        assert!(a.allow_host(&admin(), "db-9"));
        assert!(a.allow_admin(&admin()));
    }

    #[test]
    fn node_may_write_only_its_own_host() {
        let a = policy();
        assert!(a.allow_host(&node("web-1"), "web-1"));
        // A node cannot impersonate another host (the H6 hole).
        assert!(!a.allow_host(&node("web-1"), "db-9"));
        // …nor perform fleet-wide operations.
        assert!(!a.allow_admin(&node("web-1")));
    }

    #[test]
    fn anonymous_is_denied_when_enforced() {
        let a = policy();
        assert!(!a.allow_host(&Caller::Anonymous, "web-1"));
        assert!(!a.allow_admin(&Caller::Anonymous));
    }
}
