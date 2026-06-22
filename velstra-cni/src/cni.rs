//! CNI (Container Network Interface) wire types: the network config the runtime
//! passes on stdin, and the result/error we print back. See the CNI spec:
//! <https://github.com/containernetworking/cni/blob/main/SPEC.md>.

use serde::{Deserialize, Serialize};

/// The CNI versions this plugin understands.
pub const SUPPORTED_VERSIONS: &[&str] = &["0.3.1", "0.4.0", "1.0.0"];

/// Network configuration passed by the runtime on stdin. Unknown fields (e.g.
/// `prevResult`, `runtimeConfig`) are ignored.
#[derive(Debug, Deserialize)]
pub struct NetConf {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub name: String,
    /// The plugin binary name; part of the CNI schema but not used at runtime.
    #[serde(rename = "type")]
    #[allow(dead_code)]
    pub plugin_type: String,

    /// Pod subnet to allocate from, e.g. `"10.244.0.0/16"` (Velstra extension).
    pub subnet: Option<String>,
    /// Gateway address; defaults to the first usable address of `subnet`.
    pub gateway: Option<String>,
}

/// A successful ADD result (CNI `Result`).
#[derive(Debug, Serialize)]
pub struct CniResult {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub interfaces: Vec<Interface>,
    pub ips: Vec<IpConfig>,
    pub routes: Vec<Route>,
    pub dns: Dns,
}

#[derive(Debug, Serialize)]
pub struct Interface {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mac: String,
    pub sandbox: String,
}

#[derive(Debug, Serialize)]
pub struct IpConfig {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    pub interface: usize,
}

#[derive(Debug, Serialize)]
pub struct Route {
    pub dst: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gw: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct Dns {}

/// A CNI error object, printed to stdout with a non-zero exit on failure.
#[derive(Debug, Serialize)]
pub struct CniError {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub code: u32,
    pub msg: String,
}

impl CniError {
    /// Generic plugin error (CNI error code 7 = "try again later" is reserved;
    /// 100+ are plugin-specific — we use 100).
    pub fn new(cni_version: &str, msg: impl Into<String>) -> Self {
        Self {
            cni_version: cni_version.to_string(),
            code: 100,
            msg: msg.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_netconf_ignoring_unknown_fields() {
        let json = r#"{
            "cniVersion": "1.0.0",
            "name": "velstra",
            "type": "velstra-cni",
            "subnet": "10.244.0.0/16",
            "prevResult": {"whatever": true},
            "runtimeConfig": {"x": 1}
        }"#;
        let conf: NetConf = serde_json::from_str(json).unwrap();
        assert_eq!(conf.name, "velstra");
        assert_eq!(conf.subnet.as_deref(), Some("10.244.0.0/16"));
        assert_eq!(conf.gateway, None);
    }

    #[test]
    fn serializes_result_in_cni_shape() {
        let result = CniResult {
            cni_version: "1.0.0".into(),
            interfaces: vec![Interface {
                name: "eth0".into(),
                mac: String::new(),
                sandbox: "/var/run/netns/cni-1".into(),
            }],
            ips: vec![IpConfig {
                address: "10.244.0.5/16".into(),
                gateway: Some("10.244.0.1".into()),
                interface: 0,
            }],
            routes: vec![Route {
                dst: "0.0.0.0/0".into(),
                gw: None,
            }],
            dns: Dns::default(),
        };
        let v: serde_json::Value = serde_json::to_value(&result).unwrap();
        assert_eq!(v["cniVersion"], "1.0.0");
        assert_eq!(v["ips"][0]["address"], "10.244.0.5/16");
        assert_eq!(v["interfaces"][0]["name"], "eth0");
        // An empty MAC is omitted, not serialized as "".
        assert!(v["interfaces"][0].get("mac").is_none());
    }
}
