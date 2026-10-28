//! BuildManifest.plist — parse via the hardened `plist_lite` XML codec
//! (hex integers, paired booleans, comments, self-closing tags — all added
//! for the REAL T8030 iOS 13.7 manifest) and convert to the serde_json
//! shape the restore flow consumes.

use serde_json::{Map, Value};
use restore::plist_lite::Plist;

fn plist_to_json(p: &Plist) -> Value {
    match p {
        Plist::Str(s) => Value::String(s.clone()),
        Plist::UInt(n) => serde_json::json!(n),
        Plist::Bool(b) => Value::Bool(*b),
        Plist::Data(d) => serde_json::json!(d.iter().map(|b| format!("{b:02x}")).collect::<String>()),
        Plist::Array(a) => Value::Array(a.iter().map(plist_to_json).collect()),
        Plist::Dict(d) => {
            let mut m = Map::new();
            for (k, v) in d {
                m.insert(k.clone(), plist_to_json(v));
            }
            Value::Object(m)
        }
    }
}

pub fn parse_plist_xml(buf: &[u8]) -> Result<Map<String, Value>, String> {
    let text = std::str::from_utf8(buf).map_err(|_| "not utf8")?;
    let parsed = restore::plist_lite::from_xml(text)?;
    match plist_to_json(&parsed) {
        Value::Object(m) => Ok(m),
        other => Err(format!("BuildManifest root is not a dict: {other}")),
    }
}

pub fn restore_steps(m: &Map<String, Value>) -> Vec<String> {
    m.get("RestoreSteps")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0"?><plist><dict>
      <key>ProductBuildVersion</key><string>18A5357e</string>
      <key>RestoreSteps</key>
      <array>
        <string>Cleanup</string>
        <string>ASR</string>
        <string>CreatePartitionMap</string>
      </array>
      <key>Chin_SIZE</key><integer>4096</integer>
      <key>PairedFlag</key><true></true>
      <key>Digest</key><data>AAECAw==</data>
    </dict></plist>"#;

    #[test]
    fn parses_manifest_fields() {
        let m = parse_plist_xml(SAMPLE.as_bytes()).unwrap();
        assert_eq!(m.get("ProductBuildVersion").unwrap().as_str().unwrap(), "18A5357e");
        let steps = restore_steps(&m);
        assert_eq!(steps, vec!["Cleanup", "ASR", "CreatePartitionMap"]);
        assert_eq!(m.get("Chin_SIZE").unwrap().as_i64().unwrap(), 4096);
        assert_eq!(m.get("PairedFlag").unwrap().as_bool(), Some(true));
        assert_eq!(m.get("Digest").unwrap().as_str(), Some("00010203"));
    }
}
