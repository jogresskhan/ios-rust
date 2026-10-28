//! BuildManifest.plist (RESTORE_STEPS + build identity keys) — minimal
//! plist-XML reader for the fields the restore flow consumes. Full plist
//! crate parity is a ledger item; this covers dict/string/array-of-string.

use serde_json::{Map, Value};

pub fn parse_plist_xml(buf: &[u8]) -> Result<Map<String, Value>, String> {
    let text = std::str::from_utf8(buf).map_err(|_| "not utf8")?;
    // Extract <dict>…</dict> at plist root and parse flat string/arrays.
    let start = text.find("<dict>").ok_or("no <dict>")?;
    let end = text.rfind("</dict>").ok_or("no closing </dict>")?;
    let inner = &text[start + 6..end];
    parse_dict_inner(inner)
}

fn parse_dict_inner(inner: &str) -> Result<Map<String, Value>, String> {
    let mut map = Map::new();
    let mut rest = inner.trim();
    while let Some(kpos) = rest.find("<key>") {
        rest = &rest[kpos + 5..];
        let kend = rest.find("</key>").ok_or("unclosed <key>")?;
        let key = rest[..kend].to_string();
        rest = rest[kend + 6..].trim_start();

        // Dispatch on the VALUE TYPE by prefix, not by searching ahead —
        // a later <array> must not hijack a <string> value.
        if let Some(v) = rest.strip_prefix("<array>") {
            let vend = v.find("</array>").ok_or("unclosed <array>")?;
            let items: Vec<Value> = v[..vend]
                .split("</string>")
                .filter_map(|seg| {
                    seg.find("<string>").map(|s| Value::String(seg[s + 8..].trim().to_string()))
                })
                .collect();
            map.insert(key, Value::Array(items));
            rest = v[vend + 8..].trim_start();
        } else if let Some(v) = rest.strip_prefix("<string>") {
            let vend = v.find("</string>").ok_or("unclosed <string>")?;
            map.insert(key, Value::String(v[..vend].to_string()));
            rest = v[vend + 9..].trim_start();
        } else if let Some(v) = rest.strip_prefix("<integer>") {
            let vend = v.find("</integer>").ok_or("unclosed <integer>")?;
            let n: i64 = v[..vend].trim().parse().unwrap_or(0);
            map.insert(key, serde_json::json!(n));
            rest = v[vend + 10..].trim_start();
        } else if rest.starts_with("<true/>") {
            map.insert(key, Value::Bool(true));
            rest = rest[7..].trim_start();
        } else if rest.starts_with("<false/>") {
            map.insert(key, Value::Bool(false));
            rest = rest[8..].trim_start();
        } else {
            return Err(format!("unsupported plist value near key '{key}'"));
        }
    }
    Ok(map)
}

/// The restore-stage list the lane greps for (RESTORE_STEPS ordering).
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
    </dict></plist>"#;

    #[test]
    fn parses_manifest_fields() {
        let m = parse_plist_xml(SAMPLE.as_bytes()).unwrap();
        assert_eq!(m.get("ProductBuildVersion").unwrap().as_str().unwrap(), "18A5357e");
        let steps = restore_steps(&m);
        assert_eq!(steps, vec!["Cleanup", "ASR", "CreatePartitionMap"]);
        assert_eq!(m.get("Chin_SIZE").unwrap().as_i64().unwrap(), 4096);
    }
}
