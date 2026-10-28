//! plist — libplist subset: Apple **XML** property lists (parse + serialize).
//!
//! This is the transport encoding for the whole pure-Rust restore host:
//! usbmuxd plist packets (`plist_to_xml` in libusbmuxd), the restored
//! protocol (`property_list_service_send_xml_plist`) and ASR
//! (`plist_from_xml` in idevicerestore asr.c) are all XML plists, so one
//! dependency-free engine covers every X-row protocol.
//!
//! Parity: `libplist subset` row — dict/array/string/integer/real/bool/
//! data(base64)/date, entity escaping, order-preserving dicts.
//! Gate to 100: binary plist (bplist00) reader (not used by these lanes).

/// Property-list value (order-preserving dictionaries, like libplist).
#[derive(Debug, Clone)]
pub enum Value {
    Dictionary(Vec<(String, Value)>),
    Array(Vec<Value>),
    String(String),
    Integer(i64),
    UInteger(u64),
    Real(f64),
    Boolean(bool),
    Data(Vec<u8>),
    /// ISO-8601 date kept verbatim (no restore lane consumes dates).
    Date(String),
}

impl PartialEq for Value {
    /// Semantic equality: Integer/UInteger compare numerically, Real by bits.
    fn eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Dictionary(a), Value::Dictionary(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Real(a), Value::Real(b)) => a.to_bits() == b.to_bits(),
            (Value::Boolean(a), Value::Boolean(b)) => a == b,
            (Value::Data(a), Value::Data(b)) => a == b,
            (Value::Date(a), Value::Date(b)) => a == b,
            (a, b) => match (a.as_int(), b.as_int(), a.as_uint(), b.as_uint()) {
                (Some(x), Some(y), _, _) => x == y,
                (_, _, Some(x), Some(y)) => x == y,
                _ => false,
            },
        }
    }
}

impl Value {
    /// dict lookup (first match).
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dictionary(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Dictionary(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Integer or UInteger, unified.
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::Integer(i) if *i >= 0 => Some(*i as u64),
            Value::UInteger(u) => Some(*u),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            Value::UInteger(u) if *u <= i64::MAX as u64 => Some(*u as i64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            Value::Data(d) => Some(d),
            _ => None,
        }
    }

    /// dict insert-or-replace (keeps position on replace).
    pub fn set(&mut self, key: &str, value: Value) {
        if let Value::Dictionary(entries) = self {
            for (k, v) in entries.iter_mut() {
                if k == key {
                    *v = value;
                    return;
                }
            }
            entries.push((key.to_string(), value));
        }
    }
}

// ---------------------------------------------------------------------------
// base64 (shared by <data> and the TSS ticket paths)
// ---------------------------------------------------------------------------

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let end = clean.iter().position(|&b| b == b'=').unwrap_or(clean.len());
    let clean = &clean[..end];
    let mut out = Vec::with_capacity(clean.len() / 4 * 3 + 3);
    for chunk in clean.chunks(4) {
        if chunk.len() == 1 {
            return Err("base64: dangling single character".into());
        }
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = b64_val(c).ok_or_else(|| format!("base64: invalid character {c:?}"))?;
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// XML escaping
// ---------------------------------------------------------------------------

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn xml_unescape(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        let end = tail
            .find(';')
            .ok_or_else(|| "xml: unterminated entity".to_string())?;
        let ent = &tail[1..end];
        match ent {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                let val = if let Some(hex) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                    u32::from_str_radix(hex, 16).ok()
                } else if let Some(dec) = ent.strip_prefix('#') {
                    dec.parse::<u32>().ok()
                } else {
                    None
                };
                let ch = val
                    .and_then(char::from_u32)
                    .ok_or_else(|| format!("xml: bad entity &{ent};"))?;
                out.push(ch);
            }
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse an XML property list (the `<?xml …?><plist version="1.0">…</plist>`
/// shape used by usbmuxd, restored and ASR).
pub fn parse(buf: &[u8]) -> Result<Value, String> {
    let (value, consumed) = parse_prefix(buf)?;
    if consumed != buf.len() {
        return Err(format!("plist: trailing data at byte {consumed}"));
    }
    Ok(value)
}

/// Parse the FIRST plist in `buf`, returning it plus the consumed byte count.
///
/// TCP coalescing can deliver two ASR control plists in one read burst
/// (upstream reads one USB packet per plist; TCP does not preserve that), so
/// stream readers must consume exactly one message and keep the remainder
/// buffered. Trailing whitespace after the root element is insignificant.
pub fn parse_prefix(buf: &[u8]) -> Result<(Value, usize), String> {
    let text = std::str::from_utf8(buf).map_err(|e| format!("plist: not utf8: {e}"))?;
    let mut p = Parser { s: text, i: 0 };
    p.skip_prolog()?;
    p.expect_open("plist")?;
    let value = p.parse_value()?;
    p.skip_ws_and_comments();
    p.expect_close("plist")?;
    p.skip_ws_and_comments();
    Ok((value, p.i))
}

struct Parser<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws_and_comments(&mut self) {
        loop {
            while self.i < self.s.len() && self.s[self.i..].starts_with(char::is_whitespace) {
                self.i += 1;
            }
            if self.s[self.i..].starts_with("<!--") {
                match self.s[self.i..].find("-->") {
                    Some(end) => self.i += end + 3,
                    None => break,
                }
            } else {
                break;
            }
        }
    }

    /// Skip `<?xml …?>`, `<!DOCTYPE …>` and comments before the root tag.
    fn skip_prolog(&mut self) -> Result<(), String> {
        loop {
            self.skip_ws_and_comments();
            if self.s[self.i..].starts_with("<?") {
                let end = self
                    .s[self.i..]
                    .find("?>")
                    .ok_or("plist: unterminated processing instruction")?;
                self.i += end + 2;
            } else if self.s[self.i..].starts_with("<!") {
                let end = self
                    .s[self.i..]
                    .find('>')
                    .ok_or("plist: unterminated declaration")?;
                self.i += end + 1;
            } else {
                return Ok(());
            }
        }
    }

    /// Consume `<name attr…>` or `<name/>`; returns (tag name, self-closing).
    fn open_tag(&mut self) -> Result<(String, bool), String> {
        self.skip_ws_and_comments();
        if !self.s[self.i..].starts_with('<') {
            return Err("plist: expected an element".into());
        }
        let rest = &self.s[self.i..];
        let tag_end = rest.find('>').ok_or("plist: unterminated tag")?;
        let inner = &rest[1..tag_end];
        let self_closing = inner.ends_with('/');
        let inner = inner.strip_suffix('/').unwrap_or(inner);
        let tag = inner.split_whitespace().next().unwrap_or("").to_string();
        if tag.is_empty() {
            return Err("plist: empty tag".into());
        }
        self.i += tag_end + 1;
        Ok((tag, self_closing))
    }

    /// Consume `<name attr…>` and validate the tag name.
    fn expect_open(&mut self, name: &str) -> Result<bool, String> {
        let (tag, self_closing) = self.open_tag()?;
        if tag != name {
            return Err(format!("plist: expected <{name}>, found <{tag}>"));
        }
        Ok(self_closing)
    }

    fn expect_close(&mut self, name: &str) -> Result<(), String> {
        self.skip_ws_and_comments();
        let close = format!("</{name}>");
        if self.s[self.i..].starts_with(&close) {
            self.i += close.len();
            Ok(())
        } else {
            Err(format!("plist: expected </{name}> at byte {}", self.i))
        }
    }

    fn text_until(&mut self, close_tag: &str) -> Result<String, String> {
        let end = self
            .s[self.i..]
            .find(close_tag)
            .ok_or_else(|| format!("plist: missing {close_tag}"))?;
        let text = &self.s[self.i..self.i + end];
        self.i += end;
        Ok(text.to_string())
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        let (name, self_closing) = self.open_tag()?;
        match name.as_str() {
            "dict" => self.parse_dict_body(self_closing),
            "array" => self.parse_array_body(self_closing),
            "string" => {
                let v = if self_closing {
                    String::new()
                } else {
                    let raw = self.text_until("</string>")?;
                    self.expect_close("string")?;
                    xml_unescape(&raw)?
                };
                Ok(Value::String(v))
            }
            "integer" => {
                if self_closing {
                    return Err("plist: empty <integer/>".into());
                }
                let raw = self.text_until("</integer>")?;
                self.expect_close("integer")?;
                let raw = raw.trim();
                if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
                    let v = u64::from_str_radix(hex, 16)
                        .map_err(|e| format!("plist: integer {raw}: {e}"))?;
                    Ok(Value::UInteger(v))
                } else if let Ok(v) = raw.parse::<u64>() {
                    Ok(if v <= i64::MAX as u64 {
                        Value::Integer(v as i64)
                    } else {
                        Value::UInteger(v)
                    })
                } else {
                    let v = raw
                        .parse::<i64>()
                        .map_err(|e| format!("plist: integer {raw}: {e}"))?;
                    Ok(Value::Integer(v))
                }
            }
            "real" => {
                if self_closing {
                    return Err("plist: empty <real/>".into());
                }
                let raw = self.text_until("</real>")?;
                self.expect_close("real")?;
                let v = raw
                    .trim()
                    .parse::<f64>()
                    .map_err(|e| format!("plist: real {raw}: {e}"))?;
                Ok(Value::Real(v))
            }
            "true" => {
                if !self_closing {
                    self.expect_close("true")?;
                }
                Ok(Value::Boolean(true))
            }
            "false" => {
                if !self_closing {
                    self.expect_close("false")?;
                }
                Ok(Value::Boolean(false))
            }
            "data" => {
                if self_closing {
                    return Ok(Value::Data(Vec::new()));
                }
                let raw = self.text_until("</data>")?;
                self.expect_close("data")?;
                Ok(Value::Data(base64_decode(&raw)?))
            }
            "date" => {
                if self_closing {
                    return Ok(Value::Date(String::new()));
                }
                let raw = self.text_until("</date>")?;
                self.expect_close("date")?;
                Ok(Value::Date(raw.trim().to_string()))
            }
            other => Err(format!("plist: unknown element <{other}>")),
        }
    }

    fn parse_dict_body(&mut self, self_closing: bool) -> Result<Value, String> {
        let mut entries = Vec::new();
        if !self_closing {
            loop {
                self.skip_ws_and_comments();
                if self.s[self.i..].starts_with("</dict>") {
                    self.expect_close("dict")?;
                    break;
                }
                self.expect_open("key")?;
                let raw = self.text_until("</key>")?;
                self.expect_close("key")?;
                let key = xml_unescape(&raw)?;
                let value = self.parse_value()?;
                entries.push((key, value));
            }
        }
        Ok(Value::Dictionary(entries))
    }

    fn parse_array_body(&mut self, self_closing: bool) -> Result<Value, String> {
        let mut items = Vec::new();
        if !self_closing {
            loop {
                self.skip_ws_and_comments();
                if self.s[self.i..].starts_with("</array>") {
                    self.expect_close("array")?;
                    break;
                }
                items.push(self.parse_value()?);
            }
        }
        Ok(Value::Array(items))
    }
}

// ---------------------------------------------------------------------------
// Serializer
// ---------------------------------------------------------------------------

/// Serialize as the canonical Apple XML plist (header + `<plist version="1.0">`).
pub fn to_string(value: &Value) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ");
    out.push_str("\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    out.push_str("<plist version=\"1.0\">\n");
    write_value(value, 0, &mut out);
    out.push_str("</plist>\n");
    out
}

fn indent(depth: usize) -> String {
    "  ".repeat(depth)
}

fn write_value(value: &Value, depth: usize, out: &mut String) {
    match value {
        Value::Dictionary(entries) => {
            if entries.is_empty() {
                out.push_str(&indent(depth));
                out.push_str("<dict/>\n");
                return;
            }
            out.push_str(&indent(depth));
            out.push_str("<dict>\n");
            for (k, v) in entries {
                out.push_str(&indent(depth + 1));
                out.push_str("<key>");
                out.push_str(&xml_escape(k));
                out.push_str("</key>\n");
                write_value(v, depth + 1, out);
            }
            out.push_str(&indent(depth));
            out.push_str("</dict>\n");
        }
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str(&indent(depth));
                out.push_str("<array/>\n");
                return;
            }
            out.push_str(&indent(depth));
            out.push_str("<array>\n");
            for v in items {
                write_value(v, depth + 1, out);
            }
            out.push_str(&indent(depth));
            out.push_str("</array>\n");
        }
        Value::String(s) => {
            out.push_str(&indent(depth));
            out.push_str("<string>");
            out.push_str(&xml_escape(s));
            out.push_str("</string>\n");
        }
        Value::Integer(i) => {
            out.push_str(&indent(depth));
            out.push_str(&format!("<integer>{i}</integer>\n"));
        }
        Value::UInteger(u) => {
            out.push_str(&indent(depth));
            out.push_str(&format!("<integer>{u}</integer>\n"));
        }
        Value::Real(f) => {
            out.push_str(&indent(depth));
            out.push_str(&format!("<real>{f}</real>\n"));
        }
        Value::Boolean(b) => {
            out.push_str(&indent(depth));
            out.push_str(if *b { "<true/>\n" } else { "<false/>\n" });
        }
        Value::Data(d) => {
            out.push_str(&indent(depth));
            out.push_str("<data>");
            // Apple wraps base64 in <data> across lines; single-line is valid.
            out.push_str(&base64_encode(d));
            out.push_str("</data>\n");
        }
        Value::Date(d) => {
            out.push_str(&indent(depth));
            out.push_str(&format!("<date>{d}</date>\n"));
        }
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        Value::Dictionary(vec![
            ("Command".into(), Value::String("Initiate".into())),
            ("Checksum Chunks".into(), Value::Boolean(true)),
            (
                "Payload".into(),
                Value::Dictionary(vec![
                    ("Port".into(), Value::UInteger(1)),
                    ("Size".into(), Value::UInteger(0x1234_5678_9abc)),
                ]),
            ),
            ("Ticket".into(), Value::Data(b"IM4M-TEST".to_vec())),
            (
                "Flags".into(),
                Value::Array(vec![
                    Value::Integer(-1),
                    Value::Boolean(false),
                    Value::String("a<b&c>d".into()),
                ]),
            ),
        ])
    }

    #[test]
    fn roundtrip_sample() {
        let v = sample();
        let s = to_string(&v);
        let back = parse(s.as_bytes()).expect("parse own output");
        assert_eq!(v, back);
    }

    #[test]
    fn parses_real_world_headers_and_entities() {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                   <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
                   \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                   <plist version=\"1.0\">\n\
                   <dict>\n\
                     <key>Type</key><string>com.apple.mobile.restored</string>\n\
                     <key>RestoreProtocolVersion</key><integer>0x0e</integer>\n\
                     <key>Note</key><string>a &amp; b &lt;c&gt;</string>\n\
                     <key>Big</key><integer>18446744073709551615</integer>\n\
                     <key>Neg</key><integer>-42</integer>\n\
                     <key>Empty</key><dict/><key>List</key><array/>\n\
                   </dict>\n\
                   </plist>";
        let v = parse(xml.as_bytes()).expect("parse");
        assert_eq!(
            v.get("Type").and_then(|t| t.as_string()),
            Some("com.apple.mobile.restored")
        );
        assert_eq!(
            v.get("RestoreProtocolVersion").and_then(|t| t.as_uint()),
            Some(14)
        );
        assert_eq!(v.get("Note").and_then(|t| t.as_string()), Some("a & b <c>"));
        assert_eq!(v.get("Big").and_then(|t| t.as_uint()), Some(u64::MAX));
        assert_eq!(v.get("Neg").and_then(|t| t.as_int()), Some(-42));
        assert_eq!(v.get("Empty"), Some(&Value::Dictionary(Vec::new())));
        assert_eq!(v.get("List"), Some(&Value::Array(Vec::new())));
    }

    #[test]
    fn data_base64_roundtrip() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let v = Value::Data(payload.clone());
        let back = parse(to_string(&v).as_bytes()).expect("parse");
        assert_eq!(back.as_data(), Some(payload.as_slice()));
    }

    #[test]
    fn parse_prefix_consumes_exactly_one_message() {
        let a = to_string(&Value::Dictionary(vec![("n".into(), Value::Integer(1))]));
        let b = to_string(&Value::Dictionary(vec![("n".into(), Value::Integer(2))]));
        let mut joined = a.clone();
        joined.push_str(&b);
        let (v, consumed) = parse_prefix(joined.as_bytes()).expect("first plist");
        assert_eq!(v.get("n").and_then(|n| n.as_int()), Some(1));
        assert_eq!(consumed, a.len());
        let (v2, consumed2) = parse_prefix(&joined.as_bytes()[consumed..]).expect("second plist");
        assert_eq!(v2.get("n").and_then(|n| n.as_int()), Some(2));
        assert_eq!(consumed2, b.len());
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(base64_decode("Zm9v\nYmFy\n").unwrap(), b"foobar");
        assert!(base64_decode("Z*9v").is_err());
    }

    #[test]
    fn escape_and_entity_roundtrip() {
        let tricky = "<key>&</key><value>'\"</value> \u{1F4A1}";
        let v = Value::String(tricky.to_string());
        let back = parse(to_string(&v).as_bytes()).expect("parse");
        assert_eq!(back, Value::String(tricky.to_string()));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(b"").is_err());
        assert!(parse(b"<plist><dict></dict>").is_err()); // missing </plist>
        assert!(parse(b"<plist><nope/></plist>").is_err());
        assert!(parse(b"<plist><dict><key>k</key></dict></plist>").is_err()); // missing value
    }

    #[test]
    fn dict_set_preserves_order() {
        let mut d = Value::Dictionary(vec![("a".into(), Value::Integer(1))]);
        d.set("b", Value::Integer(2));
        d.set("a", Value::Integer(3));
        match &d {
            Value::Dictionary(entries) => {
                assert_eq!(entries[0].0, "a");
                assert_eq!(entries[1].0, "b");
                assert_eq!(entries[0].1, Value::Integer(3));
            }
            _ => panic!("not a dict"),
        }
    }
}
