//! plist_lite — minimal XML property-list codec for the restore wire protocols.
//!
//! The restore-path daemons (`usbmuxd`, `restored`, `asr`, TSS) exchange XML
//! plists on the wire (libusbmuxd and asr.c both emit `plist_to_xml`). This
//! module implements the exact subset those protocols use — dict / array /
//! string / integer / boolean / base64 data — with the canonical libplist
//! XML header so peers see byte-identical envelopes.
//!
//! Parity: libplist subset (libplist `plist.c` XML serialization), mirroring
//! the "libplist flat reader" row already in PARITY.md; read+write instead of
//! read-only.

use std::collections::BTreeMap;

/// A plist value: the subset used by usbmuxd / restored / ASR / TSS messages.
#[derive(Debug, Clone, PartialEq)]
pub enum Plist {
    /// `<dict>` (sorted keys for canonical output — the TSS server requires
    /// lexicographic key order, which `BTreeMap` gives for free).
    Dict(BTreeMap<String, Plist>),
    /// `<array>`.
    Array(Vec<Plist>),
    /// `<string>`.
    Str(String),
    /// `<integer>` (unsigned; the wire never carries restore-path negatives).
    UInt(u64),
    /// `<true/>` / `<false/>`.
    Bool(bool),
    /// `<data>` (base64 in XML, raw bytes here).
    Data(Vec<u8>),
}

const XML_HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n";

/// Encode a value to canonical XML plist bytes (header + `<plist>` envelope),
/// as libplist's `plist_to_xml` would emit for the same tree.
pub fn to_xml(v: &Plist) -> String {
    let mut out = String::from(XML_HEADER);
    write_node(v, &mut out, 0);
    out.push_str("</plist>\n");
    out
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push('\t');
    }
}

fn write_node(v: &Plist, out: &mut String, depth: usize) {
    match v {
        Plist::Dict(map) => {
            out.push_str("<dict>\n");
            for (k, val) in map {
                indent(out, depth + 1);
                out.push_str("<key>");
                out.push_str(&escape(k));
                out.push_str("</key>\n");
                indent(out, depth + 1);
                write_node(val, out, depth + 1);
                out.push('\n');
            }
            indent(out, depth);
            out.push_str("</dict>");
        }
        Plist::Array(items) => {
            out.push_str("<array>\n");
            for item in items {
                indent(out, depth + 1);
                write_node(item, out, depth + 1);
                out.push('\n');
            }
            indent(out, depth);
            out.push_str("</array>");
        }
        Plist::Str(s) => {
            out.push_str("<string>");
            out.push_str(&escape(s));
            out.push_str("</string>");
        }
        Plist::UInt(n) => {
            out.push_str(&format!("<integer>{n}</integer>"));
        }
        Plist::Bool(b) => {
            out.push_str(if *b { "<true/>" } else { "<false/>" });
        }
        Plist::Data(bytes) => {
            out.push_str("<data>");
            out.push_str(&base64_encode(bytes));
            out.push_str("</data>");
        }
    }
}

/// XML-escape the five predefined entities (plist strings never carry
/// control characters in these protocols).
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Parse an XML plist: full libplist-style envelope (with `<?xml`/DOCTYPE
/// preamble and `<plist>` wrapper) or a bare value. Scans elements directly —
/// no DTD validation. Unknown element types (`<real>`, `<date>`, …) are an
/// error rather than silent data loss.
pub fn from_xml(xml: &str) -> Result<Plist, String> {
    let mut p = Parser { s: xml, pos: 0 };
    p.skip_preamble();
    p.skip_ws();
    let rest = p
        .s
        .get(p.pos..)
        .ok_or_else(|| "plist: unexpected end of input".to_string())?;
    if rest.starts_with("<plist") {
        // Unwrap the envelope: consume the opening tag, parse the inner
        // value, then require the matching close.
        let gt = rest.find('>').ok_or("plist: unterminated <plist>")?;
        p.pos += gt + 1;
        p.skip_ws();
        let v = p.parse_value()?;
        p.skip_ws();
        let rest = p
            .s
            .get(p.pos..)
            .ok_or_else(|| "plist: unexpected end of input".to_string())?;
        let tail = rest
            .strip_prefix("</plist>")
            .ok_or_else(|| format!("plist: expected </plist> at byte {}", p.pos))?;
        p.pos = p.s.len() - tail.len();
        p.skip_ws();
        if p.pos != p.s.len() {
            return Err(format!(
                "plist: trailing data after </plist> at byte {}",
                p.pos
            ));
        }
        return Ok(v);
    }
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.s.len() {
        return Err(format!("plist: trailing data after value at byte {}", p.pos));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while let Some(rest) = self.s.get(self.pos..) {
            let trimmed = rest.trim_start();
            if trimmed.len() == rest.len() {
                break;
            }
            self.pos += rest.len() - trimmed.len();
        }
    }

    /// skip_ws plus inline `<!-- … -->` comments (real Apple plists
    /// interleave comments anywhere between elements).
    fn skip_ws_comments(&mut self) {
        loop {
            self.skip_ws();
            let Some(rest) = self.s.get(self.pos..) else { return };
            if rest.starts_with("<!--") {
                match rest.find("-->") {
                    Some(i) => self.pos += i + 3,
                    None => self.pos = self.s.len(),
                }
            } else {
                return;
            }
        }
    }

    /// Consume `<?xml …?>`, `<!DOCTYPE …>`, and `<!-- … -->` preambles.
    fn skip_preamble(&mut self) {
        loop {
            self.skip_ws();
            let rest = match self.s.get(self.pos..) {
                Some(r) => r,
                None => return,
            };
            if rest.starts_with("<?") {
                match rest.find("?>") {
                    Some(i) => self.pos += i + 2,
                    None => self.pos = self.s.len(),
                }
            } else if rest.starts_with("<!--") {
                match rest.find("-->") {
                    Some(i) => self.pos += i + 3,
                    None => self.pos = self.s.len(),
                }
            } else if rest.starts_with("<!DOCTYPE") {
                match rest.find('>') {
                    Some(i) => self.pos += i + 1,
                    None => self.pos = self.s.len(),
                }
            } else {
                return;
            }
        }
    }

    /// Consume the next opening tag name (after the `<`). Returns
    /// `(name, self_closing)` — real Apple plists use empty containers
    /// like `<array/>` / `<dict/>` (found on the T8030 iOS 13.7
    /// __PRELINK_INFO.__info).
    fn next_tag(&mut self) -> Result<(&'a str, bool), String> {
        self.skip_ws_comments();
        // Real Apple plists (e.g. the T8030 iOS 13.7 __PRELINK_INFO.__info)
        // interleave `<!-- … -->` comments between elements, not just in
        // the preamble — skip them inline.
        while let Some(rest) = self.s.get(self.pos..) {
            if rest.starts_with("<!--") {
                match rest.find("-->") {
                    Some(i) => self.pos += i + 3,
                    None => return Err("plist: unterminated comment".into()),
                }
                self.skip_ws();
            } else {
                break;
            }
        }
        let rest = self
            .s
            .get(self.pos..)
            .ok_or_else(|| "plist: unexpected end of input".to_string())?;
        let rest = rest
            .strip_prefix('<')
            .ok_or_else(|| format!("plist: expected '<' at byte {}", self.pos))?;
        self.pos += 1;
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(rest.len());
        let name = &rest[..end];
        // Skip past the rest of the opening tag ("attrs>" or ">" or "/>").
        let self_closing = rest.starts_with("/")
            || rest[..rest.find('>').unwrap_or(rest.len())].ends_with('/');
        match rest.find('>') {
            Some(gt) => self.pos += gt + 1,
            None => return Err("plist: unterminated tag".into()),
        }
        Ok((name, self_closing))
    }

    fn parse_value(&mut self) -> Result<Plist, String> {
        self.skip_ws();
        let rest = self
            .s
            .get(self.pos..)
            .ok_or_else(|| "plist: unexpected end of input".to_string())?;
        if !rest.starts_with('<') {
            return Err(format!("plist: expected element at byte {}", self.pos));
        }
        // Self-closing booleans are the only void elements in our subset.
        if rest.starts_with("<true/>") {
            self.pos += 7;
            return Ok(Plist::Bool(true));
        }
        if rest.starts_with("<false/>") {
            self.pos += 8;
            return Ok(Plist::Bool(false));
        }
        let (name, self_closing) = self.next_tag()?;
        let name = name.to_string();
        match name.as_str() {
            "true" | "false" => {
                // Both void (<true/>) and paired (<true></true>) forms
                // appear in real Apple plists (T8030 iOS 13.7 __info).
                if !self_closing {
                    self.raw_until(&name)?;
                }
                Ok(Plist::Bool(name == "true"))
            }
            "dict" => {
                if self_closing {
                    return Ok(Plist::Dict(Default::default()));
                }
                self.parse_dict()
            }
            "array" => {
                if self_closing {
                    return Ok(Plist::Array(Vec::new()));
                }
                self.parse_array()
            }
            "key" | "string" => {
                let text = if self_closing {
                    String::new()
                } else {
                    self.raw_until(&name)?
                };
                Ok(Plist::Str(unescape(&text)))
            }
            "integer" => {
                if self_closing {
                    return Ok(Plist::UInt(0));
                }
                let text = self.raw_until("integer")?;
                let t = text.trim();
                // Real Apple plists (e.g. the T8030 iOS 13.7
                // __PRELINK_INFO.__info) emit hex integers: 0x1, 0x1000 …
                let unsigned = t.trim_start_matches('+');
                let parsed: Result<u64, String> = if let Some(hex) = unsigned
                    .strip_prefix("0x")
                    .or_else(|| unsigned.strip_prefix("0X"))
                {
                    u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
                } else if let Some(neg) = t.strip_prefix('-') {
                    neg.trim_start_matches('+')
                        .parse::<u64>()
                        .map(|v| v.wrapping_neg())
                        .map_err(|e| e.to_string())
                } else {
                    unsigned.parse::<u64>().map_err(|e| e.to_string())
                };
                let n = parsed.map_err(|_| format!("plist: bad integer {t:?}"))?;
                Ok(Plist::UInt(n))
            }
            "data" => {
                if self_closing {
                    return Ok(Plist::Data(Vec::new()));
                }
                let text = self.raw_until("data")?;
                base64_decode(text.trim()).map(Plist::Data)
            }
            other => Err(format!("plist: unsupported element <{other}>")),
        }
    }

    fn raw_until(&mut self, tag: &str) -> Result<String, String> {
        let rest = self
            .s
            .get(self.pos..)
            .ok_or_else(|| "plist: unexpected end of input".to_string())?;
        let close = format!("</{tag}>");
        let idx = rest
            .find(&close)
            .ok_or_else(|| format!("plist: missing </{tag}>"))?;
        let text = rest[..idx].to_string();
        self.pos += idx + close.len();
        Ok(text)
    }

    fn parse_dict(&mut self) -> Result<Plist, String> {
        let mut map = BTreeMap::new();
        loop {
            self.skip_ws_comments();
            let rest = self
                .s
                .get(self.pos..)
                .ok_or_else(|| "plist: unexpected end of input".to_string())?;
            if rest.starts_with("</dict>") {
                self.pos += 7;
                return Ok(Plist::Dict(map));
            }
            if !rest.starts_with('<') {
                return Err(format!("plist: expected <key> at byte {}", self.pos));
            }
            let name = self.next_tag()?.0.to_string();
            if name != "key" {
                return Err(format!("plist: expected <key>, got <{name}>"));
            }
            let key = self.raw_until("key")?;
            let value = self.parse_value()?;
            map.insert(unescape(&key), value);
        }
    }

    fn parse_array(&mut self) -> Result<Plist, String> {
        let mut items = Vec::new();
        loop {
            self.skip_ws_comments();
            let rest = self
                .s
                .get(self.pos..)
                .ok_or_else(|| "plist: unexpected end of input".to_string())?;
            if rest.starts_with("</array>") {
                self.pos += 8;
                return Ok(Plist::Array(items));
            }
            items.push(self.parse_value()?);
        }
    }
}

/// Inverse of [`escape`] for the five predefined entities plus the numeric
/// forms libplist can emit.
fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < s.len() {
        if bytes[i] != b'&' {
            // Copy the full UTF-8 char starting here.
            let ch_len = utf8_len(bytes[i]);
            out.push_str(s.get(i..i + ch_len).unwrap_or("&"));
            i += ch_len;
            continue;
        }
        let rest = &s[i..];
        let semi = match rest.find(';') {
            Some(k) => k,
            None => {
                out.push('&');
                i += 1;
                continue;
            }
        };
        let ent = &rest[1..semi];
        let rep = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => {
                if let Some(hex) = ent.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                } else if let Some(dec) = ent.strip_prefix('#') {
                    dec.parse::<u32>().ok().and_then(char::from_u32)
                } else {
                    None
                }
            }
        };
        match rep {
            Some(ch) => {
                out.push(ch);
                i += semi + 1;
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }
    out
}

fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// RFC 4648 base64 with padding (libplist emits padded lines; the whitespace
/// inside `<data>` is accepted on parse either way).
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Decode padded or unpadded base64, ignoring interior whitespace (Apple
/// wraps `<data>` at 76 columns).
pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut acc: u32 = 0;
    let mut nbits = 0;
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for c in s.chars() {
        if c.is_whitespace() || c == '=' {
            continue;
        }
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return Err(format!("plist: invalid base64 char {c:?}")),
        };
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_dict() {
        let mut d = BTreeMap::new();
        d.insert("MessageType".into(), Plist::Str("Connect".into()));
        d.insert("DeviceID".into(), Plist::UInt(2));
        d.insert(
            "Properties".into(),
            Plist::Dict({
                let mut p = BTreeMap::new();
                p.insert("SerialNumber".into(), Plist::Str("DAPTEST-1".into()));
                p.insert("Checksum Chunks".into(), Plist::Bool(true));
                p
            }),
        );
        d.insert("Ticket".into(), Plist::Data(vec![0u8, 255, 1, 0, 77]));
        let v = Plist::Dict(d);
        let xml = to_xml(&v);
        assert!(xml.contains("<plist version=\"1.0\">"));
        assert!(xml.contains("<key>MessageType</key>"));
        let back = from_xml(&xml).expect("parse roundtrip");
        assert_eq!(back, v);
    }

    #[test]
    fn parses_apple_style_envelope() {
        let xml = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n",
            "<dict>\n\t<key>Command</key>\n\t<string>Initiate</string>\n",
            "\t<key>Checksum Chunks</key>\n\t<true/>\n",
            "\t<key>OOB Offset</key>\n\t<integer>4096</integer>\n",
            "\t<key>BBTicket</key>\n\t<data>AAECAw==</data>\n</dict>\n</plist>\n"
        );
        let v = from_xml(xml).expect("parse");
        match v {
            Plist::Dict(d) => {
                assert_eq!(d.get("Command"), Some(&Plist::Str("Initiate".into())));
                assert_eq!(d.get("Checksum Chunks"), Some(&Plist::Bool(true)));
                assert_eq!(d.get("OOB Offset"), Some(&Plist::UInt(4096)));
                assert_eq!(d.get("BBTicket"), Some(&Plist::Data(vec![0, 1, 2, 3])));
            }
            other => panic!("expected dict, got {other:?}"),
        }
    }

    #[test]
    fn parses_bare_value_without_envelope() {
        let v = from_xml("<dict><key>DeviceID</key><integer>7</integer></dict>").unwrap();
        assert_eq!(
            v,
            Plist::Dict({
                let mut d = BTreeMap::new();
                d.insert("DeviceID".into(), Plist::UInt(7));
                d
            })
        );
        let arr = from_xml("<array><string>a</string><false/></array>").unwrap();
        assert_eq!(
            arr,
            Plist::Array(vec![Plist::Str("a".into()), Plist::Bool(false)])
        );
    }

    #[test]
    fn base64_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_decode("Zm9v YmFy\n").unwrap(), b"foobar");
        assert!(base64_decode("Zm9*v").is_err());
    }

    #[test]
    fn entities_escape_and_unescape() {
        let v = Plist::Str("a<b>&c\"d'é".into());
        let xml = to_xml(&v);
        assert!(xml.contains("a&lt;b&gt;&amp;c&quot;d&apos;é"));
        assert_eq!(from_xml(&xml).unwrap(), v);
        assert_eq!(
            unescape("x&#65;&#x42;y"),
            "xABy".to_string()
        );
    }

    #[test]
    fn rejects_unknown_elements() {
        let e = from_xml("<plist version=\"1.0\"><real>1.5</real></plist>");
        assert!(e.is_err());
        let e2 = from_xml("<dict><key>a</key><date>2026</date></dict>");
        assert!(e2.is_err());
    }
}
