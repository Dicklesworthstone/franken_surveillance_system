#![forbid(unsafe_code)]
//! Private bounded XML 1.0/Namespaces subset. No DTD, external entities,
//! recursive expansion, processing instructions, or I/O are supported.

use super::{MAX_SOAP_BYTES, WireError};

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";
const MAX_DEPTH: usize = 32;
const MAX_ELEMENTS: usize = 4096;
const MAX_ATTRIBUTES: usize = 32;
const MAX_NAME_BYTES: usize = 128;
const MAX_NAMESPACE_BYTES: usize = 1024;
const MAX_TEXT_BYTES: usize = 16 * 1024;

struct Name {
    namespace: String,
    local: String,
}

struct Attribute {
    name: Name,
    value: String,
}

struct Node {
    name: Name,
    raw_name: String,
    attributes: Vec<Attribute>,
    namespaces: Vec<(String, String)>,
    parent: Option<usize>,
    children: Vec<usize>,
    text: String,
}

pub(super) struct Document {
    nodes: Vec<Node>,
    root: usize,
}

impl Document {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_SOAP_BYTES {
            return Err(WireError::InputTooLarge);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| WireError::MalformedXml)?;
        if !text.chars().all(valid_char) {
            return Err(WireError::MalformedXml);
        }
        // XML 1.0 line-ending normalization applies before tokenization, even
        // inside CDATA. Character references are decoded later and keep value.
        let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
        let input = normalized.strip_prefix('\u{feff}').unwrap_or(&normalized);
        Parser {
            input,
            pos: 0,
            nodes: Vec::new(),
            stack: Vec::new(),
            root: None,
        }
        .parse()
    }

    pub(super) const fn root(&self) -> usize {
        self.root
    }

    pub(super) fn named(&self, id: usize, namespace: &str, local: &str) -> bool {
        let name = &self.nodes[id].name;
        name.namespace == namespace && name.local == local
    }

    pub(super) fn child_ids(&self, id: usize) -> impl Iterator<Item = usize> + '_ {
        self.nodes[id].children.iter().copied()
    }

    pub(super) fn children<'a>(
        &'a self,
        id: usize,
        namespace: &'a str,
        local: &'a str,
    ) -> impl Iterator<Item = usize> + 'a {
        self.child_ids(id)
            .filter(move |child| self.named(*child, namespace, local))
    }

    pub(super) fn attribute(&self, id: usize, namespace: &str, local: &str) -> Option<&str> {
        self.nodes[id]
            .attributes
            .iter()
            .find(|attribute| {
                attribute.name.namespace == namespace && attribute.name.local == local
            })
            .map(|attribute| attribute.value.as_str())
    }

    pub(super) fn attribute_count(&self, id: usize) -> usize {
        self.nodes[id].attributes.len()
    }

    pub(super) fn only_whitespace(&self, id: usize) -> bool {
        self.nodes[id].text.chars().all(whitespace)
    }

    pub(super) fn leaf_text(&self, id: usize) -> Result<&str, WireError> {
        if !self.nodes[id].children.is_empty() {
            return Err(WireError::InvalidField);
        }
        Ok(&self.nodes[id].text)
    }

    pub(super) fn resolve_qname<'a>(
        &'a self,
        id: usize,
        value: &'a str,
    ) -> Result<(&'a str, &'a str), WireError> {
        let (prefix, local) = qname(value)?;
        let namespace = namespace(&self.nodes, Some(id), &[], prefix)?;
        Ok((namespace, local))
    }
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
    nodes: Vec<Node>,
    stack: Vec<usize>,
    root: Option<usize>,
}

impl Parser<'_> {
    fn parse(mut self) -> Result<Document, WireError> {
        if self.rest().starts_with("<?xml") {
            self.declaration()?;
        }
        while self.pos < self.input.len() {
            if self.rest().starts_with("<!--") {
                self.comment()?;
            } else if self.rest().starts_with("<![CDATA[") {
                self.cdata()?;
            } else if self.rest().starts_with("</") {
                self.close()?;
            } else if self.rest().starts_with("<!") || self.rest().starts_with("<?") {
                return Err(WireError::UnsupportedXml);
            } else if self.rest().starts_with('<') {
                self.open()?;
            } else {
                self.text()?;
            }
        }
        if !self.stack.is_empty() {
            return Err(WireError::MalformedXml);
        }
        Ok(Document {
            nodes: self.nodes,
            root: self.root.ok_or(WireError::MalformedXml)?,
        })
    }

    fn rest(&self) -> &str {
        &self.input[self.pos..]
    }

    fn skip_space(&mut self) -> bool {
        let before = self.pos;
        while self
            .input
            .as_bytes()
            .get(self.pos)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.pos += 1;
        }
        self.pos != before
    }

    fn take(&mut self, token: &str) -> bool {
        if self.rest().starts_with(token) {
            self.pos += token.len();
            true
        } else {
            false
        }
    }

    fn name(&mut self) -> Result<String, WireError> {
        let start = self.pos;
        while self
            .input
            .as_bytes()
            .get(self.pos)
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'-' | b'.' | b':'))
        {
            self.pos += 1;
        }
        let name = &self.input[start..self.pos];
        if name.len() > MAX_NAME_BYTES {
            return Err(WireError::XmlLimitExceeded);
        }
        qname(name)?;
        Ok(name.to_owned())
    }

    fn attribute_value(&mut self) -> Result<String, WireError> {
        self.skip_space();
        if !self.take("=") {
            return Err(WireError::MalformedXml);
        }
        self.skip_space();
        let quote = match self.input.as_bytes().get(self.pos) {
            Some(b'"') => '"',
            Some(b'\'') => '\'',
            _ => return Err(WireError::MalformedXml),
        };
        self.pos += 1;
        let end = self.rest().find(quote).ok_or(WireError::MalformedXml)?;
        let raw = &self.rest()[..end];
        if raw.contains('<') {
            return Err(WireError::MalformedXml);
        }
        // Literal whitespace in attributes normalizes to spaces; references
        // such as &#9; are not normalized a second time.
        let normalized = raw.replace(['\n', '\t'], " ");
        let value = entities(&normalized)?;
        self.pos += end + 1;
        Ok(value)
    }

    fn declaration(&mut self) -> Result<(), WireError> {
        self.pos += "<?xml".len();
        if !self.skip_space() {
            return Err(WireError::UnsupportedXml);
        }
        let mut attributes: Vec<(String, String)> = Vec::new();
        loop {
            if self.take("?>") {
                break;
            }
            if attributes.len() == 3 || self.pos > 256 {
                return Err(WireError::UnsupportedXml);
            }
            let name = self.name()?;
            let value_start = self.pos;
            let value = self.attribute_value()?;
            if self.input[value_start..self.pos].contains('&') {
                return Err(WireError::UnsupportedXml);
            }
            if attributes.iter().any(|(prior, _)| prior == &name) {
                return Err(WireError::MalformedXml);
            }
            attributes.push((name, value));
            let space = self.skip_space();
            if !space && !self.rest().starts_with("?>") {
                return Err(WireError::MalformedXml);
            }
        }
        let Some((name, value)) = attributes.first() else {
            return Err(WireError::UnsupportedXml);
        };
        if name != "version" || value != "1.0" {
            return Err(WireError::UnsupportedXml);
        }
        let mut standalone = false;
        for (name, value) in &attributes[1..] {
            match name.as_str() {
                "encoding" if !standalone && value.eq_ignore_ascii_case("UTF-8") => {}
                "standalone" if matches!(value.as_str(), "yes" | "no") => standalone = true,
                _ => return Err(WireError::UnsupportedXml),
            }
        }
        Ok(())
    }

    fn comment(&mut self) -> Result<(), WireError> {
        self.pos += 4;
        let end = self.rest().find("-->").ok_or(WireError::MalformedXml)?;
        let content = &self.rest()[..end];
        if content.contains("--") || content.ends_with('-') {
            return Err(WireError::MalformedXml);
        }
        self.pos += end + 3;
        Ok(())
    }

    fn cdata(&mut self) -> Result<(), WireError> {
        if self.stack.is_empty() {
            return Err(WireError::MalformedXml);
        }
        self.pos += 9;
        let end = self.rest().find("]]>").ok_or(WireError::MalformedXml)?;
        let value = self.rest()[..end].to_owned();
        self.append_text(&value)?;
        self.pos += end + 3;
        Ok(())
    }

    fn text(&mut self) -> Result<(), WireError> {
        let end = self.rest().find('<').unwrap_or(self.rest().len());
        let raw = &self.rest()[..end];
        if raw.contains("]]>") {
            return Err(WireError::MalformedXml);
        }
        if self.stack.is_empty() && !raw.chars().all(whitespace) {
            return Err(WireError::MalformedXml);
        }
        let value = entities(raw)?;
        self.append_text(&value)?;
        self.pos += end;
        Ok(())
    }

    fn append_text(&mut self, value: &str) -> Result<(), WireError> {
        if let Some(id) = self.stack.last().copied() {
            let text = &mut self.nodes[id].text;
            if text.len().saturating_add(value.len()) > MAX_TEXT_BYTES {
                return Err(WireError::XmlLimitExceeded);
            }
            text.push_str(value);
        } else if !value.chars().all(whitespace) {
            return Err(WireError::MalformedXml);
        }
        Ok(())
    }

    fn close(&mut self) -> Result<(), WireError> {
        self.pos += 2;
        let name = self.name()?;
        self.skip_space();
        if !self.take(">") {
            return Err(WireError::MalformedXml);
        }
        let id = self.stack.pop().ok_or(WireError::MalformedXml)?;
        if self.nodes[id].raw_name != name {
            return Err(WireError::MalformedXml);
        }
        Ok(())
    }

    fn open(&mut self) -> Result<(), WireError> {
        if self.stack.len() == MAX_DEPTH || self.nodes.len() == MAX_ELEMENTS {
            return Err(WireError::XmlLimitExceeded);
        }
        self.pos += 1;
        let raw_name = self.name()?;
        let mut attributes: Vec<(String, String)> = Vec::new();
        let empty;
        loop {
            let space = self.skip_space();
            if self.take("/>") {
                empty = true;
                break;
            }
            if self.take(">") {
                empty = false;
                break;
            }
            if !space {
                return Err(WireError::MalformedXml);
            }
            if attributes.len() == MAX_ATTRIBUTES {
                return Err(WireError::XmlLimitExceeded);
            }
            let name = self.name()?;
            let value = self.attribute_value()?;
            if attributes.iter().any(|(prior, _)| prior == &name) {
                return Err(WireError::MalformedXml);
            }
            attributes.push((name, value));
        }
        let mut bindings: Vec<(String, String)> = Vec::new();
        for (name, value) in &attributes {
            let prefix = if name == "xmlns" {
                Some("")
            } else {
                name.strip_prefix("xmlns:")
            };
            if let Some(prefix) = prefix {
                if value.len() > MAX_NAMESPACE_BYTES {
                    return Err(WireError::XmlLimitExceeded);
                }
                if prefix == "xmlns"
                    || value == XMLNS_NS
                    || (prefix == "xml" && value != XML_NS)
                    || (prefix != "xml" && value == XML_NS)
                    || (!prefix.is_empty() && value.is_empty())
                    || value.chars().any(char::is_whitespace)
                {
                    return Err(WireError::MalformedXml);
                }
                bindings.push((prefix.to_owned(), value.clone()));
            }
        }
        let parent = self.stack.last().copied();
        let name = expanded_name(&self.nodes, parent, &bindings, &raw_name, false)?;
        let mut expanded_attributes: Vec<Attribute> = Vec::new();
        for (raw, value) in attributes {
            if raw == "xmlns" || raw.starts_with("xmlns:") {
                continue;
            }
            let name = expanded_name(&self.nodes, parent, &bindings, &raw, true)?;
            if expanded_attributes.iter().any(|prior| {
                prior.name.namespace == name.namespace && prior.name.local == name.local
            }) {
                return Err(WireError::MalformedXml);
            }
            expanded_attributes.push(Attribute { name, value });
        }
        let id = self.nodes.len();
        if let Some(parent) = parent {
            self.nodes[parent].children.push(id);
        } else if self.root.replace(id).is_some() {
            return Err(WireError::MalformedXml);
        }
        self.nodes.push(Node {
            name,
            raw_name,
            attributes: expanded_attributes,
            namespaces: bindings,
            parent,
            children: Vec::new(),
            text: String::new(),
        });
        if !empty {
            self.stack.push(id);
        }
        Ok(())
    }
}

fn expanded_name(
    nodes: &[Node],
    parent: Option<usize>,
    bindings: &[(String, String)],
    raw: &str,
    attribute: bool,
) -> Result<Name, WireError> {
    let (prefix, local) = qname(raw)?;
    let namespace = if attribute && prefix.is_empty() {
        ""
    } else {
        namespace(nodes, parent, bindings, prefix)?
    };
    Ok(Name {
        namespace: namespace.to_owned(),
        local: local.to_owned(),
    })
}

fn namespace<'a>(
    nodes: &'a [Node],
    mut parent: Option<usize>,
    bindings: &'a [(String, String)],
    prefix: &str,
) -> Result<&'a str, WireError> {
    if prefix == "xml" {
        return Ok(XML_NS);
    }
    if prefix == "xmlns" {
        return Err(WireError::MalformedXml);
    }
    if let Some((_, uri)) = bindings.iter().find(|(name, _)| name == prefix) {
        return Ok(uri);
    }
    while let Some(id) = parent {
        if let Some((_, uri)) = nodes[id].namespaces.iter().find(|(name, _)| name == prefix) {
            return Ok(uri);
        }
        parent = nodes[id].parent;
    }
    if prefix.is_empty() {
        Ok("")
    } else {
        Err(WireError::MalformedXml)
    }
}

fn qname(value: &str) -> Result<(&str, &str), WireError> {
    if value.len() > MAX_NAME_BYTES {
        return Err(WireError::XmlLimitExceeded);
    }
    let (prefix, local) = value.split_once(':').unwrap_or(("", value));
    let valid_name = |name: &str| {
        name.as_bytes()
            .first()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || *ch == b'_')
            && name
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'-' | b'.'))
    };
    if !valid_name(local) || (!prefix.is_empty() && !valid_name(prefix)) || value.starts_with(':') {
        return Err(WireError::MalformedXml);
    }
    Ok((prefix, local))
}

fn entities(input: &str) -> Result<String, WireError> {
    if input.len() > MAX_TEXT_BYTES {
        return Err(WireError::XmlLimitExceeded);
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        rest = &rest[start + 1..];
        let end = rest.find(';').ok_or(WireError::MalformedXml)?;
        if end > 16 {
            return Err(WireError::MalformedXml);
        }
        let reference = &rest[..end];
        let ch = match reference {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "apos" => '\'',
            "quot" => '"',
            reference => {
                let (digits, radix) = if let Some(digits) = reference.strip_prefix("#x") {
                    (digits, 16)
                } else if let Some(digits) = reference.strip_prefix('#') {
                    (digits, 10)
                } else {
                    return Err(WireError::UnsupportedXml);
                };
                if digits.is_empty() || !digits.chars().all(|ch| ch.is_digit(radix)) {
                    return Err(WireError::MalformedXml);
                }
                let value =
                    u32::from_str_radix(digits, radix).map_err(|_| WireError::MalformedXml)?;
                char::from_u32(value)
                    .filter(|ch| valid_char(*ch))
                    .ok_or(WireError::MalformedXml)?
            }
        };
        out.push(ch);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

pub(super) fn whitespace(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\r' | '\n')
}

pub(super) fn valid_char(ch: char) -> bool {
    matches!(ch, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}
