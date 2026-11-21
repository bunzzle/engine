use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub depth: usize,
    pub values: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            depth: 16,
            values: 65_536,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Syntax(usize),
    Depth,
    Values,
    Duplicate(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Object(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(n) if n.bytes().all(|b| b.is_ascii_digit()) => n.parse().ok(),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Self::Object(fields) => Some(fields),
            _ => None,
        }
    }

    pub fn write(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(true) => out.push_str("true"),
            Self::Bool(false) => out.push_str("false"),
            Self::Number(n) => out.push_str(n),
            Self::String(s) => string(s, out),
            Self::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Self::Object(fields) => {
                out.push('{');
                for (i, (key, value)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    string(key, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }

    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }
}

pub use http::json_string as string;

pub fn parse(input: &[u8], limits: Limits) -> Result<Value, Error> {
    let text = std::str::from_utf8(input).map_err(|e| Error::Syntax(e.valid_up_to()))?;
    let mut parser = Parser {
        bytes: text.as_bytes(),
        at: 0,
        depth: 0,
        values: 0,
        limits,
    };
    parser.space();
    let value = parser.value()?;
    parser.space();
    if parser.at != parser.bytes.len() {
        return Err(Error::Syntax(parser.at));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    depth: usize,
    values: usize,
    limits: Limits,
}

impl Parser<'_> {
    fn syntax(&self) -> Error {
        Error::Syntax(self.at)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn eat(&mut self, b: u8) -> Result<(), Error> {
        if self.peek() == Some(b) {
            self.at += 1;
            Ok(())
        } else {
            Err(self.syntax())
        }
    }

    fn word(&mut self, word: &[u8], value: Value) -> Result<Value, Error> {
        if self.bytes[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(value)
        } else {
            Err(self.syntax())
        }
    }

    fn value(&mut self) -> Result<Value, Error> {
        self.values += 1;
        if self.values > self.limits.values {
            return Err(Error::Values);
        }
        match self.peek() {
            Some(b'n') => self.word(b"null", Value::Null),
            Some(b't') => self.word(b"true", Value::Bool(true)),
            Some(b'f') => self.word(b"false", Value::Bool(false)),
            Some(b'"') => self.string().map(Value::String),
            Some(b'[') => self.nested(Self::array),
            Some(b'{') => self.nested(Self::object),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.syntax()),
        }
    }

    fn nested(&mut self, f: fn(&mut Self) -> Result<Value, Error>) -> Result<Value, Error> {
        self.depth += 1;
        if self.depth > self.limits.depth {
            return Err(Error::Depth);
        }
        let value = f(self)?;
        self.depth -= 1;
        Ok(value)
    }

    fn array(&mut self) -> Result<Value, Error> {
        self.eat(b'[')?;
        self.space();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.space();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.space();
                }
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn object(&mut self) -> Result<Value, Error> {
        self.eat(b'{')?;
        self.space();
        let mut fields: Vec<(String, Value)> = Vec::new();
        let mut keys = HashSet::new();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(fields));
        }
        loop {
            let start = self.at;
            if self.peek() != Some(b'"') {
                return Err(self.syntax());
            }
            let key = self.string()?;
            if !keys.insert(key.clone()) {
                return Err(Error::Duplicate(start));
            }
            self.space();
            self.eat(b':')?;
            self.space();
            let value = self.value()?;
            fields.push((key, value));
            self.space();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.space();
                }
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(fields));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.at - start
    }

    fn number(&mut self) -> Result<Value, Error> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.syntax()),
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            if self.digits() == 0 {
                return Err(self.syntax());
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if self.digits() == 0 {
                return Err(self.syntax());
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| self.syntax())?;
        Ok(Value::Number(text.to_owned()))
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let digits = self.bytes.get(self.at..self.at + 4).ok_or(self.syntax())?;
        let mut value = 0;
        for &b in digits {
            let d = char::from(b).to_digit(16).ok_or(self.syntax())?;
            value = value * 16 + d;
        }
        self.at += 4;
        Ok(value)
    }

    fn string(&mut self) -> Result<String, Error> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.at;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.at += 1;
            }
            let run =
                std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| self.syntax())?;
            out.push_str(run);
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    out.push(self.escape()?);
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn escape(&mut self) -> Result<char, Error> {
        let b = self.peek().ok_or(self.syntax())?;
        self.at += 1;
        Ok(match b {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode(),
            _ => return Err(Error::Syntax(self.at - 1)),
        })
    }

    fn unicode(&mut self) -> Result<char, Error> {
        let first = self.hex4()?;
        let code = match first {
            0xD800..=0xDBFF => {
                if !self.bytes[self.at..].starts_with(b"\\u") {
                    return Err(self.syntax());
                }
                self.at += 2;
                let second = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(self.syntax());
                }
                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(self.syntax()),
            code => code,
        };
        char::from_u32(code).ok_or(self.syntax())
    }
}
