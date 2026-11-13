use std::collections::BTreeSet;
use std::collections::btree_map::Entry as Slot;

use crate::Error;
use crate::table::{Entry, Table, Value};

struct Line {
    number: usize,
    chars: Vec<char>,
    at: usize,
}

impl Line {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn column(&self) -> usize {
        self.at + 1
    }

    fn error(&self, message: impl Into<String>) -> Error {
        Error::at(self.number, self.column(), message)
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.at += 1;
        }
    }

    fn eat(&mut self, wanted: char) -> Result<(), Error> {
        match self.peek() {
            Some(c) if c == wanted => {
                self.at += 1;
                Ok(())
            }
            Some(c) => Err(self.error(format!("expected `{wanted}`, found `{}`", shown(c)))),
            None => Err(self.error(format!("expected `{wanted}` before the end of the line"))),
        }
    }

    fn key(&mut self) -> Result<String, Error> {
        let start = self.at;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            self.at += 1;
        }
        if self.at == start {
            return Err(match self.peek() {
                Some('"' | '\'') => self.error("quoted keys are not supported"),
                Some(c) => self.error(format!("expected a key, found `{}`", shown(c))),
                None => self.error("expected a key"),
            });
        }
        Ok(self.chars[start..self.at].iter().collect())
    }

    fn end(&mut self) -> Result<(), Error> {
        self.skip_space();
        match self.peek() {
            None => Ok(()),
            Some('#') => self.comment(),
            Some(c) => Err(self.error(format!("unexpected `{}`", shown(c)))),
        }
    }

    fn comment(&mut self) -> Result<(), Error> {
        while let Some(c) = self.peek() {
            if control(c) {
                return Err(self.error("control character in a comment"));
            }
            self.at += 1;
        }
        Ok(())
    }

    fn value(&mut self) -> Result<Value, Error> {
        match self.peek() {
            Some('"') => self.string().map(Value::Str),
            Some('[') => self.array(),
            Some('-' | '0'..='9') => self.integer().map(Value::Int),
            Some('t' | 'f') => self.boolean().map(Value::Bool),
            Some('\'') => Err(self.error("literal strings are not supported, use \"...\"")),
            Some('{') => Err(self.error("inline tables are not supported")),
            Some(c) => Err(self.error(format!("expected a value, found `{}`", shown(c)))),
            None => Err(self.error("expected a value")),
        }
    }

    fn string(&mut self) -> Result<String, Error> {
        self.at += 1;
        if self.chars[self.at..].starts_with(&['"', '"']) {
            return Err(self.error("multi-line strings are not supported"));
        }
        let mut text = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(self.error("unterminated string"));
            };
            match c {
                '"' => {
                    self.at += 1;
                    return Ok(text);
                }
                '\\' => {
                    self.at += 1;
                    text.push(match self.peek() {
                        Some('"') => '"',
                        Some('\\') => '\\',
                        Some('n') => '\n',
                        Some('t') => '\t',
                        _ => return Err(self.error("unsupported escape")),
                    });
                }
                c if control(c) => return Err(self.error("control character in a string")),
                c => text.push(c),
            }
            self.at += 1;
        }
    }

    fn integer(&mut self) -> Result<i64, Error> {
        let start = self.at;
        let negative = self.peek() == Some('-');
        if negative {
            self.at += 1;
        }
        let mut digits = String::new();
        let mut last_digit = false;
        while let Some(c) = self.peek() {
            match c {
                '0'..='9' => {
                    digits.push(c);
                    last_digit = true;
                }
                '_' if last_digit => last_digit = false,
                '_' => return Err(self.error("`_` must sit between digits")),
                _ => break,
            }
            self.at += 1;
        }
        if digits.is_empty() || !last_digit {
            return Err(self.error("expected digits"));
        }
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(Error::at(
                self.number,
                start + 1,
                "leading zeros are not allowed",
            ));
        }
        if matches!(self.peek(), Some('.' | 'e' | 'E' | 'x' | 'o' | 'b' | ':')) {
            return Err(self.error("only whole decimal numbers are supported"));
        }
        let text = if negative {
            format!("-{digits}")
        } else {
            digits
        };
        text.parse()
            .map_err(|_| Error::at(self.number, start + 1, "number out of range"))
    }

    fn boolean(&mut self) -> Result<bool, Error> {
        for (word, flag) in [("true", true), ("false", false)] {
            let end = self.at + word.len();
            if self.chars.len() >= end && self.chars[self.at..end].iter().copied().eq(word.chars())
            {
                self.at = end;
                return Ok(flag);
            }
        }
        Err(self.error("expected a value"))
    }

    fn array(&mut self) -> Result<Value, Error> {
        self.at += 1;
        let mut items = Vec::new();
        loop {
            self.skip_space();
            if self.peek() == Some(']') {
                self.at += 1;
                return Ok(Value::Array(items));
            }
            let column = self.column();
            let item = self.value()?;
            if !matches!(item, Value::Str(_) | Value::Int(_)) {
                return Err(Error::at(
                    self.number,
                    column,
                    "arrays hold only strings or integers",
                ));
            }
            if items
                .first()
                .is_some_and(|first: &Value| first.kind() != item.kind())
            {
                return Err(Error::at(self.number, column, "arrays must not mix types"));
            }
            items.push(item);
            self.skip_space();
            match self.peek() {
                Some(',') => self.at += 1,
                Some(']') => {}
                None => return Err(self.error("arrays must close on the same line")),
                Some(c) => {
                    return Err(self.error(format!("expected `,` or `]`, found `{}`", shown(c))));
                }
            }
        }
    }
}

fn control(c: char) -> bool {
    (c.is_control() && c != '\t') || c == '\u{7f}'
}

fn shown(c: char) -> String {
    if c.is_control() {
        c.escape_unicode().to_string()
    } else {
        c.to_string()
    }
}

#[derive(Clone)]
struct Current {
    path: Vec<String>,
    array: bool,
}

struct Parser {
    root: Table,
    current: Current,
    defined: BTreeSet<Vec<String>>,
}

pub fn parse(text: &str) -> Result<Table, Error> {
    let mut parser = Parser {
        root: Table::new(String::new(), 1),
        current: Current {
            path: Vec::new(),
            array: false,
        },
        defined: BTreeSet::new(),
    };
    for (index, raw) in text.split('\n').enumerate() {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let mut line = Line {
            number: index + 1,
            chars: raw.chars().collect(),
            at: 0,
        };
        line.skip_space();
        match line.peek() {
            None => {}
            Some('#') => line.comment()?,
            Some('[') => parser.header(&mut line)?,
            Some(_) => parser.pair(&mut line)?,
        }
    }
    Ok(parser.root)
}

impl Parser {
    fn header(&mut self, line: &mut Line) -> Result<(), Error> {
        let column = line.column();
        line.at += 1;
        let array = line.peek() == Some('[');
        if array {
            line.at += 1;
        }
        line.skip_space();
        let mut path = vec![line.key()?];
        while line.peek() == Some('.') {
            line.at += 1;
            path.push(line.key()?);
        }
        line.skip_space();
        line.eat(']')?;
        if array {
            line.eat(']')?;
        }
        line.end()?;
        let error = |message: String| Error::at(line.number, column, message);
        let name = path.join(".");
        let (last, parents) = path.split_last().expect("one key at least");
        let mut table = &mut self.root;
        for (depth, segment) in parents.iter().enumerate() {
            let prefix = path[..=depth].join(".");
            if table.entries.contains_key(segment) {
                return Err(error(format!("`{prefix}` is already a value")));
            }
            if table.arrays.contains_key(segment) {
                return Err(error(format!("[{prefix}] is an array of tables")));
            }
            table = table
                .tables
                .entry(segment.clone())
                .or_insert_with(|| Table::new(prefix, line.number));
        }
        if table.entries.contains_key(last) {
            return Err(error(format!("`{name}` is already a value")));
        }
        if array {
            if table.tables.contains_key(last) {
                return Err(error(format!("[{name}] is already a table")));
            }
            table
                .arrays
                .entry(last.clone())
                .or_default()
                .push(Table::new(name, line.number));
        } else {
            if table.arrays.contains_key(last) {
                return Err(error(format!("[{name}] is an array of tables")));
            }
            if !self.defined.insert(path.clone()) {
                return Err(error(format!("[{name}] is defined twice")));
            }
            match table.tables.entry(last.clone()) {
                Slot::Occupied(mut slot) => slot.get_mut().line = line.number,
                Slot::Vacant(slot) => {
                    slot.insert(Table::new(name, line.number));
                }
            }
        }
        self.current = Current { path, array };
        Ok(())
    }

    fn pair(&mut self, line: &mut Line) -> Result<(), Error> {
        let column = line.column();
        let key = line.key()?;
        line.skip_space();
        if line.peek() == Some('.') {
            return Err(line.error("dotted keys are not supported, use a [section]"));
        }
        line.eat('=')?;
        line.skip_space();
        let value = line.value()?;
        line.end()?;
        let table = self.target();
        if table.tables.contains_key(&key) || table.arrays.contains_key(&key) {
            return Err(Error::at(
                line.number,
                column,
                format!("`{key}` is already a section"),
            ));
        }
        match table.entries.entry(key.clone()) {
            Slot::Occupied(_) => Err(Error::at(
                line.number,
                column,
                format!("`{key}` is set twice"),
            )),
            Slot::Vacant(slot) => {
                slot.insert(Entry {
                    key,
                    value,
                    line: line.number,
                    column,
                });
                Ok(())
            }
        }
    }

    fn target(&mut self) -> &mut Table {
        let Current { path, array } = &self.current;
        let mut table = &mut self.root;
        let Some((last, parents)) = path.split_last() else {
            return table;
        };
        for segment in parents {
            table = table
                .tables
                .get_mut(segment)
                .expect("parent made by header");
        }
        if *array {
            table
                .arrays
                .get_mut(last)
                .and_then(|tables| tables.last_mut())
                .expect("array made by header")
        } else {
            table.tables.get_mut(last).expect("table made by header")
        }
    }
}
