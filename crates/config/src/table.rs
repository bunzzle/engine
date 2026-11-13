use std::collections::BTreeMap;
use std::time::Duration;

use crate::{Error, units};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<Value>),
}

impl Value {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Str(_) => "a string",
            Self::Int(_) => "an integer",
            Self::Bool(_) => "a boolean",
            Self::Array(_) => "an array",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub(crate) key: String,
    pub(crate) value: Value,
    pub(crate) line: usize,
    pub(crate) column: usize,
}

impl Entry {
    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn error(&self, message: impl AsRef<str>) -> Error {
        Error::at(
            self.line,
            self.column,
            format!("`{}` {}", self.key, message.as_ref()),
        )
    }

    fn expected(&self, kind: &str) -> Error {
        self.error(format!("must be {kind}, found {}", self.value.kind()))
    }

    pub fn str(&self) -> Result<&str, Error> {
        match &self.value {
            Value::Str(text) => Ok(text),
            _ => Err(self.expected("a string")),
        }
    }

    pub fn int(&self) -> Result<i64, Error> {
        match self.value {
            Value::Int(number) => Ok(number),
            _ => Err(self.expected("an integer")),
        }
    }

    pub fn bool(&self) -> Result<bool, Error> {
        match self.value {
            Value::Bool(flag) => Ok(flag),
            _ => Err(self.expected("a boolean")),
        }
    }

    pub fn number(&self, min: u64, max: u64) -> Result<u64, Error> {
        let number = self.int()?;
        u64::try_from(number)
            .ok()
            .filter(|n| (min..=max).contains(n))
            .ok_or_else(|| self.error(format!("must be between {min} and {max}")))
    }

    pub fn duration(&self) -> Result<Duration, Error> {
        units::duration(self.str()?).ok_or_else(|| {
            self.error("must be a duration such as \"500ms\", \"10s\", \"5m\" or \"2h\"")
        })
    }

    pub fn size(&self) -> Result<u64, Error> {
        units::size(self.str()?).ok_or_else(|| {
            self.error("must be a size such as \"512B\", \"64KiB\", \"16MiB\" or \"1GiB\"")
        })
    }

    pub fn strs(&self) -> Result<Vec<&str>, Error> {
        let Value::Array(items) = &self.value else {
            return Err(self.expected("an array of strings"));
        };
        items
            .iter()
            .map(|item| match item {
                Value::Str(text) => Ok(text.as_str()),
                _ => Err(self.expected("an array of strings")),
            })
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct Table {
    pub(crate) name: String,
    pub(crate) line: usize,
    pub(crate) entries: BTreeMap<String, Entry>,
    pub(crate) tables: BTreeMap<String, Table>,
    pub(crate) arrays: BTreeMap<String, Vec<Table>>,
}

impl Table {
    pub(crate) fn new(name: String, line: usize) -> Self {
        Self {
            name,
            line,
            ..Self::default()
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn line(&self) -> usize {
        self.line
    }

    pub fn take(&mut self, key: &str) -> Option<Entry> {
        self.entries.remove(key)
    }

    pub fn require(&mut self, key: &str) -> Result<Entry, Error> {
        self.take(key).ok_or_else(|| {
            let place = if self.name.is_empty() {
                String::from("the top level")
            } else {
                format!("[{}]", self.name)
            };
            Error::at(self.line.max(1), 1, format!("missing `{key}` in {place}"))
        })
    }

    pub fn table(&mut self, name: &str) -> Option<Table> {
        self.tables.remove(name)
    }

    pub fn tables(&mut self, name: &str) -> Vec<Table> {
        self.arrays.remove(name).unwrap_or_default()
    }

    pub fn finish(self) -> Result<(), Error> {
        let entries = self
            .entries
            .values()
            .map(|entry| entry.error("is not a known setting"));
        let tables = self.tables.values().map(unknown);
        let arrays = self.arrays.values().flatten().map(unknown);
        match entries
            .chain(tables)
            .chain(arrays)
            .min_by_key(|e| (e.line, e.column))
        {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn unknown(table: &Table) -> Error {
    Error::at(
        table.line,
        1,
        format!("[{}] is not a known section", table.name),
    )
}
