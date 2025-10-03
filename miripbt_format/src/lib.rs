use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hasher},
    ops::RangeInclusive,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

use crate::communication::Value;

pub mod communication;
pub mod test;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct MiriPBTFormat {
    pub types: Vec<Type>,
    pub functions: Vec<Function>,
}

impl MiriPBTFormat {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_types(&mut self, ty: Vec<Type>) {
        for t in ty {
            if !self
                .types
                .iter()
                .any(|existing| existing.name() == t.name())
            {
                self.types.push(t);
            }
        }
    }

    pub fn add_function(&mut self, func: Function) {
        if !self.functions.iter().any(|f| f.name == func.name) {
            self.functions.push(func);
        }
    }

    pub fn find_type(&self, ref_name: &str) -> Option<&Type> {
        self.types.iter().find(|t| t.name() == ref_name)
    }

    pub fn find_struct(&self, ref_name: &str) -> Option<&Struct> {
        self.find_type(ref_name).and_then(|t| match t {
            Type::Struct(s) => Some(s),
            _ => None,
        })
    }

    pub fn find_enum(&self, ref_name: &str) -> Option<&Enum> {
        self.find_type(ref_name).and_then(|t| match t {
            Type::Enum(e) => Some(e),
            _ => None,
        })
    }

    pub fn find_function(&self, name: &str) -> Option<&Function> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Returns Some containing a tree of fields that were modified.
    pub fn compare(
        &self,
        function_name: &str,
        before: &Value,
        after: &Value,
    ) -> Result<Vec<String>, String> {
        let func = self.find_function(function_name).ok_or_else(|| {
            format!(
                "Function {} not found in format, cannot compare",
                function_name
            )
        })?;
        let Value::Map(before) = before else {
            return Err("Before value is not a map".to_string());
        };
        let Value::Map(after) = after else {
            return Err("After value is not a map".to_string());
        };
        let mut results = vec![];
        for (name, arg) in &func.args {
            if !matches!(
                arg.kind,
                TypeRefKind::Ptr | TypeRefKind::PtrMut | TypeRefKind::RefMut | TypeRefKind::Ref
            ) {
                continue;
            }
            let before = before.get(name).ok_or_else(|| {
                format!(
                    "Function {} argument {} not found in before",
                    function_name, name
                )
            })?;
            if let Some(after) = after.get(name) {
                match arg.compare(self, before, after) {
                    Ok(mut v) => {
                        results.append(&mut v);
                    }
                    Err(e) => println!("There was an error comparing values: {}", e),
                }
            }
        }
        Ok(results)
    }

    pub fn hash(&self) -> u64 {
        let h = self
            .functions
            .iter()
            .fold(DefaultHasher::new(), |mut a, b| {
                a.write(b.name.as_bytes());
                a
            });
        h.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Struct {
    pub name: String,
    pub fields: HashMap<String, TypeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Enum {
    pub name: String,
    pub variants: HashMap<String, u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
pub enum Type {
    Struct(Struct),
    Enum(Enum),
}

impl From<Struct> for Type {
    fn from(s: Struct) -> Self {
        Type::Struct(s)
    }
}

impl From<Enum> for Type {
    fn from(e: Enum) -> Self {
        Type::Enum(e)
    }
}

impl Type {
    fn name(&self) -> &str {
        match self {
            Type::Struct(s) => s.name.as_str(),
            Type::Enum(e) => e.name.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Function {
    pub name: String,
    pub args: HashMap<String, TypeRef>,
    pub return_type: Option<TypeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TypeRef {
    pub type_ref: TypeRefType,
    pub kind: TypeRefKind,
    #[serde(default)]
    pub source: Option<Source>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub file: PathBuf,
    pub col: (usize, usize),
    pub line: (usize, usize),
}

pub enum Modified {
    Leaf,
    Obj(Vec<(String, Modified)>),
}

impl TypeRef {
    fn compare(
        &self,
        format: &MiriPBTFormat,
        before: &Value,
        after: &Value,
    ) -> Result<Vec<String>, String> {
        let m = MKC::default();
        self.compare_inner(format, before, after, &m)
            .map(|(v, _)| v)
    }

    fn compare_inner(
        &self,
        format: &MiriPBTFormat,
        before: &Value,
        after: &Value,
        m: &MKC,
    ) -> Result<(Vec<String>, bool), String> {
        let m = m.push(self.kind.into());
        let is_mutable = m.is_mutable();
        let mut v = vec![];
        let mut didnt_have_source = false;
        match (&self.type_ref, before, after) {
            (TypeRefType::Type(sname), Value::Map(before), Value::Map(after)) => {
                let structure = format
                    .find_struct(sname)
                    .ok_or_else(|| format!("Struct {} not found in format", sname))?;

                for (name, s) in &structure.fields {
                    let before = before.get(name).ok_or_else(|| {
                        format!("Struct {} field {} not found in before", sname, name)
                    })?;
                    let after = after.get(name).ok_or_else(|| {
                        format!("Struct {} field {} not found in after", sname, name)
                    })?;
                    let (res, _) = s.compare_inner(format, before, after, &m)?;
                    v.extend(res.into_iter());
                }
            }
            (
                TypeRefType::Array {
                    array_type: ArrayType::Vec,
                    element_type,
                    ..
                },
                Value::Vec(before),
                Value::Vec(after),
            )
            | (
                TypeRefType::Array {
                    array_type: ArrayType::Vec,
                    element_type,
                    ..
                },
                Value::Array(before),
                Value::Array(after),
            ) => {
                if is_mutable || before.len() == after.len() {
                    for (_idx, (before, after)) in before.iter().zip(after.iter()).enumerate() {
                        let (other, _) = element_type.compare_inner(format, before, after, &m)?;
                        v.extend(other.into_iter());
                    }
                } else {
                    if let Some(src) = &self.source {
                        v.push(make_error(src));
                    }
                }
            }
            (TypeRefType::Type(name), Value::EnumVariant(before), Value::EnumVariant(after)) => {
                let en = format
                    .find_enum(name)
                    .ok_or_else(|| format!("Enum {} not found in format", name))?;
                let res = en.variants.contains_key(before)
                    && en.variants.contains_key(after)
                    && (is_mutable || (before == after));

                if !res {
                    if let Some(src) = &self.source {
                        v.push(make_error(src));
                    }
                }
            }
            (
                TypeRefType::Primitive(PrimitiveType::Str(_)),
                Value::String(before),
                Value::String(after),
            ) => {
                if !is_mutable && before != after {
                    if let Some(src) = &self.source {
                        v.push(make_error(src));
                    } else {
                        didnt_have_source = true;
                    }
                }
            }
            (
                TypeRefType::Primitive(PrimitiveType::Char),
                Value::Char(before),
                Value::Char(after),
            ) => {
                if !is_mutable && before != after {
                    if let Some(src) = &self.source {
                        v.push(make_error(src));
                    } else {
                        didnt_have_source = true;
                    }
                }
            }
            (
                TypeRefType::Primitive(PrimitiveType::Bool),
                Value::Bool(before),
                Value::Bool(after),
            ) => {
                if !is_mutable && before != after {
                    if let Some(src) = &self.source {
                        v.push(make_error(src));
                    } else {
                        didnt_have_source = true;
                    }
                }
            }
            (
                TypeRefType::Primitive(
                    PrimitiveType::U8
                    | PrimitiveType::U16
                    | PrimitiveType::U32
                    | PrimitiveType::U64
                    | PrimitiveType::U128
                    | PrimitiveType::Usize,
                ),
                Value::UNum(before),
                Value::UNum(after),
            ) => {
                if !is_mutable && before != after {
                    if let Some(src) = &self.source {
                        v.push(make_error(src));
                    } else {
                        didnt_have_source = true;
                    }
                }
            }
            (
                TypeRefType::Primitive(
                    PrimitiveType::I8
                    | PrimitiveType::I16
                    | PrimitiveType::I32
                    | PrimitiveType::I64
                    | PrimitiveType::I128
                    | PrimitiveType::Isize,
                ),
                Value::INum(before),
                Value::INum(after),
            ) => {
                if !is_mutable && before != after {
                    if let Some(src) = &self.source {
                        v.push(make_error(src));
                    } else {
                        didnt_have_source = true;
                    }
                }
            }
            (
                TypeRefType::Primitive(
                    PrimitiveType::F16
                    | PrimitiveType::F32
                    | PrimitiveType::F64
                    | PrimitiveType::F128,
                ),
                Value::Float(before),
                Value::Float(after),
            ) => {
                if !is_mutable && before != after {
                    if let Some(src) = &self.source {
                        v.push(make_error(src));
                    } else {
                        didnt_have_source = true;
                    }
                }
            }
            (TypeRefType::Primitive(PrimitiveType::Unit), Value::Unit, Value::Unit) => {}
            (TypeRefType::Primitive(PrimitiveType::Never), Value::Never, Value::Never) => {}
            (t, b, a) => {
                return Err(format!(
                    "Expected {:?}, got {:?} as before and {:?} as after",
                    t, b, a
                ))
            }
        };
        Ok((v, didnt_have_source))
    }
}

fn make_error(s: &Source) -> String {
    let file = &s.file;
    let (col_start, col_end) = s.col;
    let (line_start, _line_end) = s.line;
    let relative_path = file
        .strip_prefix(std::env::current_dir().unwrap_or_default())
        .unwrap_or(file)
        .display();
    let contents = std::fs::read_to_string(file).unwrap_or_default();
    let lines: Vec<&str> = contents.lines().collect();
    if line_start == 0 || line_start > lines.len() {
        return format!(
            "Could not read source file {}, invalid line number {}",
            relative_path, line_start
        );
    }

    let line = lines[line_start - 1];
    if col_start == 0 || col_start > line.len() + 1 || col_end > line.len() + 1 {
        return format!(
            "Could not read source file {}, invalid column number {}",
            relative_path, col_start
        );
    }
    let indicator = " ".repeat(col_start - 1) + &"^".repeat(col_end - col_start.max(1));

    return format!("Try marking this as mutable: \n--> {relative_path}:{line_start}:{col_start}\n     |\n{line_start:>4} | {line}\n     | {indicator}\n");
}

impl Default for TypeRef {
    fn default() -> Self {
        Self {
            type_ref: TypeRefType::Primitive(PrimitiveType::Unit),
            kind: TypeRefKind::Value,
            source: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeRefKind {
    Value,
    Ref,
    RefMut,
    Ptr,
    PtrMut,
    Other,
}

impl From<TypeRefKind> for MutabilityKindCmp {
    fn from(value: TypeRefKind) -> Self {
        match value {
            TypeRefKind::Value => MutabilityKindCmp::Mut,
            TypeRefKind::Ref => MutabilityKindCmp::Not,
            TypeRefKind::RefMut => MutabilityKindCmp::Mut,
            TypeRefKind::Ptr => MutabilityKindCmp::Not,
            TypeRefKind::PtrMut => MutabilityKindCmp::Forced,
            TypeRefKind::Other => MutabilityKindCmp::Mut,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutabilityKindCmp {
    /// Not mutable, so a Ref or Ptr
    Not,
    /// A raw mutable pointer, ignores mutability of parents
    Forced,
    /// RefMut, Value or Other
    Mut,
}

#[derive(Debug, Default, Clone)]
struct MKC(Vec<MutabilityKindCmp>);

impl MKC {
    fn push(&self, m: MutabilityKindCmp) -> Self {
        let mut v = self.0.clone();
        v.push(m);
        Self(v)
    }

    fn is_mutable(&self) -> bool {
        if self.0.is_empty() {
            true
        } else {
            for entry in self.0.iter().rev() {
                match entry {
                    MutabilityKindCmp::Not => return false,
                    MutabilityKindCmp::Forced => return true,
                    MutabilityKindCmp::Mut => continue,
                }
            }
            true
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TypeRefType {
    Primitive(PrimitiveType),
    Type(String),
    Array {
        array_type: ArrayType,
        element_type: Box<TypeRef>,
        length: Option<usize>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArrayType {
    Vec,
    Array,
}

impl Default for TypeRefType {
    fn default() -> Self {
        TypeRefType::Primitive(PrimitiveType::Unit)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimitiveType {
    Bool,
    Isize,
    I8,
    I16,
    I32,
    I64,
    I128,
    Usize,
    U8,
    U16,
    U32,
    U64,
    U128,
    F16,
    F32,
    F64,
    F128,
    Str(StringType),
    Char,
    Unit,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringType {
    Str,
    String,
    CStr,
    CString,
}

impl PrimitiveType {
    pub fn range_u(&self) -> Option<RangeInclusive<u128>> {
        match self {
            PrimitiveType::Usize => Some(0..=usize::MAX as u128),
            PrimitiveType::U8 => Some(0..=u8::MAX as u128),
            PrimitiveType::U16 => Some(0..=u16::MAX as u128),
            PrimitiveType::U32 => Some(0..=u32::MAX as u128),
            PrimitiveType::U64 => Some(0..=u64::MAX as u128),
            PrimitiveType::U128 => Some(0..=u128::MAX as u128),
            _ => None,
        }
    }

    pub fn range_i(&self) -> Option<RangeInclusive<i128>> {
        match self {
            PrimitiveType::Isize => Some(isize::MIN as i128..=isize::MAX as i128),
            PrimitiveType::I8 => Some(i8::MIN as i128..=i8::MAX as i128),
            PrimitiveType::I16 => Some(i16::MIN as i128..=i16::MAX as i128),
            PrimitiveType::I32 => Some(i32::MIN as i128..=i32::MAX as i128),
            PrimitiveType::I64 => Some(i64::MIN as i128..=i64::MAX as i128),
            PrimitiveType::I128 => Some(i128::MIN as i128..=i128::MAX as i128),
            _ => None,
        }
    }

    pub fn range_f(&self) -> Option<RangeInclusive<f64>> {
        match self {
            PrimitiveType::F16 => None,
            PrimitiveType::F32 => Some(f32::MIN as f64..=f32::MAX as f64),
            PrimitiveType::F64 => Some(f64::MIN..=f64::MAX),
            PrimitiveType::F128 => None,
            _ => None,
        }
    }

    pub fn range_char(&self) -> Option<RangeInclusive<char>> {
        match self {
            PrimitiveType::Char => Some('\u{0000}'..='\u{10FFFF}'),
            _ => None,
        }
    }
}
