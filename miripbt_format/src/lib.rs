use std::{
    collections::HashMap,
    ops::{RangeInclusive},
};

use serde::{Deserialize, Serialize};

pub mod communication;

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
            if !self.types.iter().any(|existing| existing.name == t.name) {
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
        self.types.iter().find(|t| t.name == ref_name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Type {
    pub name: String,
    pub fields: HashMap<String, TypeRef>,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeRefKind {
    Value,
    Ref,
    RefMut,
    Ptr,
    PtrMut,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TypeRefType {
    Primitive(PrimitiveType),
    Struct(String),
}

impl Default for TypeRefType {
    fn default() -> Self {
        TypeRefType::Primitive(PrimitiveType::Unit)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    Str,
    Char,
    Unit,
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
