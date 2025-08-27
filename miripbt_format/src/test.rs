use std::collections::HashMap;

use checkito::{Generate, Shrink};

use crate::{communication::Mutability, Function, MiriPBTFormat, Type, TypeRefType};

pub struct MutabilityGenerator {
    format: MiriPBTFormat,
    function: Function,
}

impl Generate for MutabilityGenerator {
    type Item = HashMap<String, Mutability>;

    type Shrink = MutabilityShrinker;

    fn generate(&self, _state: &mut checkito::generate::State) -> Self::Shrink {
        let state = self.make_default_state();
        let options = flatten_mutabilities(state);

        MutabilityShrinker { options }
    }
}

impl MutabilityGenerator {
    pub fn new(format: MiriPBTFormat, function_name: &str) -> Option<Self> {
        let function = format.find_function(function_name)?;
        Some(Self {
            function: function.clone(),
            format,
        })
    }

    pub fn make_default_state(&self) -> HashMap<String, Mutability> {
        self.function
            .args
            .iter()
            .map(|(arg, v)| {
                let mutable = v.kind.into();

                (
                    arg.clone(),
                    Mutability {
                        mutable,
                        children: mutability_children(&v.type_ref, &self.format),
                    },
                )
            })
            .collect()
    }
}

fn mutability_children(t: &TypeRefType, format: &MiriPBTFormat) -> HashMap<String, Mutability> {
    match t {
        TypeRefType::Primitive(_) => HashMap::new(),
        TypeRefType::Type(name) => {
            if let Some(Type::Struct(s)) = format.find_type(name) {
                s.fields
                    .iter()
                    .map(|(k, v)| {
                        let mutable = v.kind.into();
                        (
                            k.clone(),
                            Mutability {
                                mutable,
                                children: mutability_children(&v.type_ref, format),
                            },
                        )
                    })
                    .collect()
            } else {
                HashMap::new()
            }
        }
        TypeRefType::Array { .. } => HashMap::new(),
    }
}

pub fn flatten_mutabilities(
    mutabilities: HashMap<String, Mutability>,
) -> Vec<HashMap<String, Mutability>> {
    let mut results = vec![];
    let flipped = flip_all(&mutabilities);
    for (k, v) in flipped {
        for mutability in v {
            let mut new_mutabilities = mutabilities.clone();
            new_mutabilities.insert(k.clone(), mutability);
            results.push(new_mutabilities);
        }
    }
    results.sort_by_key(|m| m.len());
    results.dedup();

    results
}

pub fn flip_all(mutabilities: &HashMap<String, Mutability>) -> HashMap<String, Vec<Mutability>> {
    mutabilities
        .iter()
        .map(|(k, v)| (k.clone(), v.permutations()))
        .collect()
}

impl Mutability {
    pub fn permutations(&self) -> Vec<Self> {
        if self.children.is_empty() {
            return vec![self.clone(), self.flipped()];
        }
        let mut results = vec![];
        for (k, v) in flip_all(&self.children) {
            for mutability in v {
                let mut new_mutability = self.clone();
                new_mutability.children.insert(k.clone(), mutability);
                results.push(new_mutability);
            }
        }
        for (k, v) in flip_all(&self.children) {
            for mutability in v {
                let mut new_mutability = self.flipped();
                new_mutability.children.insert(k.clone(), mutability);
                results.push(new_mutability);
            }
        }
        results
    }

    fn flipped(&self) -> Self {
        Self {
            mutable: match self.mutable {
                crate::communication::MutabilityKind::Immutable => {
                    crate::communication::MutabilityKind::Mutable
                }
                crate::communication::MutabilityKind::Mutable => {
                    crate::communication::MutabilityKind::Immutable
                }
                crate::communication::MutabilityKind::Value => {
                    crate::communication::MutabilityKind::Value
                }
            },
            children: self.children.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MutabilityShrinker {
    options: Vec<HashMap<String, Mutability>>,
}

impl Shrink for MutabilityShrinker {
    type Item = HashMap<String, Mutability>;

    fn item(&self) -> Self::Item {
        self.options.first().cloned().unwrap_or_default()
    }

    fn shrink(&mut self) -> Option<Self> {
        self.options.pop()?;
        Some(self.clone())
    }
}
