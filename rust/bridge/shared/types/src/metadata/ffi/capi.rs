use std::alloc::Layout;
use std::collections::BTreeSet;
use std::sync::Arc;

use serde::Serialize;

use crate::metadata::Enum;

/// A C type name which consists of a single identifier
pub type CTypeName = String;
/// A C type which is: `identifier | "const" identifier "*" | identifier "*"`
pub type CPtrTypeName = String;
pub type CFunctionName = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RustType {
    // We want name first so that the sort order is stable.
    pub name: &'static str,
    #[serde(skip)]
    pub id: std::any::TypeId,
}
impl RustType {
    pub fn of<T: ?Sized + 'static>() -> Self {
        Self {
            name: std::any::type_name::<T>(),
            id: std::any::TypeId::of::<T>(),
        }
    }
}

fn layout_serialize<S>(layout: &Option<Layout>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    #[derive(Serialize)]
    struct Layout {
        size: usize,
        align: usize,
    }
    layout
        .map(|l| Layout {
            size: l.size(),
            align: l.align(),
        })
        .serialize(s)
}

#[derive(Debug, Clone, derive_more::From, PartialEq, Eq, Serialize)]
pub enum UtilityTypedef {
    #[from]
    String(String),
    StructTypedef {
        type_name: CTypeName,
        /// `(name, type, offset)`
        fields: Vec<(String, CPtrTypeName, usize)>,
    },
    EnumWithPayloads {
        type_name: CTypeName,
        ty: Enum<CPtrTypeName>,
    },
    EnumWithoutPayloads {
        type_name: CTypeName,
        /// `(name, value)`
        variants: Vec<(String, i128)>,
        repr_ty: Option<CTypeName>,
    },
}

impl Default for UtilityTypedef {
    fn default() -> Self {
        UtilityTypedef::String(String::new())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CType {
    pub rust_type: RustType,
    pub dependencies: BTreeSet<RustType>,
    // Starts with "Signal" in most cases
    pub type_name: CTypeName,
    pub ptr_type_name: Option<CPtrTypeName>,
    pub mangling_component: String,
    pub utility_typedefs: UtilityTypedef,
    #[serde(serialize_with = "layout_serialize")]
    pub layout: Option<Layout>,
}
impl CType {
    pub fn ptr_type_name(&self) -> &CPtrTypeName {
        self.ptr_type_name.as_ref().unwrap_or(&self.type_name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CFunctionPrototype {
    pub result: Arc<CType>,
    pub args: Vec<(String, Arc<CType>)>,
}
