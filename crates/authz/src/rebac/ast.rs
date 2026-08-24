/// Where something was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct At {
    pub line: u32,
    pub column: u32,
}

/// A name, and where it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub text: String,
    pub at: At,
}

/// A whole schema, in source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema {
    pub definitions: Vec<Definition>,
}

/// One type, and what may be said about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    pub name: Name,
    /// In source order, relations and permissions together, because that is how
    /// it was written and printing it back is a thing somebody will want.
    pub members: Vec<Member>,
}

/// A relation stores edges; a permission computes from them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Member {
    Relation(RelationDecl),
    Permission(PermissionDecl),
}

impl Member {
    pub fn name(&self) -> &Name {
        match self {
            Self::Relation(relation) => &relation.name,
            Self::Permission(permission) => &permission.name,
        }
    }
}

/// `relation editor: user | group#member`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationDecl {
    pub name: Name,
    /// What may stand in this relation. Never empty: the grammar requires one.
    pub subjects: Vec<SubjectType>,
}

/// `user`, or `group#member` for the holders of a relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectType {
    pub type_name: Name,
    /// Present for a userset: the relation whose holders stand here.
    pub relation: Option<Name>,
}

/// `permission view = viewer + editor + view from parent`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDecl {
    pub name: Name,
    pub body: Expr,
}

/// What a permission computes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Another member of the same type.
    Member(Name),
    /// `computed from tupleset`: follow the tupleset relation to other objects,
    /// and ask each of them for `computed`.
    Arrow {
        computed: Name,
        tupleset: Name,
        at: At,
    },
    /// Two or more, since the parser never builds one of these from a single
    /// term. An empty one is what makes an intersection grant to everybody.
    Any {
        parts: Vec<Expr>,
        at: At,
    },
    All {
        parts: Vec<Expr>,
        at: At,
    },
}

impl Expr {
    pub fn at(&self) -> At {
        match self {
            Self::Member(name) => name.at,
            Self::Arrow { at, .. } | Self::Any { at, .. } | Self::All { at, .. } => *at,
        }
    }
}
