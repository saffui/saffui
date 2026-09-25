//! The reader behind the drift check: it walks the store's source with `syn`
//! and rebuilds each statement the way the code builds it.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use models::paging::Window;
use postgres_types::ToSql;
use quote::ToTokens;
use store::query::list_query::{ListQuery, SortDirection};
use store::query::statement;
use store::query::write_set::{Bind, WriteSet, col};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{BinOp, Expr, FnArg, ImplItemFn, ItemFn, ItemMod, Lit, Pat, Stmt, Token, Type, UnOp};

/// The calls that hand a statement to the database.
const SENDS: &[&str] = &[
    "query",
    "query_one",
    "query_opt",
    "execute",
    "batch_execute",
    "query_typed",
    "query_typed_one",
    "prepare",
    "prepare_cached",
];

/// The calls that return a statement already prepared, whose text was read
/// where it was prepared.
const PREPARES: &[&str] = &["prepare", "prepare_cached", "prepared"];

/// What an error says when a statement depends on a parameter, which the
/// reader follows to the places that call the function.
const HANDED: &str = "a parameter this function is handed";

/// A statement found in the source: where it is sent from, and what it reads
/// as, or why it could not be read.
pub(crate) struct Found {
    pub(crate) file: String,
    pub(crate) line: usize,
    pub(crate) function: String,
    /// Where the function was called from, for a statement read at a call.
    pub(crate) via: Option<String>,
    pub(crate) batch: bool,
    /// How many values the call binds, where the reader can count them.
    pub(crate) binds: Option<usize>,
    pub(crate) read: Result<Vec<String>, String>,
}

impl Found {
    pub(crate) fn at(&self) -> String {
        match &self.via {
            Some(via) => format!("{}:{} (called at {via})", self.file, self.line),
            None => format!("{}:{}", self.file, self.line),
        }
    }
}

/// What an expression was worked out to be.
#[derive(Clone)]
enum Value {
    /// The texts it can be: one, or one per branch the reader could not decide.
    Text(Vec<String>),
    /// A `WriteSet`, by the columns it assigns and the ones it filters on.
    Set {
        assigned: Vec<String>,
        filtered: Vec<String>,
    },
    /// A `ListQuery`, by what was asked of it.
    List(ListShape),
    /// A list of names.
    Names(Vec<String>),
}

#[derive(Clone, Default)]
struct ListShape {
    filters: Vec<String>,
    prefix: Option<Vec<String>>,
    kept: Vec<String>,
    sort: Vec<(String, bool)>,
}

impl ListShape {
    /// The real `ListQuery`, built from the shape with values that bind
    /// nothing: a statement's text does not depend on its values.
    fn built(&self) -> ListQuery<'static> {
        let mut query = ListQuery::new(Window {
            first: 0,
            max: 10,
            clamped: false,
        })
        .filter(self.filters.iter().map(|name| bound(name)).collect());
        if let Some(columns) = &self.prefix {
            let columns: Vec<&'static str> = columns.iter().map(|name| leaked(name)).collect();
            query = query.starting_with(Vec::leak(columns), &NOTHING);
        }
        for condition in &self.kept {
            query = query.keeping_only(leaked(condition));
        }
        for (column, ascending) in &self.sort {
            let direction = if *ascending {
                SortDirection::Ascending
            } else {
                SortDirection::Descending
            };
            query = query.sorted_by(leaked(column), direction);
        }
        query
    }
}

static NOTHING: Option<String> = None;

fn leaked(text: &str) -> &'static str {
    Box::leak(text.to_owned().into_boxed_str())
}

fn bound(name: &str) -> Bind<'static> {
    col(leaked(name), &NOTHING as &(dyn ToSql + Sync))
}

/// What a name stands for where a statement is read.
#[derive(Clone)]
enum Binding {
    /// What a `let` bound, with the names as they stood before it, so that a
    /// `let` shadowing a name reads the name it shadows.
    Local(Box<Expr>, Vec<HashMap<String, Binding>>),
    /// One element of a tuple a `let` took apart, likewise.
    Element(Box<Expr>, usize, Vec<HashMap<String, Binding>>),
    /// A value worked out already: an argument at a call, a loop's item.
    Worked(Value),
    /// A parameter holding a list query, read as one nobody narrowed.
    ListParameter,
    Parameter,
}

/// A function of the store, kept to be read again at each call.
struct Function {
    file: String,
    module: Vec<String>,
    name: String,
    parameters: Vec<(String, bool)>,
    block: syn::Block,
}

/// The constants, imports and functions of every module, found before any
/// statement is read, so that a statement may name one declared further down.
#[derive(Default)]
struct Store {
    constants: HashMap<(Vec<String>, String), (Expr, Vec<String>)>,
    imports: HashMap<(Vec<String>, String), Vec<String>>,
    functions: HashMap<(Vec<String>, String), Function>,
}

/// The module a source file is, as a path from the crate root.
fn module_of(relative: &Path) -> Vec<String> {
    let mut path: Vec<String> = relative
        .with_extension("")
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    if matches!(path.last().map(String::as_str), Some("mod" | "lib")) {
        path.pop();
    }
    path
}

fn is_test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .meta
                .to_token_stream()
                .to_string()
                .contains("test")
    })
}

/// A path made absolute from inside `module`, or nothing for one that leaves
/// the crate.
fn absolute(module: &[String], path: &[String]) -> Option<Vec<String>> {
    let mut at: Vec<String> = module.to_vec();
    let mut rest = path;
    match path.first().map(String::as_str) {
        Some("crate") => {
            at.clear();
            rest = &path[1..];
        }
        Some("self") => rest = &path[1..],
        Some("super") => {
            while rest.first().map(String::as_str) == Some("super") {
                at.pop();
                rest = &rest[1..];
            }
        }
        _ => return None,
    }
    at.extend(rest.iter().cloned());
    Some(at)
}

fn collect_uses(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    found: &mut Vec<(String, Vec<String>)>,
) {
    match tree {
        syn::UseTree::Path(held) => {
            prefix.push(held.ident.to_string());
            collect_uses(&held.tree, prefix, found);
            prefix.pop();
        }
        syn::UseTree::Name(held) => {
            let mut path = prefix.clone();
            path.push(held.ident.to_string());
            found.push((held.ident.to_string(), path));
        }
        syn::UseTree::Rename(held) => {
            let mut path = prefix.clone();
            path.push(held.ident.to_string());
            found.push((held.rename.to_string(), path));
        }
        syn::UseTree::Group(held) => {
            for item in &held.items {
                collect_uses(item, prefix, found);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

fn parameters_of(inputs: &Punctuated<FnArg, Token![,]>) -> Vec<(String, bool)> {
    inputs
        .iter()
        .filter_map(|input| match input {
            FnArg::Typed(typed) => match &*typed.pat {
                Pat::Ident(named) => Some((named.ident.to_string(), names_list_query(&typed.ty))),
                _ => None,
            },
            FnArg::Receiver(_) => None,
        })
        .collect()
}

impl Store {
    fn gather(&mut self, file: &str, module: &[String], items: &[syn::Item]) {
        for item in items {
            match item {
                syn::Item::Const(held) => {
                    self.constants.insert(
                        (module.to_vec(), held.ident.to_string()),
                        ((*held.expr).clone(), module.to_vec()),
                    );
                }
                syn::Item::Use(held) => {
                    let mut found = Vec::new();
                    collect_uses(&held.tree, &mut Vec::new(), &mut found);
                    for (alias, path) in found {
                        if let Some(path) = absolute(module, &path) {
                            self.imports.insert((module.to_vec(), alias), path);
                        }
                    }
                }
                syn::Item::Fn(held) if !is_test_only(&held.attrs) => {
                    let name = held.sig.ident.to_string();
                    self.functions.insert(
                        (module.to_vec(), name.clone()),
                        Function {
                            file: file.to_owned(),
                            module: module.to_vec(),
                            name,
                            parameters: parameters_of(&held.sig.inputs),
                            block: (*held.block).clone(),
                        },
                    );
                }
                syn::Item::Mod(held) if !is_test_only(&held.attrs) => {
                    if let Some((_, items)) = &held.content {
                        let mut inner = module.to_vec();
                        inner.push(held.ident.to_string());
                        self.gather(file, &inner, items);
                    }
                }
                _ => {}
            }
        }
    }

    /// Where a path used inside `module` leads, as a key into the maps.
    fn resolve(&self, module: &[String], path: &[String]) -> Option<(Vec<String>, String)> {
        let whole = if let [name] = path {
            match self.imports.get(&(module.to_vec(), name.clone())) {
                Some(imported) => imported.clone(),
                None => return Some((module.to_vec(), name.clone())),
            }
        } else {
            absolute(module, path).or_else(|| {
                // A path through an imported module: `events::CHANNEL`.
                let imported = self.imports.get(&(module.to_vec(), path[0].clone()))?;
                let mut whole = imported.clone();
                whole.extend(path[1..].iter().cloned());
                Some(whole)
            })?
        };
        let (name, at) = whole.split_last()?;
        Some((at.to_vec(), name.clone()))
    }
}

/// Reads statements, a function at a time, or one function again at a call.
struct Reader<'a> {
    store: &'a Store,
    /// The functions whose statements depend on what they are handed, read
    /// again at each call; empty on the first reading.
    handed: &'a HashSet<(Vec<String>, String)>,
    file: String,
    module: Vec<String>,
    function: String,
    via: Option<String>,
    depth: usize,
    scopes: Vec<HashMap<String, Binding>>,
    found: Vec<Found>,
}

impl<'a> Reader<'a> {
    fn new(store: &'a Store, handed: &'a HashSet<(Vec<String>, String)>, file: &str) -> Self {
        Reader {
            store,
            handed,
            file: file.to_owned(),
            module: Vec::new(),
            function: String::new(),
            via: None,
            depth: 0,
            scopes: Vec::new(),
            found: Vec::new(),
        }
    }

    /// The same reader, with one more scope of names on top.
    fn with(&self, scope: HashMap<String, Binding>) -> Reader<'a> {
        let mut scopes = self.scopes.clone();
        scopes.push(scope);
        Reader {
            store: self.store,
            handed: self.handed,
            file: self.file.clone(),
            module: self.module.clone(),
            function: self.function.clone(),
            via: self.via.clone(),
            depth: self.depth,
            scopes,
            found: Vec::new(),
        }
    }

    /// A reader inside `function`, its parameters bound to what a call hands
    /// it, evaluated where the call is.
    fn calling(&self, function: &Function, arguments: &[&Expr], via: String) -> Reader<'a> {
        let mut scope = HashMap::new();
        for ((name, list), argument) in function.parameters.iter().zip(arguments) {
            let binding = match self.evaluate(argument, 0) {
                Ok(value) => Binding::Worked(value),
                Err(_) if *list => Binding::ListParameter,
                Err(_) => Binding::Parameter,
            };
            scope.insert(name.clone(), binding);
        }
        Reader {
            store: self.store,
            handed: self.handed,
            file: function.file.clone(),
            module: function.module.clone(),
            function: function.name.clone(),
            via: Some(via),
            depth: self.depth + 1,
            scopes: vec![scope],
            found: Vec::new(),
        }
    }

    fn binding(&self, name: &str) -> Option<&Binding> {
        self.scopes.iter().rev().find_map(|scope| scope.get(name))
    }

    /// The same reader, with the names as they stood at an earlier point.
    fn before(&self, scopes: &[HashMap<String, Binding>]) -> Reader<'a> {
        let mut earlier = self.with(HashMap::new());
        earlier.scopes = scopes.to_vec();
        earlier
    }

    fn open_function(&mut self, name: String, inputs: &Punctuated<FnArg, Token![,]>) {
        self.function = name;
        let scope = parameters_of(inputs)
            .into_iter()
            .map(|(name, list)| {
                let binding = if list {
                    Binding::ListParameter
                } else {
                    Binding::Parameter
                };
                (name, binding)
            })
            .collect();
        self.scopes = vec![scope];
    }

    fn evaluate(&self, expr: &Expr, depth: usize) -> Result<Value, String> {
        if depth > 48 {
            return Err("an expression nested past what this reader follows".to_owned());
        }
        let deeper = depth + 1;
        match expr {
            Expr::Lit(held) => match &held.lit {
                Lit::Str(text) => Ok(Value::Text(vec![text.value()])),
                Lit::Int(number) => Ok(Value::Text(vec![number.base10_digits().to_owned()])),
                _ => Err(format!("a literal of another kind: {}", shown(expr))),
            },
            Expr::Reference(held) => self.evaluate(&held.expr, deeper),
            Expr::Paren(held) => self.evaluate(&held.expr, deeper),
            Expr::Group(held) => self.evaluate(&held.expr, deeper),
            Expr::Array(held) => {
                let mut names = Vec::new();
                for element in &held.elems {
                    names.extend(texts_of(self.evaluate(element, deeper)?)?);
                }
                Ok(Value::Names(names))
            }
            Expr::Path(held) => self.evaluate_path(&held.path, deeper),
            Expr::Macro(held) => self.evaluate_macro(&held.mac, deeper),
            Expr::MethodCall(call) => self.evaluate_method(call, deeper),
            Expr::Call(call) => self.evaluate_call(call, deeper),
            Expr::Match(held) => self.evaluate_match(held, deeper),
            Expr::If(held) => {
                let otherwise = || match &held.else_branch {
                    Some((_, otherwise)) => self.evaluate(otherwise, deeper),
                    None => Err("an `if` with no `else`".to_owned()),
                };
                match self.decided(&held.cond, deeper) {
                    Some(true) => self.value_of_block(&held.then_branch, deeper),
                    Some(false) => otherwise(),
                    None => {
                        let mut texts = texts_of(self.value_of_block(&held.then_branch, deeper)?)?;
                        texts.extend(texts_of(otherwise()?)?);
                        Ok(Value::Text(texts))
                    }
                }
            }
            Expr::Block(held) => self.value_of_block(&held.block, deeper),
            _ => Err(format!(
                "an expression this reader does not follow: {}",
                shown(expr)
            )),
        }
    }

    fn evaluate_path(&self, path: &syn::Path, depth: usize) -> Result<Value, String> {
        let named: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        if let [name] = named.as_slice() {
            match self.binding(name) {
                Some(Binding::Local(bound, before)) => {
                    return self.before(before).evaluate(bound, depth);
                }
                Some(Binding::Element(bound, index, before)) => {
                    return self.before(before).element(bound, *index, depth);
                }
                Some(Binding::Worked(value)) => return Ok(value.clone()),
                Some(Binding::ListParameter) => return Ok(Value::List(ListShape::default())),
                Some(Binding::Parameter) => return Err(format!("`{name}`, {HANDED}")),
                None => {}
            }
        }
        let found = self
            .store
            .resolve(&self.module, &named)
            .and_then(|key| self.store.constants.get(&key));
        let Some((constant, module)) = found else {
            return Err(format!(
                "`{}`, which this reader cannot find",
                named.join("::")
            ));
        };
        let mut elsewhere = self.with(HashMap::new());
        elsewhere.module = module.clone();
        elsewhere.scopes = Vec::new();
        elsewhere.evaluate(constant, depth)
    }

    /// The `index`th element of the tuple `expr` is, through the branches that
    /// choose it.
    fn element(&self, expr: &Expr, index: usize, depth: usize) -> Result<Value, String> {
        match expr {
            Expr::Tuple(tuple) => match tuple.elems.iter().nth(index) {
                Some(element) => self.evaluate(element, depth + 1),
                None => Err("a tuple shorter than the pattern taking it apart".to_owned()),
            },
            Expr::Paren(held) => self.element(&held.expr, index, depth + 1),
            Expr::Match(held) => {
                let mut texts = Vec::new();
                for arm in self.arms_taken(held, depth) {
                    texts.extend(texts_of(self.element(&arm.body, index, depth + 1)?)?);
                }
                Ok(Value::Text(texts))
            }
            _ => Err(format!(
                "a tuple this reader does not follow: {}",
                shown(expr)
            )),
        }
    }

    /// The arms a `match` can take: the one its scrutinee picks when the
    /// reader knows the scrutinee, all of them otherwise.
    fn arms_taken<'m>(&self, held: &'m syn::ExprMatch, depth: usize) -> Vec<&'m syn::Arm> {
        let known = self
            .evaluate(&held.expr, depth + 1)
            .ok()
            .and_then(|value| one_text(value).ok());
        let Some(known) = known else {
            return held.arms.iter().collect();
        };
        let picked = held.arms.iter().find(|arm| match &arm.pat {
            Pat::Lit(literal) => matches!(&literal.lit, Lit::Str(text) if text.value() == known),
            Pat::Or(any) => any.cases.iter().any(
                |case| matches!(case, Pat::Lit(literal) if matches!(&literal.lit, Lit::Str(text) if text.value() == known)),
            ),
            Pat::Wild(_) | Pat::Ident(_) => true,
            _ => false,
        });
        match picked {
            Some(arm) => vec![arm],
            None => held.arms.iter().collect(),
        }
    }

    fn evaluate_match(&self, held: &syn::ExprMatch, depth: usize) -> Result<Value, String> {
        let mut texts = Vec::new();
        for arm in self.arms_taken(held, depth) {
            texts.extend(texts_of(self.evaluate(&arm.body, depth + 1)?)?);
        }
        Ok(Value::Text(texts))
    }

    /// Whether a condition holds, where the reader can tell.
    fn decided(&self, condition: &Expr, depth: usize) -> Option<bool> {
        if depth > 48 {
            return None;
        }
        match condition {
            Expr::Lit(held) => match &held.lit {
                Lit::Bool(value) => Some(value.value),
                _ => None,
            },
            Expr::Paren(held) => self.decided(&held.expr, depth + 1),
            Expr::Unary(held) if matches!(held.op, UnOp::Not(_)) => {
                self.decided(&held.expr, depth + 1).map(|held| !held)
            }
            Expr::Binary(held) => match held.op {
                BinOp::And(_) => Some(
                    self.decided(&held.left, depth + 1)? && self.decided(&held.right, depth + 1)?,
                ),
                BinOp::Or(_) => Some(
                    self.decided(&held.left, depth + 1)? || self.decided(&held.right, depth + 1)?,
                ),
                BinOp::Eq(_) | BinOp::Ne(_) => {
                    let left = one_text(self.evaluate(&held.left, depth + 1).ok()?).ok()?;
                    let right = one_text(self.evaluate(&held.right, depth + 1).ok()?).ok()?;
                    Some((left == right) == matches!(held.op, BinOp::Eq(_)))
                }
                _ => None,
            },
            Expr::Path(held) => match held
                .path
                .get_ident()
                .and_then(|name| self.binding(&name.to_string()))
            {
                Some(Binding::Local(bound, before)) => {
                    self.before(before).decided(bound, depth + 1)
                }
                _ => None,
            },
            Expr::MethodCall(call) if call.method == "is_empty" && call.args.is_empty() => {
                let texts = texts_of(self.evaluate(&call.receiver, depth + 1).ok()?).ok()?;
                let [text] = texts.as_slice() else {
                    return None;
                };
                Some(text.is_empty())
            }
            Expr::Macro(held) if held.mac.path.is_ident("matches") => {
                let (scrutinee, pattern) = held
                    .mac
                    .parse_body_with(|input: syn::parse::ParseStream| {
                        let scrutinee: Expr = input.parse()?;
                        input.parse::<Token![,]>()?;
                        let pattern = Pat::parse_multi(input)?;
                        Ok((scrutinee, pattern))
                    })
                    .ok()?;
                let known = one_text(self.evaluate(&scrutinee, depth + 1).ok()?).ok()?;
                let cases: Vec<&Pat> = match &pattern {
                    Pat::Or(any) => any.cases.iter().collect(),
                    single => vec![single],
                };
                let mut any = false;
                for case in cases {
                    match case {
                        Pat::Lit(literal) => match &literal.lit {
                            Lit::Str(text) => any |= text.value() == known,
                            _ => return None,
                        },
                        _ => return None,
                    }
                }
                Some(any)
            }
            _ => None,
        }
    }

    /// What a block comes to: its `let`s in order, then its last expression.
    fn value_of_block(&self, block: &syn::Block, depth: usize) -> Result<Value, String> {
        let mut inner = self.with(HashMap::new());
        let Some((Stmt::Expr(last, None), before)) = block.stmts.split_last() else {
            return Err("a block that does not end in a value".to_owned());
        };
        for statement in before {
            if let Stmt::Local(local) = statement {
                inner.bind_local(local);
            }
        }
        inner.evaluate(last, depth + 1)
    }

    fn bind_local(&mut self, local: &syn::Local) {
        let Some(init) = &local.init else {
            return;
        };
        let before = self.scopes.clone();
        let Some(scope) = self.scopes.last_mut() else {
            return;
        };
        let pattern = match &local.pat {
            Pat::Type(typed) => &*typed.pat,
            other => other,
        };
        match pattern {
            Pat::Ident(named) => {
                scope.insert(
                    named.ident.to_string(),
                    Binding::Local(init.expr.clone(), before),
                );
            }
            Pat::Tuple(tuple) => {
                for (index, element) in tuple.elems.iter().enumerate() {
                    if let Pat::Ident(named) = element {
                        scope.insert(
                            named.ident.to_string(),
                            Binding::Element(init.expr.clone(), index, before.clone()),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn evaluate_macro(&self, mac: &syn::Macro, depth: usize) -> Result<Value, String> {
        let name = mac
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        let arguments = mac
            .parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
            .map_err(|why| format!("a `{name}!` this reader cannot parse: {why}"))?;
        match name.as_str() {
            "concat" => {
                let mut whole = vec![String::new()];
                for argument in &arguments {
                    whole = joined(&whole, &texts_of(self.evaluate(argument, depth)?)?);
                }
                Ok(Value::Text(whole))
            }
            "format" => self.evaluate_format(&arguments, depth),
            "vec" => {
                let mut names = Vec::new();
                for element in &arguments {
                    names.push(column_of(element)?);
                }
                Ok(Value::Names(names))
            }
            _ => Err(format!("a `{name}!` this reader does not follow")),
        }
    }

    fn evaluate_format(
        &self,
        arguments: &Punctuated<Expr, Token![,]>,
        depth: usize,
    ) -> Result<Value, String> {
        let mut arguments = arguments.iter();
        let Some(template) = arguments.next() else {
            return Err("a `format!` with nothing to format".to_owned());
        };
        let template = one_text(self.evaluate(template, depth)?)?;
        let mut positional = Vec::new();
        let mut named = HashMap::new();
        for argument in arguments {
            if let Expr::Assign(assigned) = argument {
                named.insert(shown(&assigned.left), (*assigned.right).clone());
            } else {
                positional.push(argument.clone());
            }
        }

        let mut whole = vec![String::new()];
        let mut next = 0;
        let mut characters = template.chars().peekable();
        while let Some(character) = characters.next() {
            match character {
                '{' if characters.peek() == Some(&'{') => {
                    characters.next();
                    whole = joined(&whole, &["{".to_owned()]);
                }
                '}' if characters.peek() == Some(&'}') => {
                    characters.next();
                    whole = joined(&whole, &["}".to_owned()]);
                }
                '{' => {
                    let mut inside = String::new();
                    for held in characters.by_ref() {
                        if held == '}' {
                            break;
                        }
                        inside.push(held);
                    }
                    if inside.contains(':') {
                        return Err(format!(
                            "a placeholder with a format of its own: {{{inside}}}"
                        ));
                    }
                    let filled = if inside.is_empty() {
                        let argument = positional
                            .get(next)
                            .ok_or("a placeholder with no argument")?;
                        next += 1;
                        self.evaluate(argument, depth)?
                    } else if let Ok(index) = inside.parse::<usize>() {
                        let argument = positional
                            .get(index)
                            .ok_or("a placeholder past its arguments")?;
                        self.evaluate(argument, depth)?
                    } else if let Some(argument) = named.get(&inside) {
                        self.evaluate(argument, depth)?
                    } else {
                        let captured = syn::parse_str::<Expr>(&inside)
                            .map_err(|_| format!("a placeholder naming `{inside}`"))?;
                        self.evaluate(&captured, depth)?
                    };
                    whole = joined(&whole, &texts_of(filled)?);
                }
                _ => whole = joined(&whole, &[character.to_string()]),
            }
        }
        Ok(Value::Text(whole))
    }

    fn evaluate_method(&self, call: &syn::ExprMethodCall, depth: usize) -> Result<Value, String> {
        let method = call.method.to_string();
        let arguments: Vec<&Expr> = call.args.iter().collect();
        let receiver = || self.evaluate(&call.receiver, depth);
        match (method.as_str(), arguments.as_slice()) {
            ("as_str" | "to_string" | "to_owned" | "clone" | "into" | "as_ref", [])
            | ("iter" | "into_iter" | "collect", []) => receiver(),
            ("replace", [from, to]) => {
                let (from, to) = (
                    one_text(self.evaluate(from, depth)?)?,
                    one_text(self.evaluate(to, depth)?)?,
                );
                let texts = texts_of(receiver()?)?;
                Ok(Value::Text(
                    texts.iter().map(|text| text.replace(&from, &to)).collect(),
                ))
            }
            ("split", [separator]) => {
                let separator = one_text(self.evaluate(separator, depth)?)?;
                let text = one_text(receiver()?)?;
                Ok(Value::Names(
                    text.split(separator.as_str()).map(str::to_owned).collect(),
                ))
            }
            ("map", [Expr::Closure(closure)]) => {
                let mut inputs = closure.inputs.iter();
                let (Some(Pat::Ident(parameter)), None) = (inputs.next(), inputs.next()) else {
                    return Err("a closure this reader does not follow".to_owned());
                };
                let mut mapped = Vec::new();
                for name in names_of(receiver()?)? {
                    let scope = HashMap::from([(
                        parameter.ident.to_string(),
                        Binding::Worked(Value::Text(vec![name])),
                    )]);
                    mapped.push(one_text(self.with(scope).evaluate(&closure.body, depth)?)?);
                }
                Ok(Value::Names(mapped))
            }
            ("join", [separator]) => {
                let separator = one_text(self.evaluate(separator, depth)?)?;
                Ok(Value::Text(vec![names_of(receiver()?)?.join(&separator)]))
            }
            ("filter", [binds]) => {
                let mut shape = list_of(receiver()?)?;
                shape
                    .filters
                    .extend(names_of(self.evaluate(binds, depth)?)?);
                Ok(Value::List(shape))
            }
            ("scoped_by", [bind]) => {
                let mut shape = list_of(receiver()?)?;
                shape.filters.insert(0, column_of(bind)?);
                Ok(Value::List(shape))
            }
            ("starting_with", [columns, _]) => {
                let mut shape = list_of(receiver()?)?;
                shape.prefix = Some(names_of(self.evaluate(columns, depth)?)?);
                Ok(Value::List(shape))
            }
            ("keeping_only", [condition]) => {
                let mut shape = list_of(receiver()?)?;
                shape.kept.push(one_text(self.evaluate(condition, depth)?)?);
                Ok(Value::List(shape))
            }
            ("sorted_by", [column, direction]) => {
                let mut shape = list_of(receiver()?)?;
                let ascending = !shown(direction).ends_with("Descending");
                shape
                    .sort
                    .push((one_text(self.evaluate(column, depth)?)?, ascending));
                Ok(Value::List(shape))
            }
            ("select", [columns, table]) => {
                let shape = list_of(receiver()?)?;
                let columns = one_text(self.evaluate(columns, depth)?)?;
                let table = one_text(self.evaluate(table, depth)?)?;
                Ok(Value::Text(vec![shape.built().select(&columns, &table)]))
            }
            ("count", [table]) => {
                let shape = list_of(receiver()?)?;
                let table = one_text(self.evaluate(table, depth)?)?;
                Ok(Value::Text(vec![shape.built().count(&table)]))
            }
            ("where_clause", []) => Ok(Value::Text(vec![
                list_of(receiver()?)?.built().where_clause(),
            ])),
            ("order_clause", []) => Ok(Value::Text(vec![
                list_of(receiver()?)?.built().order_clause(),
            ])),
            ("limit_clause", []) => Ok(Value::Text(vec![
                list_of(receiver()?)?.built().limit_clause(),
            ])),
            _ => Err(format!("a call to `.{method}` this reader does not follow")),
        }
    }

    fn evaluate_call(&self, call: &syn::ExprCall, depth: usize) -> Result<Value, String> {
        let Expr::Path(function) = &*call.func else {
            return Err(format!(
                "a call this reader does not follow: {}",
                shown(&call.func)
            ));
        };
        let path: Vec<String> = function
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let arguments: Vec<&Expr> = call.args.iter().collect();
        let tail: Vec<&str> = path.iter().rev().take(2).map(String::as_str).collect();
        match (tail.as_slice(), arguments.as_slice()) {
            (["insert", "statement"], [table, set]) | (["update", "statement"], [table, set]) => {
                let table = one_text(self.evaluate(table, depth)?)?;
                let Value::Set { assigned, filtered } = self.evaluate(set, depth)? else {
                    return Err("a statement built from something other than a set".to_owned());
                };
                let assigned: Vec<Bind<'static>> =
                    assigned.iter().map(|name| bound(name)).collect();
                let filtered: Vec<Bind<'static>> =
                    filtered.iter().map(|name| bound(name)).collect();
                let text = if tail[0] == "insert" {
                    statement::insert(&table, &WriteSet::insert(assigned))
                } else {
                    statement::update(&table, &WriteSet::update(assigned, filtered))
                };
                Ok(Value::Text(vec![text]))
            }
            (["insert", "WriteSet"], [assigned]) => Ok(Value::Set {
                assigned: names_of(self.evaluate(assigned, depth)?)?,
                filtered: Vec::new(),
            }),
            (["update", "WriteSet"], [assigned, filtered]) => Ok(Value::Set {
                assigned: names_of(self.evaluate(assigned, depth)?)?,
                filtered: names_of(self.evaluate(filtered, depth)?)?,
            }),
            (["new", "ListQuery"], [_]) => Ok(Value::List(ListShape::default())),
            (["from", "String"] | ["Borrowed", "Cow"] | ["Owned", "Cow"], [inner]) => {
                self.evaluate(inner, depth)
            }
            _ => {
                // A function of the store that works out a fragment: read its
                // body with what this call hands it.
                let callee = self
                    .store
                    .resolve(&self.module, &path)
                    .and_then(|key| self.store.functions.get(&key));
                match callee {
                    Some(callee) if self.depth < 4 => self
                        .calling(callee, &arguments, String::new())
                        .value_of_block(&callee.block, depth),
                    _ => Err(format!(
                        "a call to `{}` this reader does not follow",
                        path.join("::")
                    )),
                }
            }
        }
    }

    /// Whether `expr` names a statement already prepared, whose text was read
    /// at the call that prepared it.
    fn names_a_prepared_statement(&self, expr: &Expr) -> bool {
        let mut at = expr;
        loop {
            at = match at {
                Expr::Reference(held) => &held.expr,
                Expr::Paren(held) => &held.expr,
                Expr::Try(held) => &held.expr,
                Expr::Await(held) => &held.base,
                Expr::MethodCall(call) if PREPARES.contains(&call.method.to_string().as_str()) => {
                    return true;
                }
                Expr::MethodCall(call) => &call.receiver,
                Expr::Path(held) => match held
                    .path
                    .get_ident()
                    .and_then(|name| self.binding(&name.to_string()))
                {
                    Some(Binding::Local(bound, _)) => bound,
                    _ => return false,
                },
                _ => return false,
            };
        }
    }

    fn record(&mut self, call: &syn::ExprMethodCall) {
        let Some(statement) = call.args.first() else {
            return;
        };
        if self.names_a_prepared_statement(statement) {
            return;
        }
        let read = self.evaluate(statement, 0).and_then(texts_of);
        let binds = match call.method.to_string().as_str() {
            "prepare" | "prepare_cached" | "batch_execute" => None,
            _ => call
                .args
                .iter()
                .nth(1)
                .and_then(|values| self.count_of(values, 0)),
        };
        self.found.push(Found {
            file: self.file.clone(),
            line: call.method.span().start().line,
            function: self.function.clone(),
            via: self.via.clone(),
            batch: call.method == "batch_execute",
            binds,
            read,
        });
    }

    /// How many values an argument binds: a literal list, a set's or a list
    /// query's own, or a local that holds one of those.
    fn count_of(&self, values: &Expr, depth: usize) -> Option<usize> {
        if depth > 48 {
            return None;
        }
        match values {
            Expr::Reference(held) => self.count_of(&held.expr, depth + 1),
            Expr::Paren(held) => self.count_of(&held.expr, depth + 1),
            Expr::Array(held) => Some(held.elems.len()),
            Expr::Macro(held) if held.mac.path.is_ident("vec") => held
                .mac
                .parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
                .ok()
                .map(|elements| elements.len()),
            Expr::MethodCall(call) if call.args.is_empty() => {
                let method = call.method.to_string();
                match (
                    method.as_str(),
                    self.evaluate(&call.receiver, depth + 1).ok()?,
                ) {
                    ("params", Value::Set { assigned, filtered }) => {
                        Some(assigned.len() + filtered.len())
                    }
                    ("bound", Value::List(shape)) => {
                        Some(shape.filters.len() + usize::from(shape.prefix.is_some()))
                    }
                    ("page_params", Value::List(shape)) => {
                        Some(shape.filters.len() + usize::from(shape.prefix.is_some()) + 2)
                    }
                    _ => None,
                }
            }
            Expr::Path(held) => match held
                .path
                .get_ident()
                .and_then(|name| self.binding(&name.to_string()))
            {
                Some(Binding::Local(bound, before)) => {
                    self.before(before).count_of(bound, depth + 1)
                }
                _ => None,
            },
            _ => None,
        }
    }
}

impl<'ast> Visit<'ast> for Reader<'_> {
    fn visit_item_mod(&mut self, module: &'ast ItemMod) {
        if is_test_only(&module.attrs) {
            return;
        }
        self.module.push(module.ident.to_string());
        syn::visit::visit_item_mod(self, module);
        self.module.pop();
    }

    fn visit_item_fn(&mut self, function: &'ast ItemFn) {
        if is_test_only(&function.attrs) {
            return;
        }
        self.open_function(function.sig.ident.to_string(), &function.sig.inputs);
        syn::visit::visit_item_fn(self, function);
    }

    fn visit_impl_item_fn(&mut self, function: &'ast ImplItemFn) {
        if is_test_only(&function.attrs) {
            return;
        }
        self.open_function(function.sig.ident.to_string(), &function.sig.inputs);
        syn::visit::visit_impl_item_fn(self, function);
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.scopes.push(HashMap::new());
        syn::visit::visit_block(self, block);
        self.scopes.pop();
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        syn::visit::visit_local(self, local);
        self.bind_local(local);
    }

    /// Inside a macro whose body is a list of expressions, `tokio::join!`
    /// among them, the statements it sends are read like any other.
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Ok(inside) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) {
            for expr in &inside {
                Visit::visit_expr(self, expr);
            }
        }
    }

    /// Only the branch a decided condition takes: a call in the other one
    /// never runs with what this reading was handed.
    fn visit_expr_if(&mut self, branched: &'ast syn::ExprIf) {
        self.visit_expr(&branched.cond);
        let taken = self.decided(&branched.cond, 0);
        if taken != Some(false) {
            self.visit_block(&branched.then_branch);
        }
        if taken != Some(true)
            && let Some((_, otherwise)) = &branched.else_branch
        {
            self.visit_expr(otherwise);
        }
    }

    /// Likewise, only the arm a known scrutinee picks.
    fn visit_expr_match(&mut self, matched: &'ast syn::ExprMatch) {
        self.visit_expr(&matched.expr);
        for arm in self.arms_taken(matched, 0) {
            self.visit_arm(arm);
        }
    }

    fn visit_expr_for_loop(&mut self, looped: &'ast syn::ExprForLoop) {
        self.visit_expr(&looped.expr);
        let mut scope = HashMap::new();
        if let Pat::Ident(named) = &*looped.pat
            && let Ok(Value::Names(items)) = self.evaluate(&looped.expr, 0)
        {
            scope.insert(named.ident.to_string(), Binding::Worked(Value::Text(items)));
        }
        self.scopes.push(scope);
        self.visit_block(&looped.body);
        self.scopes.pop();
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if SENDS.contains(&call.method.to_string().as_str()) {
            self.record(call);
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(function) = &*call.func
            && self.depth < 4
        {
            let path: Vec<String> = function
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            if let Some(key) = self.store.resolve(&self.module, &path)
                && self.handed.contains(&key)
                && let Some(callee) = self.store.functions.get(&key)
            {
                let arguments: Vec<&Expr> = call.args.iter().collect();
                let via = format!("{}:{}", self.file, call.span().start().line);
                let mut inner = self.calling(callee, &arguments, via);
                inner.visit_block(&callee.block);
                self.found.extend(inner.found);
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn names_list_query(ty: &Type) -> bool {
    match ty {
        Type::Reference(reference) => names_list_query(&reference.elem),
        Type::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "ListQuery"),
        _ => false,
    }
}

/// The column a `col("name", value)` names.
fn column_of(bind: &Expr) -> Result<String, String> {
    if let Expr::Call(call) = bind
        && let Expr::Path(function) = &*call.func
        && function.path.is_ident("col")
        && let Some(Expr::Lit(named)) = call.args.first()
        && let Lit::Str(name) = &named.lit
    {
        return Ok(name.value());
    }
    Err(format!(
        "a bind that is not `col(\"name\", value)`: {}",
        shown(bind)
    ))
}

fn shown(expr: &Expr) -> String {
    expr.to_token_stream().to_string()
}

fn texts_of(value: Value) -> Result<Vec<String>, String> {
    match value {
        Value::Text(texts) => Ok(texts),
        _ => Err("a value that is not a text".to_owned()),
    }
}

fn one_text(value: Value) -> Result<String, String> {
    match texts_of(value)?.as_slice() {
        [text] => Ok(text.clone()),
        _ => Err("a choice of texts where one was needed".to_owned()),
    }
}

fn names_of(value: Value) -> Result<Vec<String>, String> {
    match value {
        Value::Names(names) => Ok(names),
        _ => Err("a value that is not a list of names".to_owned()),
    }
}

fn list_of(value: Value) -> Result<ListShape, String> {
    match value {
        Value::List(shape) => Ok(shape),
        _ => Err("a value that is not a list query".to_owned()),
    }
}

/// Every text `left` can be, followed by every text `right` can be.
fn joined(left: &[String], right: &[String]) -> Vec<String> {
    left.iter()
        .flat_map(|head| right.iter().map(move |tail| format!("{head}{tail}")))
        .collect()
}

fn source_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(
                std::fs::read_dir(&path)
                    .expect("a readable directory")
                    .map(|entry| entry.expect("an entry").path()),
            );
        } else if path.extension().is_some_and(|kind| kind == "rs") {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// Every statement the store sends, read out of its source.
///
/// Read twice: the first reading finds the functions whose statements depend
/// on what they are handed, and the second reads those again at every call,
/// with what the call hands them. A statement read at its calls is not left
/// unread in the function itself.
pub(crate) fn read_the_store() -> Vec<Found> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let parsed: Vec<(String, Vec<String>, syn::File)> = source_files(&root)
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("a readable source");
            let file = syn::parse_file(&text).expect("the store's source parses");
            let relative = path.strip_prefix(&root).expect("a file under the root");
            (
                relative.to_string_lossy().into_owned(),
                module_of(relative),
                file,
            )
        })
        .collect();

    let mut store = Store::default();
    for (file, module, parsed) in &parsed {
        store.gather(file, module, &parsed.items);
    }

    let read = |handed: &HashSet<(Vec<String>, String)>| {
        let mut found = Vec::new();
        for (file, module, parsed) in &parsed {
            let mut reader = Reader::new(&store, handed, file);
            reader.module = module.clone();
            reader.visit_file(parsed);
            found.extend(reader.found);
        }
        found
    };

    let first = read(&HashSet::new());
    let handed: HashSet<(Vec<String>, String)> = first
        .iter()
        .filter(|held| held.read.as_ref().is_err_and(|why| why.contains(HANDED)))
        .filter_map(|held| {
            store
                .functions
                .values()
                .find(|function| function.file == held.file && function.name == held.function)
                .map(|function| (function.module.clone(), function.name.clone()))
        })
        .collect();

    let second = read(&handed);
    let read_at_a_call: HashSet<(String, usize)> = second
        .iter()
        .filter(|held| held.via.is_some())
        .map(|held| (held.file.clone(), held.line))
        .collect();
    second
        .into_iter()
        .filter(|held| {
            held.via.is_some()
                || held.read.is_ok()
                || !read_at_a_call.contains(&(held.file.clone(), held.line))
        })
        .collect()
}
