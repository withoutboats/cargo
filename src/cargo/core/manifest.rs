use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use semver::Version;
use serde::ser;
use toml;
use url::Url;

use core::interning::InternedString;
use core::profiles::Profiles;
use core::{Dependency, PackageId, PackageIdSpec, SourceId, Summary};
use core::{Edition, Feature, Features, WorkspaceConfig};
use util::errors::*;
use util::toml::TomlManifest;
use util::Config;

pub enum EitherManifest {
    Real(Manifest),
    Virtual(VirtualManifest),
}

/// Contains all the information about a package, as loaded from a Cargo.toml.
#[derive(Clone, Debug)]
pub struct Manifest {
    summary: Summary,
    targets: Vec<Target>,
    links: Option<String>,
    warnings: Warnings,
    exclude: Vec<String>,
    include: Vec<String>,
    metadata: ManifestMetadata,
    custom_metadata: Option<toml::Value>,
    profiles: Profiles,
    publish: Option<Vec<String>>,
    publish_lockfile: bool,
    replace: Vec<(PackageIdSpec, Dependency)>,
    patch: HashMap<Url, Vec<Dependency>>,
    workspace: WorkspaceConfig,
    original: Rc<TomlManifest>,
    features: Features,
    edition: Edition,
    im_a_teapot: Option<bool>,
    default_run: Option<String>,
}

/// When parsing `Cargo.toml`, some warnings should silenced
/// if the manifest comes from a dependency. `ManifestWarning`
/// allows this delayed emission of warnings.
#[derive(Clone, Debug)]
pub struct DelayedWarning {
    pub message: String,
    pub is_critical: bool,
}

#[derive(Clone, Debug)]
pub struct Warnings(Vec<DelayedWarning>);

#[derive(Clone, Debug)]
pub struct VirtualManifest {
    replace: Vec<(PackageIdSpec, Dependency)>,
    patch: HashMap<Url, Vec<Dependency>>,
    workspace: WorkspaceConfig,
    profiles: Profiles,
    warnings: Warnings,
}

/// General metadata about a package which is just blindly uploaded to the
/// registry.
///
/// Note that many of these fields can contain invalid values such as the
/// homepage, repository, documentation, or license. These fields are not
/// validated by cargo itself, but rather it is up to the registry when uploaded
/// to validate these fields. Cargo will itself accept any valid TOML
/// specification for these values.
#[derive(PartialEq, Clone, Debug)]
pub struct ManifestMetadata {
    pub authors: Vec<String>,
    pub keywords: Vec<String>,
    pub categories: Vec<String>,
    pub license: Option<String>,
    pub license_file: Option<String>,
    pub description: Option<String>,   // not markdown
    pub readme: Option<String>,        // file, not contents
    pub homepage: Option<String>,      // url
    pub repository: Option<String>,    // url
    pub documentation: Option<String>, // url
    pub badges: BTreeMap<String, BTreeMap<String, String>>,
    pub links: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LibKind {
    Lib,
    Rlib,
    Dylib,
    ProcMacro,
    Other(String),
}

impl LibKind {
    pub fn from_str(string: &str) -> LibKind {
        match string {
            "lib" => LibKind::Lib,
            "rlib" => LibKind::Rlib,
            "dylib" => LibKind::Dylib,
            "proc-macro" => LibKind::ProcMacro,
            s => LibKind::Other(s.to_string()),
        }
    }

    /// Returns the argument suitable for `--crate-type` to pass to rustc.
    pub fn crate_type(&self) -> &str {
        match *self {
            LibKind::Lib => "lib",
            LibKind::Rlib => "rlib",
            LibKind::Dylib => "dylib",
            LibKind::ProcMacro => "proc-macro",
            LibKind::Other(ref s) => s,
        }
    }

    pub fn linkable(&self) -> bool {
        match *self {
            LibKind::Lib | LibKind::Rlib | LibKind::Dylib | LibKind::ProcMacro => true,
            LibKind::Other(..) => false,
        }
    }
}

impl fmt::Debug for LibKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.crate_type().fmt(f)
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum TargetKind {
    Lib(Vec<LibKind>),
    Bin,
    Test,
    Bench,
    ExampleLib(Vec<LibKind>),
    ExampleBin,
    CustomBuild,
}

impl ser::Serialize for TargetKind {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use self::TargetKind::*;
        match *self {
            Lib(ref kinds) => kinds.iter().map(LibKind::crate_type).collect(),
            Bin => vec!["bin"],
            ExampleBin | ExampleLib(_) => vec!["example"],
            Test => vec!["test"],
            CustomBuild => vec!["custom-build"],
            Bench => vec!["bench"],
        }.serialize(s)
    }
}

impl fmt::Debug for TargetKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::TargetKind::*;
        match *self {
            Lib(ref kinds) => kinds.fmt(f),
            Bin => "bin".fmt(f),
            ExampleBin | ExampleLib(_) => "example".fmt(f),
            Test => "test".fmt(f),
            CustomBuild => "custom-build".fmt(f),
            Bench => "bench".fmt(f),
        }
    }
}

/// Information about a binary, a library, an example, etc. that is part of the
/// package.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct Target {
    kind: TargetKind,
    name: String,
    // Note that the `src_path` here is excluded from the `Hash` implementation
    // as it's absolute currently and is otherwise a little too brittle for
    // causing rebuilds. Instead the hash for the path that we send to the
    // compiler is handled elsewhere.
    src_path: NonHashedPathBuf,
    required_features: Option<Vec<String>>,
    tested: bool,
    benched: bool,
    doc: bool,
    doctest: bool,
    harness: bool, // whether to use the test harness (--test)
    for_host: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct NonHashedPathBuf {
    path: PathBuf,
}

impl Hash for NonHashedPathBuf {
    fn hash<H: Hasher>(&self, _: &mut H) {
        // ...
    }
}

impl fmt::Debug for NonHashedPathBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.path.fmt(f)
    }
}

#[derive(Serialize)]
struct SerializedTarget<'a> {
    /// Is this a `--bin bin`, `--lib`, `--example ex`?
    /// Serialized as a list of strings for historical reasons.
    kind: &'a TargetKind,
    /// Corresponds to `--crate-type` compiler attribute.
    /// See https://doc.rust-lang.org/reference/linkage.html
    crate_types: Vec<&'a str>,
    name: &'a str,
    src_path: &'a PathBuf,
}

impl ser::Serialize for Target {
    fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        SerializedTarget {
            kind: &self.kind,
            crate_types: self.rustc_crate_types(),
            name: &self.name,
            src_path: &self.src_path.path,
        }.serialize(s)
    }
}

compact_debug! {
    impl fmt::Debug for Target {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let (default, default_name) = {
                let src = self.src_path().to_path_buf();
                match &self.kind {
                    TargetKind::Lib(kinds) => {
                        (
                            Target::lib_target(&self.name, kinds.clone(), src.clone()),
                            format!("lib_target({:?}, {:?}, {:?})",
                                    self.name, kinds, src),
                        )
                    }
                    TargetKind::CustomBuild => {
                        (
                            Target::custom_build_target(&self.name, src.clone()),
                            format!("custom_build_target({:?}, {:?})",
                                    self.name, src),
                        )
                    }
                    _ => (
                        Target::with_path(src.clone()),
                        format!("with_path({:?})", src),
                    ),
                }
            };
            [debug_the_fields(
                kind
                name
                src_path
                required_features
                tested
                benched
                doc
                doctest
                harness
                for_host
            )]
        }
    }
}

impl Manifest {
    pub fn new(
        summary: Summary,
        targets: Vec<Target>,
        exclude: Vec<String>,
        include: Vec<String>,
        links: Option<String>,
        metadata: ManifestMetadata,
        custom_metadata: Option<toml::Value>,
        profiles: Profiles,
        publish: Option<Vec<String>>,
        publish_lockfile: bool,
        replace: Vec<(PackageIdSpec, Dependency)>,
        patch: HashMap<Url, Vec<Dependency>>,
        workspace: WorkspaceConfig,
        features: Features,
        edition: Edition,
        im_a_teapot: Option<bool>,
        default_run: Option<String>,
        original: Rc<TomlManifest>,
    ) -> Manifest {
        Manifest {
            summary,
            targets,
            warnings: Warnings::new(),
            exclude,
            include,
            links,
            metadata,
            custom_metadata,
            profiles,
            publish,
            replace,
            patch,
            workspace,
            features,
            edition,
            original,
            im_a_teapot,
            default_run,
            publish_lockfile,
        }
    }

    pub fn dependencies(&self) -> &[Dependency] {
        self.summary.dependencies()
    }
    pub fn exclude(&self) -> &[String] {
        &self.exclude
    }
    pub fn include(&self) -> &[String] {
        &self.include
    }
    pub fn metadata(&self) -> &ManifestMetadata {
        &self.metadata
    }
    pub fn name(&self) -> InternedString {
        self.package_id().name()
    }
    pub fn package_id(&self) -> &PackageId {
        self.summary.package_id()
    }
    pub fn summary(&self) -> &Summary {
        &self.summary
    }
    pub fn targets(&self) -> &[Target] {
        &self.targets
    }
    pub fn version(&self) -> &Version {
        self.package_id().version()
    }
    pub fn warnings_mut(&mut self) -> &mut Warnings {
        &mut self.warnings
    }
    pub fn warnings(&self) -> &Warnings {
        &self.warnings
    }
    pub fn profiles(&self) -> &Profiles {
        &self.profiles
    }
    pub fn publish(&self) -> &Option<Vec<String>> {
        &self.publish
    }
    pub fn publish_lockfile(&self) -> bool {
        self.publish_lockfile
    }
    pub fn replace(&self) -> &[(PackageIdSpec, Dependency)] {
        &self.replace
    }
    pub fn original(&self) -> &TomlManifest {
        &self.original
    }
    pub fn patch(&self) -> &HashMap<Url, Vec<Dependency>> {
        &self.patch
    }
    pub fn links(&self) -> Option<&str> {
        self.links.as_ref().map(|s| &s[..])
    }

    pub fn workspace_config(&self) -> &WorkspaceConfig {
        &self.workspace
    }

    pub fn features(&self) -> &Features {
        &self.features
    }

    pub fn set_summary(&mut self, summary: Summary) {
        self.summary = summary;
    }

    pub fn map_source(self, to_replace: &SourceId, replace_with: &SourceId) -> Manifest {
        Manifest {
            summary: self.summary.map_source(to_replace, replace_with),
            ..self
        }
    }

    pub fn feature_gate(&self) -> CargoResult<()> {
        if self.im_a_teapot.is_some() {
            self.features
                .require(Feature::test_dummy_unstable())
                .chain_err(|| {
                    format_err!(
                        "the `im-a-teapot` manifest key is unstable and may \
                         not work properly in England"
                    )
                })?;
        }

        if self.default_run.is_some() {
            self.features
                .require(Feature::default_run())
                .chain_err(|| {
                    format_err!(
                        "the `default-run` manifest key is unstable"
                    )
                })?;
        }

        Ok(())
    }

    // Just a helper function to test out `-Z` flags on Cargo
    pub fn print_teapot(&self, config: &Config) {
        if let Some(teapot) = self.im_a_teapot {
            if config.cli_unstable().print_im_a_teapot {
                println!("im-a-teapot = {}", teapot);
            }
        }
    }

    pub fn edition(&self) -> Edition {
        self.edition
    }

    pub fn custom_metadata(&self) -> Option<&toml::Value> {
        self.custom_metadata.as_ref()
    }

    pub fn default_run(&self) -> Option<&str> {
        self.default_run.as_ref().map(|s| &s[..])
    }
}

impl VirtualManifest {
    pub fn new(
        replace: Vec<(PackageIdSpec, Dependency)>,
        patch: HashMap<Url, Vec<Dependency>>,
        workspace: WorkspaceConfig,
        profiles: Profiles,
    ) -> VirtualManifest {
        VirtualManifest {
            replace,
            patch,
            workspace,
            profiles,
            warnings: Warnings::new(),
        }
    }

    pub fn replace(&self) -> &[(PackageIdSpec, Dependency)] {
        &self.replace
    }

    pub fn patch(&self) -> &HashMap<Url, Vec<Dependency>> {
        &self.patch
    }

    pub fn workspace_config(&self) -> &WorkspaceConfig {
        &self.workspace
    }

    pub fn profiles(&self) -> &Profiles {
        &self.profiles
    }

    pub fn warnings_mut(&mut self) -> &mut Warnings {
        &mut self.warnings
    }

    pub fn warnings(&self) -> &Warnings {
        &self.warnings
    }
}

impl Target {
    fn with_path(src_path: PathBuf) -> Target {
        assert!(
            src_path.is_absolute(),
            "`{}` is not absolute",
            src_path.display()
        );
        Target {
            kind: TargetKind::Bin,
            name: String::new(),
            src_path: NonHashedPathBuf { path: src_path },
            required_features: None,
            doc: false,
            doctest: false,
            harness: true,
            for_host: false,
            tested: true,
            benched: true,
        }
    }

    pub fn lib_target(name: &str, crate_targets: Vec<LibKind>, src_path: PathBuf) -> Target {
        Target {
            kind: TargetKind::Lib(crate_targets),
            name: name.to_string(),
            doctest: true,
            doc: true,
            ..Target::with_path(src_path)
        }
    }

    pub fn bin_target(
        name: &str,
        src_path: PathBuf,
        required_features: Option<Vec<String>>,
    ) -> Target {
        Target {
            kind: TargetKind::Bin,
            name: name.to_string(),
            required_features,
            doc: true,
            ..Target::with_path(src_path)
        }
    }

    /// Builds a `Target` corresponding to the `build = "build.rs"` entry.
    pub fn custom_build_target(name: &str, src_path: PathBuf) -> Target {
        Target {
            kind: TargetKind::CustomBuild,
            name: name.to_string(),
            for_host: true,
            benched: false,
            tested: false,
            ..Target::with_path(src_path)
        }
    }

    pub fn example_target(
        name: &str,
        crate_targets: Vec<LibKind>,
        src_path: PathBuf,
        required_features: Option<Vec<String>>,
    ) -> Target {
        let kind = if crate_targets.is_empty() {
            TargetKind::ExampleBin
        } else {
            TargetKind::ExampleLib(crate_targets)
        };

        Target {
            kind,
            name: name.to_string(),
            required_features,
            tested: false,
            benched: false,
            ..Target::with_path(src_path)
        }
    }

    pub fn test_target(
        name: &str,
        src_path: PathBuf,
        required_features: Option<Vec<String>>,
    ) -> Target {
        Target {
            kind: TargetKind::Test,
            name: name.to_string(),
            required_features,
            benched: false,
            ..Target::with_path(src_path)
        }
    }

    pub fn bench_target(
        name: &str,
        src_path: PathBuf,
        required_features: Option<Vec<String>>,
    ) -> Target {
        Target {
            kind: TargetKind::Bench,
            name: name.to_string(),
            required_features,
            tested: false,
            ..Target::with_path(src_path)
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn crate_name(&self) -> String {
        self.name.replace("-", "_")
    }
    pub fn src_path(&self) -> &Path {
        &self.src_path.path
    }
    pub fn required_features(&self) -> Option<&Vec<String>> {
        self.required_features.as_ref()
    }
    pub fn kind(&self) -> &TargetKind {
        &self.kind
    }
    pub fn tested(&self) -> bool {
        self.tested
    }
    pub fn harness(&self) -> bool {
        self.harness
    }
    pub fn documented(&self) -> bool {
        self.doc
    }
    pub fn for_host(&self) -> bool {
        self.for_host
    }
    pub fn benched(&self) -> bool {
        self.benched
    }

    pub fn doctested(&self) -> bool {
        self.doctest && match self.kind {
            TargetKind::Lib(ref kinds) => kinds
                .iter()
                .any(|k| *k == LibKind::Rlib || *k == LibKind::Lib || *k == LibKind::ProcMacro),
            _ => false,
        }
    }

    pub fn allows_underscores(&self) -> bool {
        self.is_bin() || self.is_example() || self.is_custom_build()
    }

    pub fn is_lib(&self) -> bool {
        match self.kind {
            TargetKind::Lib(_) => true,
            _ => false,
        }
    }

    pub fn is_dylib(&self) -> bool {
        match self.kind {
            TargetKind::Lib(ref libs) => libs.iter().any(|l| *l == LibKind::Dylib),
            _ => false,
        }
    }

    pub fn is_cdylib(&self) -> bool {
        let libs = match self.kind {
            TargetKind::Lib(ref libs) => libs,
            _ => return false,
        };
        libs.iter().any(|l| match *l {
            LibKind::Other(ref s) => s == "cdylib",
            _ => false,
        })
    }

    pub fn linkable(&self) -> bool {
        match self.kind {
            TargetKind::Lib(ref kinds) => kinds.iter().any(|k| k.linkable()),
            _ => false,
        }
    }

    pub fn is_bin(&self) -> bool {
        self.kind == TargetKind::Bin
    }

    pub fn is_example(&self) -> bool {
        match self.kind {
            TargetKind::ExampleBin | TargetKind::ExampleLib(..) => true,
            _ => false,
        }
    }

    pub fn is_bin_example(&self) -> bool {
        // Needed for --all-examples in contexts where only runnable examples make sense
        match self.kind {
            TargetKind::ExampleBin => true,
            _ => false,
        }
    }

    pub fn is_test(&self) -> bool {
        self.kind == TargetKind::Test
    }
    pub fn is_bench(&self) -> bool {
        self.kind == TargetKind::Bench
    }
    pub fn is_custom_build(&self) -> bool {
        self.kind == TargetKind::CustomBuild
    }

    /// Returns the arguments suitable for `--crate-type` to pass to rustc.
    pub fn rustc_crate_types(&self) -> Vec<&str> {
        match self.kind {
            TargetKind::Lib(ref kinds) | TargetKind::ExampleLib(ref kinds) => {
                kinds.iter().map(LibKind::crate_type).collect()
            }
            TargetKind::CustomBuild
            | TargetKind::Bench
            | TargetKind::Test
            | TargetKind::ExampleBin
            | TargetKind::Bin => vec!["bin"],
        }
    }

    pub fn can_lto(&self) -> bool {
        match self.kind {
            TargetKind::Lib(ref v) => {
                !v.contains(&LibKind::Rlib) && !v.contains(&LibKind::Dylib)
                    && !v.contains(&LibKind::Lib)
            }
            _ => true,
        }
    }

    pub fn set_tested(&mut self, tested: bool) -> &mut Target {
        self.tested = tested;
        self
    }
    pub fn set_benched(&mut self, benched: bool) -> &mut Target {
        self.benched = benched;
        self
    }
    pub fn set_doctest(&mut self, doctest: bool) -> &mut Target {
        self.doctest = doctest;
        self
    }
    pub fn set_for_host(&mut self, for_host: bool) -> &mut Target {
        self.for_host = for_host;
        self
    }
    pub fn set_harness(&mut self, harness: bool) -> &mut Target {
        self.harness = harness;
        self
    }
    pub fn set_doc(&mut self, doc: bool) -> &mut Target {
        self.doc = doc;
        self
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            TargetKind::Lib(..) => write!(f, "Target(lib)"),
            TargetKind::Bin => write!(f, "Target(bin: {})", self.name),
            TargetKind::Test => write!(f, "Target(test: {})", self.name),
            TargetKind::Bench => write!(f, "Target(bench: {})", self.name),
            TargetKind::ExampleBin | TargetKind::ExampleLib(..) => {
                write!(f, "Target(example: {})", self.name)
            }
            TargetKind::CustomBuild => write!(f, "Target(script)"),
        }
    }
}

impl Warnings {
    fn new() -> Warnings {
        Warnings(Vec::new())
    }

    pub fn add_warning(&mut self, s: String) {
        self.0.push(DelayedWarning {
            message: s,
            is_critical: false,
        })
    }

    pub fn add_critical_warning(&mut self, s: String) {
        self.0.push(DelayedWarning {
            message: s,
            is_critical: true,
        })
    }

    pub fn warnings(&self) -> &[DelayedWarning] {
        &self.0
    }
}
