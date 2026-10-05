//! guard_core — native acceleration for Guard's antivirus engine (`guard_av`).
//!
//! Step 1 of the Rust migration: the CPU-hot paths (rule matching and content
//! heuristics, ~85% of scan time in the Python engine) run here; Python keeps
//! orchestration, I/O, archives and policy. `guard_av._native` loads this
//! module when present and falls back to pure Python otherwise, so behaviour
//! is identical either way (the test suite runs against both backends).
//! Matching releases the GIL, so scans can run on several threads.

pub mod entropy;
pub mod heuristics;
pub mod rules;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

type PyIndicators = Vec<(String, u32, String)>;

fn own(v: Vec<heuristics::Indicator>) -> PyIndicators {
    v.into_iter().map(|(id, s, d)| (id.to_string(), s, d)).collect()
}

#[pyfunction]
fn shannon_entropy(py: Python<'_>, data: &[u8]) -> f64 {
    py.detach(|| entropy::shannon_entropy(data))
}

#[pyfunction]
fn pe_indicators(py: Python<'_>, data: &[u8]) -> PyIndicators {
    own(py.detach(|| heuristics::pe_indicators(data)))
}

#[pyfunction]
fn elf_indicators(py: Python<'_>, data: &[u8]) -> PyIndicators {
    own(py.detach(|| heuristics::elf_indicators(data)))
}

#[pyfunction]
fn macho_indicators(py: Python<'_>, data: &[u8]) -> PyIndicators {
    own(py.detach(|| heuristics::macho_indicators(data)))
}

#[pyfunction]
fn script_indicators(py: Python<'_>, data: &[u8]) -> PyIndicators {
    own(py.detach(|| heuristics::script_indicators(data)))
}

/// Compiled rule set. Built from the JSON list of rule dicts that Python
/// already validated; raises ValueError if a pattern can't be compiled by the
/// Rust regex engine (Python then keeps matching those rules itself).
#[pyclass(name = "RuleSet", frozen)]
struct PyRuleSet {
    inner: rules::RuleSet,
}

#[pymethods]
impl PyRuleSet {
    #[new]
    fn new(rules_json: &str) -> PyResult<Self> {
        rules::RuleSet::from_json(rules_json)
            .map(|inner| PyRuleSet { inner })
            .map_err(PyValueError::new_err)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// -> [(rule_index, evidence), ...] for the rules at `indices` that match.
    fn scan(&self, py: Python<'_>, data: &[u8], indices: Vec<usize>, filesize: i64,
            max_matches: usize) -> Vec<(usize, String)> {
        py.detach(|| self.inner.scan(data, &indices, filesize, max_matches))
    }
}

#[pymodule]
fn guard_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(shannon_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(pe_indicators, m)?)?;
    m.add_function(wrap_pyfunction!(elf_indicators, m)?)?;
    m.add_function(wrap_pyfunction!(macho_indicators, m)?)?;
    m.add_function(wrap_pyfunction!(script_indicators, m)?)?;
    m.add_class::<PyRuleSet>()?;
    Ok(())
}
