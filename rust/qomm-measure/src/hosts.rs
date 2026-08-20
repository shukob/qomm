//! Stable labels for the machines the measurements were taken on.
//!
//! The reasoning is `mvp/qomm/scripts/hosts.py`'s, and so is the table: real
//! host names identify people and networks, so the label is applied where the
//! name is recorded rather than scrubbed before publication --- a repository
//! that is only safe to publish if someone remembers a step is not safe.
//!
//! This is a second copy of that table, which is a thing worth having only
//! because the alternative is a Rust harness that records a real hostname. The
//! copy is held to the original by `mvp/qomm/tests/test_host_labels.py`, which
//! reads both and fails if they diverge.

/// Every machine that has produced a measurement in this project.
pub const LABELS: &[(&str, &str)] = &[
    ("host-a", "host-a"),      // 64 vCPU, RAM 234 GB, x86_64
    ("host-a", "host-a"),            // the ssh alias for the same machine
    ("host-b", "host-b"),            // 20 vCPU, RAM 62 GB, x86_64
    ("host-b", "host-b"),
    ("host-c", "host-c"),   // 14-inch laptop
];

/// The published name for a machine. Unknown machines keep their name.
pub fn label(node: &str) -> String {
    let short = node.split('.').next().unwrap_or(node);
    for (name, published) in LABELS {
        if *name == node || *name == short {
            return (*published).to_string();
        }
    }
    node.to_string()
}

/// The label for the machine currently running, for harnesses to record.
///
/// `QOMM_HOST` wins when set, so a run inside a container --- where the node
/// name is a hash that no table can hold --- can still say where it really was.
pub fn this_host() -> String {
    if let Ok(name) = std::env::var("QOMM_HOST") {
        if !name.is_empty() { return label(&name); }
    }
    label(&node_name())
}

fn node_name() -> String {
    std::process::Command::new("hostname").output().ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_labels_are_the_python_ones() {
        assert_eq!(label("host-a"), "host-a");
        assert_eq!(label("host-a"), "host-a");
        assert_eq!(label("host-b"), "host-b");
        assert_eq!(label("host-c"), "host-c");
        // A domain is stripped before the second look, so a machine listed
        // without one is found however it announces itself.
        assert_eq!(label("host-a.internal"), "host-a");
        // The laptop is listed *with* `.local`, so its bare form is not in the
        // table and is left alone --- which is what the Python does, and the
        // point of this test is to be the same as the Python.
        assert_eq!(label("host-c"),
                   "host-c");
    }

    #[test]
    fn an_unknown_machine_keeps_its_name() {
        assert_eq!(label("somebody-elses-laptop"), "somebody-elses-laptop");
    }

    #[test]
    fn the_environment_can_say_where_a_container_really_is() {
        // Not run in parallel with anything that reads the same variable: the
        // rest of the crate does not touch it.
        unsafe { std::env::set_var("QOMM_HOST", "host-a") };
        assert_eq!(this_host(), "host-a");
        unsafe { std::env::remove_var("QOMM_HOST") };
    }
}
