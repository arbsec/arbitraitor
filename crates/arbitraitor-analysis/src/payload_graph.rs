//! Payload graph for recursive artifact discovery (spec §20).
//!
//! Each artifact is a node identified by its SHA-256 digest. Edges represent
//! relationships between artifacts: downloads, decodes-to, executes, loads,
//! installs, references, and verifies. The graph is recorded in the scan
//! receipt so downstream consumers can reconstruct the full containment and
//! dependency structure of an inspected artifact.

use arbitraitor_artifact::ArtifactType;
use arbitraitor_model::ids::Sha256Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error returned when a payload graph operation fails.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PayloadGraphError {
    /// An edge referenced a node index that does not exist.
    #[error("edge references unknown node index {index}")]
    UnknownNode {
        /// The invalid node index.
        index: usize,
    },
}

/// Directed edge between two payload graph nodes (spec §20.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEdgeType {
    /// The source artifact downloads the target artifact.
    Downloads,
    /// The source artifact decodes to the target artifact (e.g. base64, compression).
    DecodesTo,
    /// The source artifact executes the target artifact.
    Executes,
    /// The source artifact loads the target artifact (e.g. shared library, module).
    Loads,
    /// The source artifact installs the target artifact.
    Installs,
    /// The source artifact references the target artifact (e.g. SBOM component).
    References,
    /// The source artifact verifies the target artifact (e.g. checksum, signature).
    Verifies,
}

/// A node in the payload graph representing a single artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadNode {
    /// SHA-256 digest of the artifact bytes.
    pub digest: Sha256Digest,
    /// Human-readable name or path for the artifact.
    pub name: String,
    /// Classified artifact type, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<ArtifactType>,
}

/// A directed edge between two nodes in the payload graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadEdge {
    /// Index of the source node in [`PayloadGraph::nodes`].
    pub from: usize,
    /// Index of the target node in [`PayloadGraph::nodes`].
    pub to: usize,
    /// Relationship type between the source and target nodes.
    pub edge_type: PayloadEdgeType,
}

/// Payload graph recording artifacts and their relationships (spec §20).
///
/// Each node is an artifact identified by its SHA-256 digest. Edges represent
/// downloads, decodes-to, executes, loads, installs, references, and verifies
/// relationships. The graph is recorded in the scan receipt so downstream
/// consumers can reconstruct the full containment and dependency structure.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadGraph {
    /// All artifact nodes in the graph.
    #[serde(default)]
    pub nodes: Vec<PayloadNode>,
    /// All directed edges between nodes.
    #[serde(default)]
    pub edges: Vec<PayloadEdge>,
}

impl PayloadGraph {
    /// Creates an empty payload graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a node to the graph and returns its index.
    pub fn add_node(&mut self, node: PayloadNode) -> usize {
        let index = self.nodes.len();
        self.nodes.push(node);
        index
    }

    /// Adds a directed edge between two existing nodes.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadGraphError::UnknownNode`] if `from` or `to` does not
    /// reference a valid node index.
    pub fn add_edge(
        &mut self,
        from: usize,
        to: usize,
        edge_type: PayloadEdgeType,
    ) -> Result<(), PayloadGraphError> {
        if from >= self.nodes.len() {
            return Err(PayloadGraphError::UnknownNode { index: from });
        }
        if to >= self.nodes.len() {
            return Err(PayloadGraphError::UnknownNode { index: to });
        }
        self.edges.push(PayloadEdge {
            from,
            to,
            edge_type,
        });
        Ok(())
    }

    /// Returns the node at the given index, if it exists.
    #[must_use]
    pub fn node(&self, index: usize) -> Option<&PayloadNode> {
        self.nodes.get(index)
    }

    /// Returns the indices of nodes that `node` points to via outgoing edges.
    #[must_use]
    pub fn children(&self, node: usize) -> Vec<usize> {
        self.edges
            .iter()
            .filter(|edge| edge.from == node)
            .map(|edge| edge.to)
            .collect()
    }

    /// Returns the indices of nodes that point to `node` via incoming edges.
    #[must_use]
    pub fn parents(&self, node: usize) -> Vec<usize> {
        self.edges
            .iter()
            .filter(|edge| edge.to == node)
            .map(|edge| edge.from)
            .collect()
    }

    /// Returns `true` when the graph is structurally complete for evaluation.
    ///
    /// A graph is complete when it has at least one node (the root artifact)
    /// and every edge references valid node indices. An empty graph or a graph
    /// with dangling edges is incomplete and must not be used for verdict
    /// evaluation.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        if self.nodes.is_empty() {
            return false;
        }
        let node_count = self.nodes.len();
        self.edges
            .iter()
            .all(|edge| edge.from < node_count && edge.to < node_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_digest(value: u8) -> Sha256Digest {
        Sha256Digest::new([value; 32])
    }

    fn sample_graph() -> PayloadGraph {
        let mut graph = PayloadGraph::new();
        let root = graph.add_node(PayloadNode {
            digest: sample_digest(0x01),
            name: "install.sh".to_owned(),
            artifact_type: Some(ArtifactType::ShellScript(
                arbitraitor_artifact::ShellKind::Bash,
            )),
        });
        let tool = graph.add_node(PayloadNode {
            digest: sample_digest(0x02),
            name: "tool.tar.gz".to_owned(),
            artifact_type: Some(ArtifactType::GzipCompressed),
        });
        let checksum = graph.add_node(PayloadNode {
            digest: sample_digest(0x03),
            name: "checksums.txt".to_owned(),
            artifact_type: Some(ArtifactType::GenericText),
        });
        let _ = graph.add_edge(root, tool, PayloadEdgeType::Downloads);
        let _ = graph.add_edge(root, checksum, PayloadEdgeType::Downloads);
        let _ = graph.add_edge(root, tool, PayloadEdgeType::Verifies);
        graph
    }

    #[test]
    fn add_node_returns_incrementing_index() {
        let mut graph = PayloadGraph::new();
        let first = graph.add_node(PayloadNode {
            digest: sample_digest(0x01),
            name: "a".to_owned(),
            artifact_type: None,
        });
        let second = graph.add_node(PayloadNode {
            digest: sample_digest(0x02),
            name: "b".to_owned(),
            artifact_type: None,
        });
        assert_eq!(first, 0);
        assert_eq!(second, 1);
        assert_eq!(graph.nodes.len(), 2);
    }

    #[test]
    fn add_edge_rejects_unknown_from_index() {
        let mut graph = PayloadGraph::new();
        graph.add_node(PayloadNode {
            digest: sample_digest(0x01),
            name: "a".to_owned(),
            artifact_type: None,
        });
        let result = graph.add_edge(5, 0, PayloadEdgeType::Downloads);
        assert_eq!(result, Err(PayloadGraphError::UnknownNode { index: 5 }));
    }

    #[test]
    fn add_edge_rejects_unknown_to_index() {
        let mut graph = PayloadGraph::new();
        graph.add_node(PayloadNode {
            digest: sample_digest(0x01),
            name: "a".to_owned(),
            artifact_type: None,
        });
        let result = graph.add_edge(0, 99, PayloadEdgeType::Executes);
        assert_eq!(result, Err(PayloadGraphError::UnknownNode { index: 99 }));
    }

    #[test]
    fn children_returns_outgoing_targets() {
        let graph = sample_graph();
        let children = graph.children(0);
        assert_eq!(children, vec![1, 2, 1]);
    }

    #[test]
    fn parents_returns_incoming_sources() {
        let graph = sample_graph();
        let parents = graph.parents(1);
        assert_eq!(parents, vec![0, 0]);
    }

    #[test]
    fn children_of_leaf_node_is_empty() {
        let graph = sample_graph();
        assert!(graph.children(2).is_empty());
    }

    #[test]
    fn parents_of_root_node_is_empty() {
        let graph = sample_graph();
        assert!(graph.parents(0).is_empty());
    }

    #[test]
    fn is_complete_true_for_valid_graph() {
        let graph = sample_graph();
        assert!(graph.is_complete());
    }

    #[test]
    fn is_complete_false_for_empty_graph() {
        let graph = PayloadGraph::new();
        assert!(!graph.is_complete());
    }

    #[test]
    fn is_complete_true_for_single_node_without_edges() {
        let mut graph = PayloadGraph::new();
        graph.add_node(PayloadNode {
            digest: sample_digest(0x01),
            name: "lonely".to_owned(),
            artifact_type: None,
        });
        assert!(graph.is_complete());
    }

    #[test]
    fn node_returns_reference_for_valid_index() {
        let graph = sample_graph();
        let node = graph.node(0);
        assert_eq!(node.map(|n| n.name.as_str()), Some("install.sh"));
    }

    #[test]
    fn node_returns_none_for_out_of_bounds() {
        let graph = sample_graph();
        assert!(graph.node(99).is_none());
    }

    #[test]
    fn serde_round_trip_preserves_graph() -> Result<(), Box<dyn std::error::Error>> {
        let graph = sample_graph();
        let json = serde_json::to_string(&graph)?;
        let decoded: PayloadGraph = serde_json::from_str(&json)?;
        assert_eq!(decoded, graph);
        Ok(())
    }

    #[test]
    fn serde_round_trip_with_empty_graph() -> Result<(), Box<dyn std::error::Error>> {
        let graph = PayloadGraph::new();
        let json = serde_json::to_string(&graph)?;
        let decoded: PayloadGraph = serde_json::from_str(&json)?;
        assert_eq!(decoded, graph);
        Ok(())
    }

    #[test]
    fn serde_edge_type_uses_snake_case() -> Result<(), Box<dyn std::error::Error>> {
        let edge_type = PayloadEdgeType::DecodesTo;
        let json = serde_json::to_string(&edge_type)?;
        assert_eq!(json, "\"decodes_to\"");
        let decoded: PayloadEdgeType = serde_json::from_str(&json)?;
        assert_eq!(decoded, edge_type);
        Ok(())
    }

    #[test]
    fn serde_node_without_artifact_type_omits_field() -> Result<(), Box<dyn std::error::Error>> {
        let node = PayloadNode {
            digest: sample_digest(0x42),
            name: "mystery".to_owned(),
            artifact_type: None,
        };
        let json = serde_json::to_string(&node)?;
        assert!(!json.contains("artifact_type"));
        let decoded: PayloadNode = serde_json::from_str(&json)?;
        assert_eq!(decoded, node);
        Ok(())
    }
}
