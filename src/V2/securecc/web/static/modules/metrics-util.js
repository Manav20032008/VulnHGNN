export function graphMetricCounts(data) {
  const viz = data?.graph;
  const sg = data?.scan?.graph;
  if (viz && typeof viz.total_nodes === "number") {
    const nodes = viz.shown_nodes ?? viz.total_nodes;
    const edges = Array.isArray(viz.edges) ? viz.edges.length : viz.edge_count;
    if (typeof edges === "number") return { nodes, edges };
    return { nodes, edges: "—" };
  }
  if (sg && typeof sg.nodes === "number") {
    return {
      nodes: sg.nodes,
      edges: typeof sg.edges === "number" ? sg.edges : "—",
    };
  }
  if (sg && Array.isArray(sg.nodes)) {
    return {
      nodes: sg.nodes.length,
      edges: Array.isArray(sg.edges) ? sg.edges.length : "—",
    };
  }
  if (viz && Array.isArray(viz.nodes)) {
    return {
      nodes: viz.nodes.length,
      edges: Array.isArray(viz.edges) ? viz.edges.length : "—",
    };
  }
  return { nodes: "—", edges: "—" };
}