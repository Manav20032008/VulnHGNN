/* global d3 */

window.SecureCCGraph = (function () {
  let simulation = null;
  let svg = null;
  let zoomLayer = null;

  function destroy(container) {
    if (simulation) {
      simulation.stop();
      simulation = null;
    }
    d3.select(container).selectAll("*").remove();
    svg = null;
    zoomLayer = null;
  }

  function render(container, graphData) {
    destroy(container);

    if (!graphData || !graphData.nodes || !graphData.nodes.length) {
      container.innerHTML =
        '<p class="muted" style="padding:2rem;text-align:center">No graph data for this analysis.</p>';
      return;
    }

    const width = container.clientWidth || 800;
    const height = container.clientHeight || 520;

    const nodes = graphData.nodes.map((n) => ({ ...n }));
    const links = graphData.edges.map((e) => ({
      source: e.source,
      target: e.target,
      type: e.type,
    }));

    svg = d3
      .select(container)
      .append("svg")
      .attr("width", width)
      .attr("height", height)
      .attr("viewBox", [0, 0, width, height]);

    const zoom = d3.zoom().scaleExtent([0.2, 4]).on("zoom", (event) => {
      zoomLayer.attr("transform", event.transform);
    });

    svg.call(zoom);

    zoomLayer = svg.append("g");

    simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3
          .forceLink(links)
          .id((d) => d.id)
          .distance(48)
          .strength(0.4)
      )
      .force("charge", d3.forceManyBody().strength(-120))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(14));

    const link = zoomLayer
      .append("g")
      .attr("stroke", "#2a3344")
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke-width", (d) => (d.type === "data_flow" ? 1.5 : 1))
      .attr("stroke-opacity", 0.7);

    const node = zoomLayer
      .append("g")
      .selectAll("circle")
      .data(nodes)
      .join("circle")
      .attr("r", (d) => (d.highlight ? 9 : d.type === "block" ? 7 : 5))
      .attr("fill", (d) => {
        if (d.highlight) return "#f2555a";
        if (d.type === "block") return "#7c5cff";
        return "#3d9cf0";
      })
      .attr("stroke", (d) => (d.highlight ? "#fff" : "none"))
      .attr("stroke-width", 1.5)
      .call(drag(simulation));

    const labels = zoomLayer
      .append("g")
      .selectAll("text")
      .data(nodes.filter((d) => d.highlight))
      .join("text")
      .text((d) => d.id.slice(0, 24))
      .attr("font-size", 9)
      .attr("fill", "#8b95a8")
      .attr("dx", 10)
      .attr("dy", 3);

    node.append("title").text((d) => d.label || d.id);

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);

      node.attr("cx", (d) => d.x).attr("cy", (d) => d.y);
      labels.attr("x", (d) => d.x).attr("y", (d) => d.y);
    });

    function drag(sim) {
      function dragstarted(event) {
        if (!event.active) sim.alphaTarget(0.3).restart();
        event.subject.fx = event.subject.x;
        event.subject.fy = event.subject.y;
      }
      function dragged(event) {
        event.subject.fx = event.x;
        event.subject.fy = event.y;
      }
      function dragended(event) {
        if (!event.active) sim.alphaTarget(0);
        event.subject.fx = null;
        event.subject.fy = null;
      }
      return d3
        .drag()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended);
    }
  }

  function resetView(container) {
    if (!svg) return;
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 520;
    svg.transition()
      .duration(400)
      .call(
        d3.zoom().transform,
        d3.zoomIdentity.translate(width / 2, height / 2).scale(0.85).translate(-width / 2, -height / 2)
      );
  }

  return { render, destroy, resetView };
})();
