/* global d3 */

window.SecureCCGraph = (function () {
  let simulation = null;
  let svg = null;
  let zoomLayer = null;
  let zoomBehavior = null;
  let nodeSelection = null;
  let allNodes = [];
  let lastContainer = null;
  let lastGraphData = null;

  function cssColor(varName, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(varName).trim();
    return v || fallback;
  }

  function palette() {
    return {
      link: cssColor("--border", "#e2e8f0"),
      linkFlow: cssColor("--cyan", "#0891b2"),
      block: cssColor("--purple", "#7c3aed"),
      inst: cssColor("--accent-bright", "#3b82f6"),
      vuln: cssColor("--danger", "#dc2626"),
      vulnStroke: cssColor("--text", "#0f172a"),
      label: cssColor("--text-muted", "#64748b"),
    };
  }

  function showNodeDetail(d) {
    if (!d) return;
    const inLiveEngine = document.querySelector("#live-section-engine:not(.hidden)");
    if (inLiveEngine) {
      /* Live Engine: graph is the UI; tooltips on nodes only */
      return;
    }
    const el = document.querySelector("#graph-node-detail");
    if (!el) return;
    const finding = window.SecureCCLiveEngine?.findingForNode?.(d.id);
  const lineHint = finding?.location?.line
      ? `<p class="muted small">Source line ${finding.location.line} · ${finding.cwe_id || ""}</p>`
      : d.line
        ? `<p class="muted small">Line ${d.line}</p>`
        : "";
    el.innerHTML = `<strong>${d.label || d.id}</strong>
      <p class="muted small">Type: ${d.type || "—"}</p>
      <p class="mono small">${d.id}</p>
      ${lineHint}
      ${d.highlight ? '<p class="badge-block">Evidence / vuln</p>' : ""}`;
    if (finding?.location?.line) {
      el.innerHTML += `<button type="button" class="btn btn-ghost btn-sm live-graph-goto-line">Go to line ${finding.location.line}</button>`;
      el.querySelector(".live-graph-goto-line")?.addEventListener("click", () => {
        window.SecureCCMonaco?.goToLine?.(finding.location.line);
      });
    }
  }

  function destroy(container) {
    if (simulation) {
      simulation.stop();
      simulation = null;
    }
    d3.select(container).selectAll("*").remove();
    svg = null;
    zoomLayer = null;
    nodeSelection = null;
  }

  function render(container, graphData) {
    destroy(container);
    lastContainer = container;
    lastGraphData = graphData;

    const colors = palette();
    container.style.background = cssColor("--graph-canvas", "#f8fafc");

    if (!graphData || !graphData.nodes || !graphData.nodes.length) {
      container.innerHTML =
        '<p class="muted" style="padding:2rem;text-align:center">No graph data for this analysis.</p>';
      return;
    }

    const rect = container.getBoundingClientRect();
    const isLiveHost = container.id === "live-preview-graph-host";
    const width = Math.max(rect.width || container.clientWidth || 0, isLiveHost ? 280 : 400, 200);
    const height = Math.max(
      rect.height || container.clientHeight || 0,
      isLiveHost ? 300 : 400,
      200
    );
    if (isLiveHost) container.style.minHeight = `${Math.min(height, 360)}px`;

    allNodes = graphData.nodes.map((n) => ({ ...n }));
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

    zoomBehavior = d3.zoom().scaleExtent([0.2, 4]).on("zoom", (event) => {
      zoomLayer.attr("transform", event.transform);
    });

    svg.call(zoomBehavior);

    zoomLayer = svg.append("g");

    simulation = d3
      .forceSimulation(allNodes)
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
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke-width", (d) => (d.type === "data_flow" ? 2 : 1))
      .attr("stroke", (d) => (d.type === "data_flow" ? colors.linkFlow : colors.link))
      .attr("stroke-opacity", 0.85);

    nodeSelection = zoomLayer
      .append("g")
      .selectAll("circle")
      .data(allNodes)
      .join("circle")
      .attr("r", (d) => (d.highlight ? 10 : d.type === "block" ? 8 : 5))
      .attr("fill", (d) => {
        if (d.highlight) return colors.vuln;
        if (d.type === "block") return colors.block;
        return colors.inst;
      })
      .attr("stroke", (d) => (d.highlight ? colors.vulnStroke : colors.link))
      .attr("stroke-width", (d) => (d.highlight ? 2 : 1))
      .style("cursor", "pointer")
      .on("click", (_, d) => {
        const inLive = document.querySelector("#live-section-engine:not(.hidden)");
        if (inLive) {
          const f = window.SecureCCLiveEngine?.findingForNode?.(d.id);
          if (f?.location?.line) window.SecureCCMonaco?.goToLine?.(f.location.line);
          return;
        }
        showNodeDetail(d);
      })
      .call(drag(simulation));

    const labels = zoomLayer
      .append("g")
      .selectAll("text")
      .data(allNodes.filter((d) => d.highlight))
      .join("text")
      .text((d) => (d.id || "").slice(0, 24))
      .attr("font-size", 9)
      .attr("fill", colors.label)
      .attr("dx", 10)
      .attr("dy", 3);

    nodeSelection.append("title").text((d) => d.label || d.id);

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);

      nodeSelection.attr("cx", (d) => d.x).attr("cy", (d) => d.y);
      labels.attr("x", (d) => d.x).attr("y", (d) => d.y);
    });

    const firstVuln = allNodes.find((n) => n.highlight);
    if (firstVuln) showNodeDetail(firstVuln);
  }

  function filterNodes(query) {
    if (!nodeSelection) return;
    const q = (query || "").trim().toLowerCase();
    nodeSelection.attr("opacity", (d) => {
      if (!q) return 1;
      const id = (d.id || "").toLowerCase();
      const label = (d.label || "").toLowerCase();
      return id.includes(q) || label.includes(q) ? 1 : 0.12;
    });
  }

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
    return d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended);
  }

  function resetView(container) {
    fitView(container || lastContainer);
  }

  function fitView(container) {
    if (!svg || !container) return;
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 520;
    svg
      .transition()
      .duration(400)
      .call(
        d3.zoom().transform,
        d3.zoomIdentity.translate(width / 2, height / 2).scale(0.85).translate(-width / 2, -height / 2)
      );
  }

  function rerenderLast() {
    if (lastContainer && lastGraphData) render(lastContainer, lastGraphData);
  }

  return { render, destroy, resetView, fitView, filterNodes, rerenderLast };
})();