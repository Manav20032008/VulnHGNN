class GraphAdapter:
    @staticmethod
    def unwrap(sample):
        if isinstance(sample, dict) and "graph" in sample:
            return sample["graph"]
        return sample

    @staticmethod
    def graph(sample):
        graph = GraphAdapter.unwrap(sample)
        if not hasattr(graph, "nodes") or not hasattr(graph, "edges"):
            raise TypeError(f"Expected NetworkX graph, got {type(graph)!r}")
        return graph

    @staticmethod
    def nodes(sample):
        return GraphAdapter.graph(sample).nodes(data=True)

    @staticmethod
    def edges(sample):
        return GraphAdapter.graph(sample).edges(data=True)

    @staticmethod
    def metadata(sample):
        if isinstance(sample, dict):
            return {
                "filename": sample.get("filename", ""),
                "sample_id": sample.get("sample_id", ""),
            }
        return {}
