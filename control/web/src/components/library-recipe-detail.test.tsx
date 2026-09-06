import {render, screen, within} from "@testing-library/react";
import type {ControlApi, LibraryApi, LibraryRecipeDetail, VisualFleetNode, VisualFleetSnapshot} from "../api/types";
import {App} from "../app";
import {fullLibraryDetail, librarySnapshot} from "../test-fixtures/library";
import {LibraryRecipeAuthority} from "./library-recipe-detail";

// Job submission has its own contract tests; these exercise lifecycle copy only.
vi.mock("./artifact-job-workspace", () => ({ArtifactJobWorkspace: () => null}));

function runningDetail(): LibraryRecipeDetail {
  const detail = structuredClone(fullLibraryDetail);
  detail.operational_state.runs = [{run_id: "run-chat", installation_id: "installation-chat", mapping_id: "mapping-chat", recipe_revision_id: "revision-chat", node_ids: ["node-alpha", "node-beta"], route_state: "published", state: "running"}];
  return detail;
}

function healthyFleet(): VisualFleetSnapshot {
  return {
    schema_version: 1, generated_at: librarySnapshot.generated_at, authority_revision: "f".repeat(64), event_cursor: 1,
    nodes: ["node-alpha", "node-beta"].map((id, rank): VisualFleetNode => ({
      id, display_name: id, hostname: id, labels: {}, lifecycle: "ready", installed: [],
      connection: {agent_state: "active", certificate_state: "valid", last_seen_age_seconds: 1, last_seen_at: librarySnapshot.generated_at, offline_reason: null, online_state: "online"},
      inventory: null, telemetry: null, reservations: {disk_bytes: 0, gpu_memory_bytes: 0, host_memory_bytes: 0, port_count: 0, unified_memory_bytes: 0}, warnings: [],
      loaded: [{run_id: "run-chat", recipe_id: "recipe-chat", recipe_revision_id: "revision-chat", installation_id: "installation-chat", alias: "qwen-chat", title: "Qwen Chat", rank, role: rank === 0 ? "leader" : "worker", rank_state: "running", run_state: "running", route_state: "published", rank_fresh: true, rank_age_seconds: 1, healthy: true, group_state: "healthy", expected_rank_count: 2, member_node_ids: ["node-alpha", "node-beta"], present_ranks: [0, 1]}],
    })),
  };
}

function renderRecommendation(detail = runningDetail(), fleet?: VisualFleetSnapshot) {
  render(<LibraryRecipeAuthority api={{} as LibraryApi} detail={detail} fleet={fleet} onRefresh={async () => undefined} policy={librarySnapshot.freshness_policy}/>);
  return screen.getByRole("region", {name: "Recommended next action"});
}

afterEach(() => { history.replaceState(null, "", "/"); vi.restoreAllMocks(); });

test("uses complete healthy Fleet evidence through the Library browser before claiming the model is serving", async () => {
  history.replaceState(null, "", "/library/recipes/recipe-chat");
  const api = {librarySnapshot: async () => librarySnapshot, libraryRecipe: async () => runningDetail(), visualFleet: async () => healthyFleet()} as unknown as ControlApi;
  render(<App api={api}/>);
  const recommendation = await screen.findByRole("heading", {name: "Model is serving"});
  expect(recommendation.closest("section")).toHaveTextContent("Current Fleet evidence shows healthy ranks and published routes.");
  expect(within(recommendation.closest("section")!).getByRole("link", {name: "Open Fleet"})).toHaveAttribute("href", "/fleet");
});

test.each(["withdrawn", "unhealthy", "stale", "degraded", "rank-stopped"])("calls attention to an active run with %s evidence", state => {
  const detail = runningDetail();
  const fleet = healthyFleet();
  if (state === "withdrawn") detail.operational_state.runs[0].route_state = "withdrawn";
  if (state === "unhealthy") fleet.nodes[1].loaded[0].healthy = false;
  if (state === "stale") fleet.nodes[1].loaded[0].rank_fresh = false;
  if (state === "degraded") fleet.nodes[1].loaded[0].group_state = "degraded";
  if (state === "rank-stopped") fleet.nodes[1].loaded[0].rank_state = "stopped";
  const recommendation = renderRecommendation(detail, fleet);
  expect(recommendation).toHaveTextContent("Active run needs attention");
  expect(recommendation).toHaveClass("is-blocked");
  expect(recommendation).not.toHaveTextContent("No lifecycle change is required");
  expect(recommendation).not.toHaveTextContent("Model is serving");
  expect(within(recommendation).getByRole("link", {name: "Open Fleet"})).toBeVisible();
  expect(within(recommendation).queryByRole("button")).not.toBeInTheDocument();
});

test.each(["missing", "incomplete", "other-run", "other-recipe"])("does not infer serving health from %s Fleet evidence", state => {
  const fleet = healthyFleet();
  if (state === "incomplete") fleet.nodes[1].loaded = [];
  if (state === "other-run") fleet.nodes[1].loaded[0].run_id = "another-run";
  if (state === "other-recipe") fleet.nodes[1].loaded[0].recipe_id = "another-recipe";
  const recommendation = renderRecommendation(runningDetail(), state === "missing" ? undefined : fleet);
  expect(recommendation).toHaveTextContent("Check active run health");
  expect(recommendation).not.toHaveTextContent("Model is serving");
});

test("does not mark a logical artifact-job session unhealthy just because its route is withdrawn", () => {
  const detail = runningDetail();
  detail.visual_recipe!.interfaces = [{adapter: "image-job", path: "/outputs"}];
  detail.operational_state.runs[0].route_state = "withdrawn";
  const recommendation = renderRecommendation(detail);
  expect(recommendation).toHaveTextContent("Run is active");
  expect(recommendation).not.toHaveTextContent(/Model is serving|needs attention|No lifecycle change/);
});
