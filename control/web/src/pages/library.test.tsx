import {render, screen, waitFor, within} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type {ControlApi, LibrarySnapshot, PublicRecipe} from "../api/types";
import {App} from "../app";
import {libraryRecipeSummary, librarySnapshot, minimalLibraryDetail} from "../test-fixtures/library";

function recipe(overrides: Partial<PublicRecipe> = {}): PublicRecipe {
  return {
    publisher: "vonk-forge", slug: "glm-5-3-flash", title: "GLM 5.3 Flash NVFP4", description: "Fast GLM recipe", tags: [], uri: `vonk://catalog/vonk-forge/glm@sha256:${"b".repeat(64)}`, content_sha256: "b".repeat(64),
    model_publisher: "zai-org", model_slug: "glm-5-3-flash", model_title: "GLM 5.3 Flash", model_version_publisher: "zai-org", model_version_slug: "glm-5-3-flash-nvfp4", model_version_title: "zai-org/GLM-5.3-Flash-NVFP4", source_owner: "zai-org", source_repository: "https://github.com/zai-org/GLM-5", alignment: "standard", capabilities: ["chat", "reasoning"], qualification: "candidate", qualification_basis: "explicit-candidate-metadata", qualification_detail: "Candidate.", precision: "NVFP4", quantizations: ["NVFP4"], execution_readiness: "executable", execution_readiness_basis: "explicit-executable-metadata", execution_readiness_detail: "Executable.", execution_harness: "vllm-openai", runtime_distribution: "vllm-0-27-1", source_bundle_sha256: "9".repeat(64), artifact_count: 1, topology_name: "dual", topology_mode: "distributed", node_count: 2, topology_roles: [{name: "worker", count: 2, endpoint_owner: true}], fabric: {connectivity: "connected", minimum_bandwidth_mbps: 10000}, expected_download_bytes: 120, maximum_installed_bytes_per_node: 80, maximum_runtime_memory_bytes_per_node: 100, release_version: "1.0.0", release_released_at: "2026-09-01", local: {status: "not-imported", recipe_id: null, revision_number: null, content_sha256: null, release_version: null},
    ...overrides,
  };
}

const emptySnapshot: LibrarySnapshot = {...librarySnapshot, models: [], unlinked_recipes: []};

function largeLibrary(modelCount: number, start = 0): LibrarySnapshot {
  return {...emptySnapshot, models: Array.from({length: modelCount}, (_, index) => {
    const id = start + index;
    return {model: {...librarySnapshot.models[0]!.model, slug: `model-${id}`}, page_local: true, recipes: [libraryRecipeSummary({recipe_id: `recipe-${id}`, slug: `recipe-${id}`, title: id === 0 ? "Qwen evaluation" : `Recipe ${id}`})]};
  })};
}

function publicRows(snapshot: LibrarySnapshot): PublicRecipe[] {
  return snapshot.models.flatMap(model => model.recipes.map(item => recipe({
    slug: item.slug, title: item.title, uri: `vonk://catalog/vonk-forge/${item.slug}@sha256:${"b".repeat(64)}`,
    local: {status: "current", recipe_id: item.recipe_id, revision_number: 3, content_sha256: "a".repeat(64), release_version: "1.0.0"},
  })));
}

test("retains all local authority from a complete API page larger than forty models", async () => {
  history.replaceState(null, "", "/library");
  const snapshot = largeLibrary(73);
  snapshot.models[0]!.recipes.push(...Array.from({length: 11}, (_, index) => libraryRecipeSummary({recipe_id: `extra-${index}`, slug: `extra-${index}`, title: `Extra ${index}`})));
  const catalog = publicRows(snapshot);
  snapshot.models[0]!.recipes.push(libraryRecipeSummary({recipe_id: "custom-eval", slug: "custom-eval", title: "Qwen custom evaluation"}));
  const api = {librarySnapshot: async () => snapshot, listPublicRecipes: async () => ({repository: "repo", commit: "c".repeat(40), recipes: catalog})} as unknown as ControlApi;
  const user = userEvent.setup();
  render(<App api={api}/>);

  expect(await screen.findByRole("group", {name: "73 model versions"})).toBeVisible();
  expect(screen.getByRole("group", {name: "85 recipes"})).toBeVisible();
  expect(screen.getAllByRole("button", {name: "Place on Spark"})).toHaveLength(85);
  expect(screen.queryByRole("button", {name: "Syncing…"})).not.toBeInTheDocument();
  await user.type(screen.getByRole("searchbox", {name: "Search Library"}), "Qwen");
  expect(screen.getByRole("link", {name: "Qwen evaluation"})).toBeVisible();
  expect(screen.getByRole("link", {name: "Qwen custom evaluation"})).toBeVisible();
});

test("keeps later pages bounded while imported evicted rows can open exact details", async () => {
  history.replaceState(null, "", "/library");
  const first = {...largeLibrary(100), next_cursor: "next"};
  const next = largeLibrary(25, 100);
  const catalog = [...publicRows(first), ...publicRows(next), recipe()];
  const librarySnapshotApi = vi.fn().mockResolvedValueOnce(first).mockResolvedValueOnce(next);
  const detail = {...minimalLibraryDetail, recipe: {...minimalLibraryDetail.recipe, recipe_id: "recipe-0", title: "Qwen evaluation"}};
  const libraryRecipe = vi.fn().mockResolvedValue(detail);
  const api = {librarySnapshot: librarySnapshotApi, libraryRecipe, listPublicRecipes: async () => ({repository: "repo", commit: "c".repeat(40), recipes: catalog})} as unknown as ControlApi;
  const user = userEvent.setup();
  render(<App api={api}/>);
  await user.click(await screen.findByRole("button", {name: "Load more Library recipes"}));
  await waitFor(() => expect(librarySnapshotApi).toHaveBeenCalledTimes(2));
  expect(await screen.findByRole("status", {name: "Bounded Library window"})).toHaveTextContent("No more server pages remain");
  expect(screen.getByRole("group", {name: "100 model versions"})).toBeVisible();
  const row = screen.getByRole("row", {name: /Qwen evaluation/});
  expect(within(row).queryByRole("button", {name: "Syncing…"})).not.toBeInTheDocument();
  expect(screen.getByRole("button", {name: "Syncing…"})).toBeDisabled();
  await user.click(within(row).getByRole("link", {name: "Open recipe"}));
  expect(await screen.findByRole("region", {name: "Recipe detail"})).toHaveTextContent("Qwen evaluation");
  expect(libraryRecipe).toHaveBeenCalledWith("recipe-0", expect.any(AbortSignal));
});

test("keeps the selected recipe pinned as later pages evict older models", async () => {
  history.replaceState(null, "", "/library/recipes/recipe-0");
  const first = {...largeLibrary(100), next_cursor: "next"};
  const next = largeLibrary(25, 100);
  const api = {librarySnapshot: vi.fn().mockResolvedValueOnce(first).mockResolvedValueOnce(next), libraryRecipe: async () => ({...minimalLibraryDetail, recipe: {...minimalLibraryDetail.recipe, recipe_id: "recipe-0", title: "Qwen evaluation"}}), listPublicRecipes: async () => ({repository: "repo", commit: "c".repeat(40), recipes: [...publicRows(first), ...publicRows(next)]})} as unknown as ControlApi;
  const user = userEvent.setup();
  render(<App api={api}/>);
  await user.click(await screen.findByRole("button", {name: "Load more Library recipes"}));
  expect(await screen.findByRole("status", {name: "Bounded Library window"})).toBeVisible();
  expect(screen.getByRole("group", {name: "100 model versions"})).toBeVisible();
  expect(screen.getByRole("button", {name: "Place on Spark"})).toBeEnabled();
  expect(screen.getByRole("region", {name: "Recipe detail"})).toHaveTextContent("Qwen evaluation");
});

afterEach(() => { history.replaceState(null, "", "/"); vi.restoreAllMocks(); });

test("shows repository recipes directly in Library even before local synchronization", async () => {
  history.replaceState(null, "", "/library");
  const api = {librarySnapshot: async () => emptySnapshot, listPublicRecipes: async () => ({repository: "CarstVaartjes/vonk-forge-recipes", commit: "c".repeat(40), recipes: [recipe()]})} as unknown as ControlApi;
  render(<App api={api}/>);

  expect(await screen.findByRole("heading", {name: "Library"})).toBeVisible();
  const table = await screen.findByRole("table", {name: /Recipes synchronized from the repository/});
  expect(within(table).getByRole("row", {name: /GLM 5.3 Flash NVFP4/})).toHaveTextContent("GLM 5.3 Flash");
  expect(screen.queryByRole("link", {name: /Browse catalog|Browse public recipes/i})).not.toBeInTheDocument();
  expect(screen.queryByRole("button", {name: /Import|Review/i})).not.toBeInTheDocument();
});

test("treats the retired import URL as the same repository-backed Library", async () => {
  history.replaceState(null, "", "/library/import");
  const api = {librarySnapshot: async () => emptySnapshot, listPublicRecipes: async () => ({repository: "CarstVaartjes/vonk-forge-recipes", commit: "c".repeat(40), recipes: [recipe()]})} as unknown as ControlApi;
  render(<App api={api}/>);

  expect(await screen.findByRole("table", {name: /Recipes synchronized from the repository/})).toBeVisible();
  expect(screen.queryByText(/Import public recipe|Review recipe/i)).not.toBeInTheDocument();
});

test("filters the unified table from the Library search", async () => {
  history.replaceState(null, "", "/library");
  const api = {librarySnapshot: async () => emptySnapshot, listPublicRecipes: async () => ({repository: "CarstVaartjes/vonk-forge-recipes", commit: "c".repeat(40), recipes: [recipe(), recipe({slug: "qwen", title: "Qwen 3.5 9B", uri: `vonk://catalog/vonk-forge/qwen@sha256:${"d".repeat(64)}`, model_title: "Qwen 3.5", model_version_slug: "qwen-3-5-9b", model_version_title: "Qwen/Qwen3.5-9B"})]})} as unknown as ControlApi;
  const user = userEvent.setup();
  render(<App api={api}/>);
  await screen.findByRole("row", {name: /GLM 5.3 Flash NVFP4/});

  await user.type(screen.getByRole("searchbox", {name: "Search Library"}), "qwen");
  expect(screen.getByRole("row", {name: /Qwen 3.5 9B/})).toBeVisible();
  expect(screen.queryByRole("row", {name: /GLM 5.3 Flash NVFP4/})).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", {name: "Clear Library search"}));
  expect(screen.getByRole("row", {name: /GLM 5.3 Flash NVFP4/})).toBeVisible();
});

test("keeps the Library usable when repository refresh fails and retries", async () => {
  history.replaceState(null, "", "/library");
  const listPublicRecipes = vi.fn().mockRejectedValueOnce(new Error("catalog offline")).mockResolvedValueOnce({repository: "CarstVaartjes/vonk-forge-recipes", commit: "c".repeat(40), recipes: [recipe()]});
  const api = {librarySnapshot: async () => librarySnapshot, listPublicRecipes} as unknown as ControlApi;
  const user = userEvent.setup();
  render(<App api={api}/>);

  expect(await screen.findByRole("alert")).toHaveTextContent("Repository catalog unavailable: catalog offline");
  expect(screen.getByRole("row", {name: /Qwen Chat/})).toBeVisible();
  await user.click(screen.getByRole("button", {name: "Retry repository"}));
  await waitFor(() => expect(listPublicRecipes).toHaveBeenCalledTimes(2));
  expect(await screen.findByRole("row", {name: /GLM 5.3 Flash NVFP4/})).toBeVisible();
});

test("keeps custom recipe authoring as a separate operational route", async () => {
  history.replaceState(null, "", "/library");
  const api = {librarySnapshot: async () => emptySnapshot, listPublicRecipes: async () => ({repository: "repo", commit: "c".repeat(40), recipes: []})} as unknown as ControlApi;
  const user = userEvent.setup();
  render(<App api={api}/>);
  await user.click(await screen.findByRole("link", {name: "Create custom"}));
  expect(await screen.findByRole("heading", {name: /Create custom recipe/i})).toBeVisible();
});
