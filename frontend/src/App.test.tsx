import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App, Result } from "./App";

const result: Result = {
  id: "scan-1",
  target: "https://example.com/login",
  target_type: "url",
  score: 42,
  verdict: "suspicious",
  provider: "ThreatScope local analysis",
  cached: true,
  scanned_at: "2026-08-28T00:00:00Z",
  findings: [{ label: "Sensitive-action wording", severity: "medium", detail: "URL text contains: login." }],
};

function response(data: unknown, ok = true) {
  return { ok, json: vi.fn().mockResolvedValue(data) } as unknown as Response;
}

describe("ThreatScope App", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response([])));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("keeps VirusTotal opt-in and sends the selected mode", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockImplementation(async (_input, init) => init?.method === "POST" ? response(result) : response([]));
    const user = userEvent.setup();
    render(<App />);

    const toggle = screen.getByRole("button", { name: /check an existing virustotal report/i });
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-pressed", "true");

    await user.type(screen.getByRole("textbox", { name: /scan target/i }), result.target);
    await user.click(screen.getByRole("button", { name: /scan target/i }));

    await waitFor(() => expect(screen.getAllByText("42").length).toBeGreaterThan(0));
    const postCall = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(JSON.parse(String(postCall?.[1]?.body))).toEqual({
      target: result.target,
      share_with_virustotal: true,
    });
    expect(screen.getByText(/recent cached result/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Sensitive-action wording" })).toBeInTheDocument();
    expect(screen.getAllByText("suspicious").length).toBeGreaterThan(0);
  });

  it("shows loading state and defaults to local-only scanning", async () => {
    let resolvePost: ((value: Response) => void) | undefined;
    const postResponse = new Promise<Response>((resolve) => { resolvePost = resolve; });
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockImplementation((_input, init) => init?.method === "POST" ? postResponse : Promise.resolve(response([])));
    const user = userEvent.setup();
    render(<App />);

    await user.type(screen.getByRole("textbox", { name: /scan target/i }), "example.com");
    await user.click(screen.getByRole("button", { name: /scan target/i }));
    expect(screen.getByRole("button", { name: /analyzing/i })).toBeDisabled();

    const postCall = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(JSON.parse(String(postCall?.[1]?.body)).share_with_virustotal).toBe(false);
    resolvePost?.(response({ ...result, cached: false }));
    await waitFor(() => expect(screen.getAllByText("42").length).toBeGreaterThan(0));
  });

  it("surfaces API validation errors", async () => {
    vi.mocked(fetch).mockImplementation(async (_input, init) => (
      init?.method === "POST" ? response({ detail: "Only HTTP and HTTPS URLs can be scanned." }, false) : response([])
    ));
    const user = userEvent.setup();
    render(<App />);

    await user.type(screen.getByRole("textbox", { name: /scan target/i }), "ftp://example.com");
    await user.click(screen.getByRole("button", { name: /scan target/i }));

    expect(await screen.findByText("Only HTTP and HTTPS URLs can be scanned.")).toBeInTheDocument();
  });

  it("loads recent history and opens a stored result", async () => {
    vi.mocked(fetch).mockResolvedValue(response([result]));
    const user = userEvent.setup();
    render(<App />);

    const historyTarget = await screen.findByRole("button", { name: /https:\/\/example.com\/login/i });
    expect(screen.getByText("1 stored")).toBeInTheDocument();
    await user.click(historyTarget);

    expect(screen.getAllByText("42").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Sensitive-action wording" })).toBeInTheDocument();
  });
});
