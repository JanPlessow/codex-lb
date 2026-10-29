import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import App from "@/App";
import { renderWithProviders } from "@/test/utils";
import { createOauthStartResponse } from "@/test/mocks/factories";
import { server } from "@/test/mocks/server";

const response = {
  ...createOauthStartResponse(),
  method: "browser",
  flowId: "browser-test-flow",
  authorizationUrl: null,
  managedBrowser: true,
  personaId: "test-persona",
  browserLabel: "Account",
  routeMode: "direct",
};

function managedHandlers() {
  const requests: unknown[] = [];
  const reopened: unknown[] = [];
  server.use(
    http.get("/api/local-browser/capabilities", () => HttpResponse.json({ enabled: true })),
    http.post("/api/local-browser/start", async ({ request }) => {
      expect(request.headers.get("X-Codex-LB-Browser")).toBe("1");
      requests.push(await request.json());
      return HttpResponse.json(response);
    }),
    http.get("/api/oauth/status", () => HttpResponse.json({ status: "pending" })),
    http.post("/api/local-browser/reopen", async ({ request }) => {
      reopened.push(await request.json());
      return HttpResponse.json(response);
    }),
  );
  return { requests, reopened };
}

describe("account browser integration", () => {
  it("launches the selected local account and reopens its flow without an authorization link", async () => {
    const { requests, reopened } = managedHandlers();
    const user = userEvent.setup({ delay: null });
    window.history.pushState({}, "", "/accounts");
    renderWithProviders(<App />);
    await user.click(await screen.findByRole("button", { name: "Re-authenticate" }));
    await waitFor(() => expect(requests).toHaveLength(1));
    expect(requests[0]).toEqual({ accountId: expect.any(String) });
    expect(screen.queryByRole("link", { name: /open|sign in|authorize/i })).not.toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Reopen account Chrome" }));
    await waitFor(() => expect(reopened).toEqual([{ flowId: "browser-test-flow" }]));
  });

  it("requires an explicit connection before enrolling an account", async () => {
    const { requests } = managedHandlers();
    const user = userEvent.setup({ delay: null });
    window.history.pushState({}, "", "/accounts");
    renderWithProviders(<App />);
    const add = await screen.findByRole("button", { name: /Add account/i });
    await waitFor(() => expect(add).toBeEnabled());
    await user.click(add);
    await user.click(await screen.findByRole("button", { name: /^OAuth/ }));
    await screen.findByLabelText("Account connection");
    expect(screen.getByRole("button", { name: "Open account Chrome" })).toBeDisabled();
    expect(requests).toEqual([]);
    await user.selectOptions(screen.getByLabelText("Account connection"), "direct");
    await user.click(screen.getByRole("button", { name: "Open account Chrome" }));
    await waitFor(() => expect(requests).toEqual([{ direct: true }]));
    expect(await screen.findByText(/Complete sign-in in the Chrome window/)).toBeInTheDocument();
  });
});
