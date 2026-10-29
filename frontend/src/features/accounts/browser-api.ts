import { z } from "zod";

import { get, post } from "@/lib/api-client";
import { OauthStartResponseSchema } from "@/features/accounts/schemas";

const base = "/api/local-browser";
const headers = { "X-Codex-LB-Browser": "1" };

export type BrowserStart = { accountId?: string; poolId?: string; direct?: boolean };
export const BrowserResponseSchema = OauthStartResponseSchema.extend({
  managedBrowser: z.literal(true),
  personaId: z.string(),
  browserLabel: z.string(),
  routeMode: z.enum(["direct", "proxy"]),
});

export function browserCapabilities() {
  return get(`${base}/capabilities`, z.object({ enabled: z.boolean() }));
}

export function startAccountBrowser(body: BrowserStart) {
  return post(`${base}/start`, BrowserResponseSchema, { body, headers });
}

export function reopenAccountBrowser(flowId: string) {
  return post(`${base}/reopen`, BrowserResponseSchema, { body: { flowId }, headers });
}

export function cancelAccountBrowser(flowId: string) {
  return post(`${base}/cancel`, z.object({ status: z.string() }), { body: { flowId }, headers });
}
