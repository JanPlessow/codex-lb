import { useState } from "react";

import { AlertMessage } from "@/components/alert-message";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { BrowserStart } from "@/features/accounts/browser-api";
import type { OAuthState } from "@/features/accounts/schemas";

type Props = {
  open: boolean;
  accountId: string | null;
  accountLabel: string;
  state: OAuthState;
  pools: Array<{ id: string; name: string; isActive: boolean }>;
  onStart: (request: BrowserStart) => Promise<unknown>;
  onReopen: () => Promise<unknown>;
  onClose: () => Promise<void>;
};

export function AccountBrowserDialog({ open, accountId, accountLabel, state, pools, onStart, onReopen, onClose }: Props) {
  const [connection, setConnection] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (action: () => Promise<unknown>) => {
    setActionError(null);
    setBusy(true);
    try { await action(); } catch (error) {
      setActionError(error instanceof Error ? error.message : "The account browser could not be opened.");
    } finally { setBusy(false); }
  };
  const start = () => run(() => onStart(accountId ? { accountId } : connection === "direct" ? { direct: true } : { poolId: connection }));
  const pending = state.status === "pending";
  const starting = busy || state.status === "starting";

  return (
    <Dialog open={open} onOpenChange={(next) => { if (!next && !starting) void run(onClose); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{state.status === "success" ? "Account connected" : accountId ? `Sign in as ${accountLabel}` : "Add an account"}</DialogTitle>
          <DialogDescription>
            {accountId ? "This account opens in its own Chrome profile with its assigned connection." : "Choose the connection for this account before signing in. Its Chrome profile will be saved automatically."}
          </DialogDescription>
        </DialogHeader>
        {!accountId && !pending && state.status !== "success" && (
          <label className="space-y-2 text-sm">
            <span>Account connection</span>
            <select aria-label="Account connection" className="w-full rounded-md border bg-background p-2" value={connection} disabled={starting} onChange={(event) => setConnection(event.target.value)}>
              <option value="" disabled>Choose a connection</option>
              <option value="direct">Direct — this Mac’s internet connection</option>
              {pools.filter((pool) => pool.isActive).map((pool) => <option key={pool.id} value={pool.id}>{pool.name}</option>)}
            </select>
            <p className="text-xs text-muted-foreground">A proxy pool must contain exactly one active endpoint.</p>
          </label>
        )}
        {starting && <p className="text-sm" role="status">Opening the account’s Chrome profile…</p>}
        {pending && <p className="text-sm" role="status">Complete sign-in in the Chrome window that opened. You can enter any verification code there. This dialog updates automatically.</p>}
        {state.status === "success" && <p className="text-sm">The account is connected. Its browser profile and connection are saved for the next sign-in.</p>}
        {(actionError || state.errorMessage) && <AlertMessage variant="error">{actionError || state.errorMessage}</AlertMessage>}
        <div className="flex justify-end gap-2">
          <Button variant="outline" disabled={starting} onClick={() => void run(onClose)}>{state.status === "success" ? "Done" : "Cancel"}</Button>
          {pending ? <Button disabled={starting} onClick={() => void run(onReopen)}>Reopen account Chrome</Button>
            : state.status !== "success" && <Button disabled={starting || (!accountId && !connection)} onClick={() => void start()}>Open account Chrome</Button>}
        </div>
      </DialogContent>
    </Dialog>
  );
}
