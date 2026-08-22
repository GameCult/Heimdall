import { afterEach, describe, expect, it, vi } from "vitest";
import {
  heimdallAccessBrowserAdapter,
  readHeimdallBrowserReturn,
  resumeHeimdallAccess,
} from "../plugins/gamecult.heimdall.access/browser-adapter.js";

const attemptKey = "gamecult.heimdall.access.attempt";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Heimdall browser completion fallback", () => {
  it("recognizes only a matching Ghostlight browser completion witness", () => {
    const handle = "d0a9c1e7-89ac-46f9-8c85-c2484ed18f76";
    expect(readHeimdallBrowserReturn(returnUrl(handle), "ghostlight")).toEqual({
      status: "success",
      handle,
    });
    expect(readHeimdallBrowserReturn(returnUrl(handle), "another-app")).toMatchObject({ status: "error" });
    expect(readHeimdallBrowserReturn(returnUrl(handle, "different"), "ghostlight")).toMatchObject({ status: "error" });
    expect(readHeimdallBrowserReturn("https://yggdrasil.gamecult.org/ghostlight/", "ghostlight")).toBeUndefined();
  });

  it("redeems the URL witness after tab-local attempt state is lost", async () => {
    const handle = "0be30b8c-b599-4920-b8b8-733f5e7bc275";
    const storage = memoryStorage();
    const replaced: string[] = [];
    vi.stubGlobal("sessionStorage", storage);
    vi.stubGlobal("history", { replaceState: (_state: unknown, _title: string, url: string) => replaced.push(url) });
    vi.stubGlobal("window", {
      location: {
        href: returnUrl(handle),
        pathname: "/ghostlight/",
        search: "",
      },
    });
    const completed: string[] = [];

    await expect(resumeHeimdallAccess({ complete: async value => { completed.push(value); } }, { appSlug: "ghostlight" }))
      .resolves.toBe(true);

    expect(completed).toEqual([handle]);
    expect(storage.getItem(attemptKey)).toBe(handle);
    expect(replaced).toEqual(["/ghostlight/"]);

    await heimdallAccessBrowserAdapter.consumeCommandResult?.({
      schemaId: "heimdall.auth_completion_status.v1",
      payload: { status: "authenticated" },
    });
    expect(storage.getItem(attemptKey)).toBeNull();
  });

  it("does not redeem a returned witness that conflicts with the browser-held attempt", async () => {
    const storage = memoryStorage([[attemptKey, "stored-handle"]]);
    vi.stubGlobal("sessionStorage", storage);
    vi.stubGlobal("history", { replaceState: () => undefined });
    vi.stubGlobal("window", {
      location: {
        href: returnUrl("returned-handle"),
        pathname: "/ghostlight/",
        search: "",
      },
    });
    const complete = vi.fn(async () => undefined);

    await expect(resumeHeimdallAccess({ complete }, { appSlug: "ghostlight" }))
      .rejects.toThrow("other than the one this browser started");
    expect(complete).not.toHaveBeenCalled();
    expect(storage.getItem(attemptKey)).toBeNull();
  });
});

function returnUrl(attemptId: string, completionCode = attemptId): string {
  const parameters = new URLSearchParams({
    heimdall_status: "success",
    heimdall_provider: "discord",
    heimdall_handoff_kind: "browser_completion",
    heimdall_app_slug: "ghostlight",
    heimdall_mode: "sign_in",
    heimdall_attempt_id: attemptId,
    heimdall_completion_code: completionCode,
  });
  return `https://yggdrasil.gamecult.org/ghostlight/#${parameters}`;
}

function memoryStorage(initial: Array<[string, string]> = []): Storage {
  const values = new Map(initial);
  return {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: key => values.get(key) ?? null,
    key: index => [...values.keys()][index] ?? null,
    removeItem: key => { values.delete(key); },
    setItem: (key, value) => { values.set(key, value); },
  };
}
