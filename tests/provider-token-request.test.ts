import { inspect } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { type HeimdallConfig } from "../src/config.js";
import { providers, type Provider } from "../src/contracts.js";
import { requestProviderTokens } from "../src/oauth.js";
import { providerCatalog } from "../src/providers.js";

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

function configFor(): HeimdallConfig {
  return {
    providers: Object.fromEntries(providers.map((p) => [p, { clientId: `${p}-client`, clientSecret: `${p}-secret` }])),
  } as unknown as HeimdallConfig;
}

interface Captured {
  url: string;
  method: string | undefined;
  headers: Record<string, string>;
  body: URLSearchParams;
}

function capture(answer: () => Response): { calls: Captured[] } {
  const calls: Captured[] = [];
  globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method,
      headers: init?.headers as Record<string, string>,
      body: init?.body as URLSearchParams,
    });
    return answer();
  }) as typeof fetch;
  return { calls };
}

const ok = () =>
  new Response(JSON.stringify({ access_token: "a", refresh_token: "r", token_type: "Bearer", expires_in: 3600, scope: "x y" }), {
    status: 200,
  });

const requestable: Provider[] = [...providers];

describe("requestProviderTokens follows the provider descriptor", () => {
  it.each(requestable.flatMap((p) => [[p, "authorization_code"] as const, [p, "refresh_token"] as const]))(
    "%s %s hits its token endpoint with its client-auth method only",
    async (provider, grantType) => {
      const { calls } = capture(ok);
      const descriptor = providerCatalog[provider];
      const grant =
        grantType === "authorization_code"
          ? ({ grant_type: "authorization_code", code: "the-code", redirect_uri: "https://h/cb" } as const)
          : ({ grant_type: "refresh_token", refresh_token: "the-refresh" } as const);

      const tokens = await requestProviderTokens(provider, configFor(), grant);

      expect(calls).toHaveLength(1);
      const call = calls[0]!;
      expect(call.url).toBe(descriptor.tokenEndpoint);
      expect(call.method).toBe("POST");
      expect(call.headers["Content-Type"]).toBe("application/x-www-form-urlencoded");
      expect(call.headers.Accept).toBe("application/json");
      expect(call.body.get("grant_type")).toBe(grantType);
      if (descriptor.tokenEndpointAuthMethod === "client_secret_basic") {
        expect(call.headers.Authorization).toBe(`Basic ${Buffer.from(`${provider}-client:${provider}-secret`).toString("base64")}`);
        expect(call.body.has("client_id")).toBe(false);
        expect(call.body.has("client_secret")).toBe(false);
      } else {
        expect(call.headers.Authorization).toBeUndefined();
        expect(call.body.get("client_id")).toBe(`${provider}-client`);
        expect(call.body.get("client_secret")).toBe(`${provider}-secret`);
      }
      expect(tokens.accessToken).toBe("a");
      expect(tokens.refreshToken).toBe("r");
      expect(tokens.scope).toEqual(["x", "y"]);
      expect(Date.parse(tokens.expiresAt ?? "")).toBeGreaterThan(Date.now());
    }
  );

  it("sends the code and redirect uri on exchange and the refresh token on refresh", async () => {
    const { calls } = capture(ok);
    await requestProviderTokens("spotify", configFor(), { grant_type: "authorization_code", code: "C", redirect_uri: "https://h/cb" });
    await requestProviderTokens("spotify", configFor(), { grant_type: "refresh_token", refresh_token: "R" });
    expect(calls[0]!.body.get("code")).toBe("C");
    expect(calls[0]!.body.get("redirect_uri")).toBe("https://h/cb");
    expect(calls[1]!.body.get("refresh_token")).toBe("R");
    expect(calls[1]!.body.has("code")).toBe(false);
  });

  const everyProvider = Object.keys(providerCatalog) as Provider[];

  it("gives every provider a default access-token lifetime of 3600 seconds", () => {
    for (const provider of everyProvider) {
      expect(providerCatalog[provider].defaultAccessTokenLifetimeSeconds).toBe(3600);
    }
  });

  // expires_in is RECOMMENDED (RFC 6749 5.1): unusable means the default, never an unknown expiry.
  it.each([
    ["no expires_in", undefined, 3600],
    ["a zero expires_in", 0, 3600],
    ["a negative expires_in", -5, 3600],
    ["a null expires_in", null, 3600],
    ["an object expires_in", {}, 3600],
    ["a non-numeric string", "abc", 3600],
    ["an empty string", "", 3600],
    ["a negative string", "-1", 3600],
    ["a zero string", "0", 3600],
    ["a fractional string", "12.5", 3600],
    ["an exponent string", "1e3", 3600],
    ["a numeric string", "7200", 7200],
    ["a padded numeric string", " 7200 ", 7200],
    ["a number", 7200, 7200],
  ])("stores now plus the right lifetime for %s, on every provider and grant", async (_n, expiresIn, seconds) => {
    for (const provider of everyProvider) {
      for (const grant of [
        { grant_type: "authorization_code", code: "c", redirect_uri: "u" } as const,
        { grant_type: "refresh_token", refresh_token: "R" } as const,
      ]) {
        capture(() => new Response(JSON.stringify({ access_token: "a", ...(expiresIn === undefined ? {} : { expires_in: expiresIn }) }), { status: 200 }));
        const before = Date.now();
        const tokens = await requestProviderTokens(provider, configFor(), grant);
        const stored = Date.parse(tokens.expiresAt ?? "");
        expect(stored - before).toBeGreaterThanOrEqual(seconds * 1000);
        expect(stored - before).toBeLessThan(seconds * 1000 + 5_000);
        expect(tokens.refreshToken).toBeUndefined();
      }
    }
  });

  it("takes the default lifetime for an expires_in too large to be a date", async () => {
    capture(() => new Response('{"access_token":"a","expires_in":1e999}', { status: 200 }));
    const before = Date.now();
    const tokens = await requestProviderTokens("twitch", configFor(), { grant_type: "refresh_token", refresh_token: "R" });
    expect(Date.parse(tokens.expiresAt ?? "") - before).toBeLessThan(3600 * 1000 + 5_000);
  });

  it.each([
    ["a number", 42],
    ["an object", { a: 1 }],
    ["an array", ["r"]],
    ["true", true],
    ["null", null],
  ])("refuses a 2xx whose refresh_token is %s as a malformed token set", async (_n, refreshToken) => {
    capture(() => new Response(JSON.stringify({ access_token: "a", refresh_token: refreshToken, expires_in: 3600 }), { status: 200 }));
    await expect(
      requestProviderTokens("twitch", configFor(), { grant_type: "refresh_token", refresh_token: "R" })
    ).rejects.toMatchObject({ code: "provider_body_not_token_set" });
  });

  it("reads an empty-string refresh_token as no refresh token", async () => {
    capture(() => new Response(JSON.stringify({ access_token: "a", refresh_token: "", expires_in: 3600 }), { status: 200 }));
    const tokens = await requestProviderTokens("twitch", configFor(), { grant_type: "refresh_token", refresh_token: "R" });
    expect(tokens.refreshToken).toBeUndefined();
  });

  it.each([
    ["authorization_code", { grant_type: "authorization_code", code: "c", redirect_uri: "u" } as const, "exchange"],
    ["refresh_token", { grant_type: "refresh_token", refresh_token: "r" } as const, "refresh"],
  ])("keeps the failure label for %s", async (_g, grant, word) => {
    capture(() => new Response("nope", { status: 500 }));
    await expect(requestProviderTokens("youtube", configFor(), grant)).rejects.toThrow(
      `YouTube token ${word} failed (status 500, provider_status).`
    );
  });

  it("passes the abort signal to the provider call", async () => {
    let seen: AbortSignal | null | undefined;
    globalThis.fetch = (async (_input: string | URL, init?: RequestInit) => {
      seen = init?.signal;
      return ok();
    }) as typeof fetch;
    const controller = new AbortController();
    await requestProviderTokens("twitch", configFor(), { grant_type: "refresh_token", refresh_token: "r" }, controller.signal);
    expect(seen).toBe(controller.signal);
  });

  it("keeps the provider's token type and defaults a missing one to Bearer", async () => {
    capture(() => new Response(JSON.stringify({ access_token: "a", token_type: "bearer" }), { status: 200 }));
    expect((await requestProviderTokens("twitch", configFor(), { grant_type: "refresh_token", refresh_token: "r" })).tokenType).toBe("bearer");
    capture(() => new Response(JSON.stringify({ access_token: "a" }), { status: 200 }));
    expect((await requestProviderTokens("twitch", configFor(), { grant_type: "refresh_token", refresh_token: "r" })).tokenType).toBe("Bearer");
  });

  it("trims scope entries and drops empty ones", async () => {
    capture(() => new Response(JSON.stringify({ access_token: "a", scope: [" a ", "", "b"] }), { status: 200 }));
    expect((await requestProviderTokens("twitch", configFor(), { grant_type: "refresh_token", refresh_token: "r" })).scope).toEqual(["a", "b"]);
  });

  it.each([
    ["an empty body", ""],
    ["an empty object", "{}"],
    ["JSON null", "null"],
    ["a JSON array", "[]"],
    ["an error beside an access token", JSON.stringify({ access_token: "a", error: "invalid_grant" })],
    ["an empty access token", JSON.stringify({ access_token: "" })],
    ["a numeric access token", JSON.stringify({ access_token: 5 })],
  ])("refuses a 2xx with %s as not a token set, carrying nothing of the body", async (_name, body) => {
    capture(() => new Response(body, { status: 200 }));
    const error = await requestProviderTokens("twitch", configFor(), { grant_type: "refresh_token", refresh_token: "r" }).then(
      () => {
        throw new Error("expected a refusal");
      },
      (e: unknown) => e as Error & { code?: string; status?: number; oauthError?: unknown }
    );
    expect(error.name).toBe("ProviderResponseError");
    expect(error.code).toBe("provider_body_not_token_set");
    expect(error.status).toBe(200);
    expect(error.oauthError).toBeUndefined();
  });

  it("sets no refreshToken key when the provider sent none", async () => {
    capture(() => new Response(JSON.stringify({ access_token: "a" }), { status: 200 }));
    const tokens = await requestProviderTokens("twitch", configFor(), { grant_type: "refresh_token", refresh_token: "r" });
    expect("refreshToken" in tokens).toBe(false);
  });

  it.each([
    ["only the secret missing", { clientId: "id" }],
    ["only the id missing", { clientSecret: "secret" }],
  ])("refuses a provider with %s", async (_n, partial) => {
    const config = { providers: { twitch: partial } } as unknown as HeimdallConfig;
    await expect(requestProviderTokens("twitch", config, { grant_type: "refresh_token", refresh_token: "r" })).rejects.toThrow(
      "Twitch OAuth is not fully configured."
    );
  });

  it("refuses an unconfigured provider by display name", async () => {
    const config = { providers: { patreon: {} } } as unknown as HeimdallConfig;
    await expect(
      requestProviderTokens("patreon", config, { grant_type: "refresh_token", refresh_token: "r" })
    ).rejects.toThrow("Patreon OAuth is not fully configured.");
  });
});

describe("oauthError is a closed set", () => {
  const refresh = { grant_type: "refresh_token", refresh_token: "r" } as const;
  async function failure(body: string, status = 400) {
    capture(() => new Response(body, { status }));
    return requestProviderTokens("twitch", configFor(), refresh).then(
      () => {
        throw new Error("expected a refusal");
      },
      (error: unknown) => error as Error & { oauthError?: string }
    );
  }

  it("takes invalid_grant from the body and carries nothing else of it", async () => {
    const error = await failure(JSON.stringify({ error: "invalid_grant", error_description: "CANARY" }));
    expect(error.oauthError).toBe("invalid_grant");
    expect(`${error.message} ${error.stack} ${inspect(error, { depth: 5, showHidden: true })} ${JSON.stringify(error)}`).not.toContain("CANARY");
  });

  it.each([401, 403, 429, 500, 502, 503])("takes no oauthError from a %i, whatever its body says", async (status) => {
    const error = await failure(JSON.stringify({ error: "invalid_grant" }), status);
    expect(error.oauthError).toBeUndefined();
  });

  it.each(["invalid_grant_extra", "not_invalid_grant", "INVALID_GRANT", " invalid_grant", "invalid_grant "])(
    "takes the code by exact match only: %j is no code",
    async (code) => {
      const error = await failure(JSON.stringify({ error: code }));
      expect(error.oauthError).toBeUndefined();
    }
  );

  it.each([
    ["an error outside the RFC set", JSON.stringify({ error: "CANARY_unknown" })],
    ["a non-string error", JSON.stringify({ error: { code: "invalid_grant" } })],
    ["a body that is not JSON", "CANARY <html>"],
    ["JSON null", "null"],
  ])("leaves oauthError undefined for %s", async (_name, body) => {
    const error = await failure(body);
    expect(error.oauthError).toBeUndefined();
    expect(`${error.message} ${inspect(error, { depth: 5, showHidden: true })}`).not.toContain("CANARY");
  });
});
