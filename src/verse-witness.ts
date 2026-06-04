import { appProfiles, type CapabilityDefinition } from "./app-profiles.js";
import { appSlugs, providers, type AppSlug, type Provider } from "./contracts.js";
import { providerCatalog, type ProviderRole } from "./providers.js";

export const heimdallWitnessSchemaIds = [
  "heimdall.account.v0",
  "heimdall.linked_identity.v0",
  "heimdall.capability_grant.v0",
  "heimdall.session.v0",
  "heimdall.entitlement_snapshot.v0",
  "heimdall.auth_completion.v0",
  "heimdall.audit_event.v0",
  "heimdall.app_profile.v0",
  "heimdall.managed_credential_projection.v0",
] as const;

export type HeimdallWitnessSchemaId = (typeof heimdallWitnessSchemaIds)[number];

export interface HeimdallWitnessDocumentDescriptor {
  schemaId: HeimdallWitnessSchemaId;
  documentType: HeimdallWitnessSchemaId;
  cultCachePath: string;
  redaction: string;
  ownedTruth: string;
  forbiddenFields: string[];
}

export const heimdallWitnessDocuments: readonly HeimdallWitnessDocumentDescriptor[] = [
  {
    schemaId: "heimdall.account.v0",
    documentType: "heimdall.account.v0",
    cultCachePath: "cultcache/heimdall/accounts/{accountId}.cc",
    redaction: "Email is optional and should be omitted unless an operator-safe identity hint is needed.",
    ownedTruth: "Local GameCult account record independent of upstream providers.",
    forbiddenFields: ["providerAccessToken", "providerRefreshToken"],
  },
  {
    schemaId: "heimdall.linked_identity.v0",
    documentType: "heimdall.linked_identity.v0",
    cultCachePath: "cultcache/heimdall/linked-identities/{provider}/{providerUserId}.cc",
    redaction: "Token ciphertext and raw provider profile stay out; export only custody status and selected identity labels.",
    ownedTruth: "External provider identity linked to exactly one Heimdall account.",
    forbiddenFields: ["accessTokenEncrypted", "refreshTokenEncrypted", "profileJson"],
  },
  {
    schemaId: "heimdall.capability_grant.v0",
    documentType: "heimdall.capability_grant.v0",
    cultCachePath: "cultcache/heimdall/grants/{grantId}.cc",
    redaction: "Operator notes must be reviewed before export and kept free of secrets or private app data.",
    ownedTruth: "Manual or system-issued shared capability grant.",
    forbiddenFields: ["providerAccessToken", "providerRefreshToken", "appDomainPayload"],
  },
  {
    schemaId: "heimdall.session.v0",
    documentType: "heimdall.session.v0",
    cultCachePath: "cultcache/heimdall/sessions/{sessionId}.cc",
    redaction: "Signed tokens are never exported; claims are reduced to audience, revision, expiry, facts, and capabilities.",
    ownedTruth: "Local app/browser session issued by Heimdall.",
    forbiddenFields: ["accessToken", "refreshToken", "claimsJson"],
  },
  {
    schemaId: "heimdall.entitlement_snapshot.v0",
    documentType: "heimdall.entitlement_snapshot.v0",
    cultCachePath: "cultcache/heimdall/entitlements/{accountId}/{provider}/{scope}.cc",
    redaction: "Raw provider responses stay out; export reason codes and compact summaries only.",
    ownedTruth: "Cached provider entitlement evaluation result.",
    forbiddenFields: ["rawProviderResponse", "providerAccessToken", "providerRefreshToken"],
  },
  {
    schemaId: "heimdall.auth_completion.v0",
    documentType: "heimdall.auth_completion.v0",
    cultCachePath: "cultcache/heimdall/auth-completions/{completionCodeHash}.cc",
    redaction: "Completion codes are hashed or omitted; payload is redacted to status, provider, app, mode, and expiry.",
    ownedTruth: "One-time OAuth browser/backend handoff completion state.",
    forbiddenFields: ["code", "accessToken", "refreshToken", "callbackSecret"],
  },
  {
    schemaId: "heimdall.audit_event.v0",
    documentType: "heimdall.audit_event.v0",
    cultCachePath: "cultcache/heimdall/audit/{eventId}.cc",
    redaction: "Audit payloads must pass token, code, secret, callback, and private-profile redaction before export.",
    ownedTruth: "Durable auth/control-plane event history.",
    forbiddenFields: ["accessToken", "refreshToken", "authorizationCode", "clientSecret"],
  },
  {
    schemaId: "heimdall.app_profile.v0",
    documentType: "heimdall.app_profile.v0",
    cultCachePath: "cultcache/heimdall/app-profiles/{appSlug}.cc",
    redaction: "Profile exports contain policy shape and capability names, not app-local state.",
    ownedTruth: "Per-app auth policy profile owned by Heimdall.",
    forbiddenFields: ["appSharedSecret", "appDomainState"],
  },
  {
    schemaId: "heimdall.managed_credential_projection.v0",
    documentType: "heimdall.managed_credential_projection.v0",
    cultCachePath: "cultcache/heimdall/managed-credentials/{appSlug}/{accountId}/{provider}.cc",
    redaction: "Expose custody status, provider subject, scopes, and expiry only; never provider tokens.",
    ownedTruth: "Read-only projection that a managed provider credential exists in Heimdall custody.",
    forbiddenFields: ["accessToken", "refreshToken", "accessTokenEncrypted", "refreshTokenEncrypted"],
  },
] as const;

export interface HeimdallAdvertisedProvider {
  key: Provider;
  displayName: string;
  roles: ProviderRole[];
  defaultScopes: string[];
  authorizationEndpoint: string;
  configuredByEnv: {
    clientId: string;
    clientSecret: string;
  };
}

export interface HeimdallAdvertisedAppProfile {
  slug: AppSlug;
  displayName: string;
  profileVersion: string;
  identityProviders: Provider[];
  entitlementSources: Provider[];
  managedConnectionProviders: Provider[];
  capabilities: CapabilityDefinition[];
}

export interface EveProviderAdvertisementDocument {
  schemaVersion: "gamecult.eve.provider_advertisement.v1";
  providerId: "heimdall";
  verseId: "gamecult";
  rootVerse: "asgard";
  canonicalService: "asgard.heimdall";
  locatedService: "asgard.starfire.heimdall";
  cultMeshAddress: "asgard.starfire.heimdall/eve/tui";
  title: "Heimdall";
  description: string;
  version: string;
  status: "read_only_witness_planned";
  updatedAt: string;
  provider: {
    id: "heimdall";
    title: "Heimdall";
    description: string;
    capabilities: string[];
    usesCultMesh: boolean;
    transport: string;
  };
  controlSurface: {
    primary: string;
    controls: {
      mode: "read-only";
      writes: false;
      reason: string;
    };
  };
  endpoints: string[];
  routes: Array<{
    kind: string;
    address: string;
    note: string;
  }>;
  providers: HeimdallAdvertisedProvider[];
  appProfiles: HeimdallAdvertisedAppProfile[];
  documents: HeimdallWitnessDocumentDescriptor[];
}

export function buildHeimdallProviderAdvertisement(options: { updatedAt: string }): EveProviderAdvertisementDocument {
  return {
    schemaVersion: "gamecult.eve.provider_advertisement.v1",
    providerId: "heimdall",
    verseId: "gamecult",
    rootVerse: "asgard",
    canonicalService: "asgard.heimdall",
    locatedService: "asgard.starfire.heimdall",
    cultMeshAddress: "asgard.starfire.heimdall/eve/tui",
    title: "Heimdall",
    description: "Shared GameCult auth/control-plane authority with redacted CultCache witness projections.",
    version: "read-only-witness-v0",
    status: "read_only_witness_planned",
    updatedAt: options.updatedAt,
    provider: {
      id: "heimdall",
      title: "Heimdall",
      description: "Publishes provider/app auth surfaces and planned redacted witness document paths for Odin and Eve.",
      capabilities: [
        "shared-auth",
        "provider-oauth",
        "linked-identities",
        "capability-grants",
        "session-claims",
        "managed-credential-custody",
        "redacted-cultcache-witness",
      ],
      usesCultMesh: true,
      transport: "CultMesh provider advertisement; first cut is a read-only fixture/export.",
    },
    controlSurface: {
      primary: "asgard.starfire.heimdall/eve/tui",
      controls: {
        mode: "read-only",
        writes: false,
        reason: "This export advertises witness shapes only. Runtime auth mutation remains behind Heimdall APIs.",
      },
    },
    endpoints: [
      "asgard.starfire.heimdall/eve/tui",
      "asgard.starfire.heimdall/eve/gui",
      "asgard.starfire.heimdall/witness",
    ],
    routes: [
      {
        kind: "cultmesh-legacy-uri",
        address: "cultmesh://gamecult/heimdall/provider-advertisement",
        note: "Legacy document route; not service identity.",
      },
      {
        kind: "cultmesh-legacy-uri",
        address: "cultmesh://gamecult/heimdall/witness",
        note: "Legacy witness route; not service identity.",
      },
    ],
    providers: providers.map((provider) => {
      const descriptor = providerCatalog[provider];
      return {
        key: descriptor.key,
        displayName: descriptor.displayName,
        roles: descriptor.roles,
        defaultScopes: descriptor.defaultScopes,
        authorizationEndpoint: descriptor.authorizationEndpoint,
        configuredByEnv: {
          clientId: descriptor.clientIdEnv,
          clientSecret: descriptor.clientSecretEnv,
        },
      };
    }),
    appProfiles: appSlugs.map((appSlug) => {
      const profile = appProfiles[appSlug];
      return {
        slug: profile.slug,
        displayName: profile.displayName,
        profileVersion: profile.profileVersion,
        identityProviders: profile.identityProviders,
        entitlementSources: profile.entitlementSources,
        managedConnectionProviders: profile.managedConnectionProviders,
        capabilities: profile.capabilities,
      };
    }),
    documents: [...heimdallWitnessDocuments],
  };
}
