import { describe, expect, it } from "vitest";
import {
  buildHeimdallProviderAdvertisement,
  heimdallWitnessDocuments,
  heimdallWitnessSchemaIds,
} from "../src/verse-witness.js";

describe("Heimdall Verse witness advertisement", () => {
  it("advertises the Odin/Eve provider surface and redacted witness documents", () => {
    const advertisement = buildHeimdallProviderAdvertisement({
      updatedAt: "2026-06-03T12:00:00.000Z",
    });

    expect(advertisement).toMatchObject({
      schemaVersion: "gamecult.eve.provider_advertisement.v1",
      providerId: "heimdall",
      verseId: "gamecult",
      status: "read_only_witness_planned",
      updatedAt: "2026-06-03T12:00:00.000Z",
      controlSurface: {
        controls: {
          mode: "read-only",
          writes: false,
        },
      },
    });
    expect(advertisement.providers.map((provider) => provider.key)).toEqual([
      "discord",
      "patreon",
      "github",
      "twitch",
      "youtube",
      "spotify",
    ]);
    expect(advertisement.appProfiles.map((profile) => profile.slug)).toEqual([
      "repixelizer",
      "streampixels",
      "spotiverse",
    ]);
    expect(advertisement.documents.map((document) => document.schemaId)).toEqual([...heimdallWitnessSchemaIds]);
  });

  it("keeps token custody fields forbidden in witness descriptors", () => {
    expect(heimdallWitnessDocuments).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          schemaId: "heimdall.linked_identity.v0",
          forbiddenFields: expect.arrayContaining(["accessTokenEncrypted", "refreshTokenEncrypted"]),
        }),
        expect.objectContaining({
          schemaId: "heimdall.managed_credential_projection.v0",
          forbiddenFields: expect.arrayContaining(["accessToken", "refreshToken"]),
        }),
      ])
    );
  });
});
