import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import { afterEach, describe, expect, it } from "vitest";

// GHSA-p68q-wchp-6fh7 (fastify < 5.12.2): a malformed request target under one
// plugin prefix, with a method that has no route in the main router, was
// dispatched to the not-found handler of a sibling plugin, skipping that
// handler's preHandler. This pins the framework fix; it is not about a Heimdall
// route.
describe("fastify malformed URL under sibling not-found handlers", () => {
  const apps: Array<ReturnType<typeof Fastify>> = [];
  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  async function build() {
    const app = Fastify();
    apps.push(app);
    await app.register(async (pub) => {
      pub.get("/ping", async () => "pong");
    }, { prefix: "/public" });
    await app.register(async (priv) => {
      priv.setNotFoundHandler(
        {
          preHandler: async (request: FastifyRequest, reply: FastifyReply) => {
            if (!request.headers.authorization) return reply.code(401).send({ error: "auth" });
          },
        },
        (_request: FastifyRequest, reply: FastifyReply) => reply.code(404).send({ secret: "PRIVATE-TENANT-DATA" }),
      );
      priv.get("/x", async () => "x");
    }, { prefix: "/private" });
    return app;
  }

  it("fails closed with 400 and never reaches another prefix's not-found handler", async () => {
    const app = await build();
    const response = await app.inject({ method: "DELETE", url: "/public/%zz" });
    expect(response.body).not.toContain("PRIVATE-TENANT-DATA");
    expect(response.statusCode).toBe(400);
  });

  it("still runs the authenticated not-found preHandler for a well-formed URL", async () => {
    const app = await build();
    const response = await app.inject({ method: "DELETE", url: "/private/nothing" });
    expect(response.statusCode).toBe(401);
  });
});
