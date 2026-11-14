import { type Provider } from "../contracts.js";
import { type MoveIdentitiesInput, type StoredIdentityMove, type StoredLinkedIdentity } from "./types.js";

/** Everything a store read under its locks that the move rules decide on. */
export interface MoveFacts {
  /** The identity_moves row already holding input.moveId. */
  existing: StoredIdentityMove | null;
  /** The move input.reversesMoveId names, and whether a reversal of it already exists. */
  forward: { move: StoredIdentityMove; reversed: boolean } | null;
  /** Every proof session still carries its sid, app, account and access revision and has not expired. */
  proofSessionsLive: boolean;
  sourceIdentities: readonly StoredLinkedIdentity[];
  destinationProviders: ReadonlySet<Provider>;
  /** An account with no identity and an unreversed move from it. */
  sourceIsAlias: boolean;
  destinationIsAlias: boolean;
}

export type MoveDecision =
  | { kind: "replayed"; move: StoredIdentityMove }
  | { kind: "refused"; result: { kind: "move_id_conflict" | "proof_lapsed" | "already_moved" | "identity_not_found" | "identity_not_proved" | "not_reversible" } | { kind: "provider_conflict"; provider: Provider } }
  | { kind: "move"; identities: StoredLinkedIdentity[] };

/**
 * The one statement of the move rules, in the order they are decided. Both
 * stores gather MoveFacts under their locks and apply the answer, so memory
 * and Postgres cannot disagree about what a move refuses.
 */
export function decideMove(input: MoveIdentitiesInput, facts: MoveFacts): MoveDecision {
  const refuse = (kind: "move_id_conflict" | "proof_lapsed" | "already_moved" | "identity_not_found" | "identity_not_proved" | "not_reversible"): MoveDecision => ({ kind: "refused", result: { kind } });

  const { existing } = facts;
  if (existing) {
    return existing.appSlug === input.appSlug &&
      existing.fromAccountId === input.fromAccountId &&
      existing.toAccountId === input.toAccountId &&
      existing.reversesMoveId === input.reversesMoveId
      ? { kind: "replayed", move: existing }
      : refuse("move_id_conflict");
  }
  if (!facts.proofSessionsLive) return refuse("proof_lapsed");

  const held = new Set(facts.sourceIdentities.map((identity) => identity.id));
  if (input.reversesMoveId !== undefined) {
    const forward = facts.forward;
    if (
      !forward ||
      forward.reversed ||
      forward.move.appSlug !== input.appSlug ||
      forward.move.reversesMoveId !== undefined ||
      forward.move.toAccountId !== input.fromAccountId ||
      forward.move.fromAccountId !== input.toAccountId ||
      !forward.move.moved.every((moved) => held.has(moved.id))
    ) {
      return refuse("not_reversible");
    }
  } else if (facts.sourceIsAlias || facts.destinationIsAlias) {
    return refuse("already_moved");
  }

  let chosen: StoredLinkedIdentity[];
  if (input.identityIds === "all") {
    chosen = [...facts.sourceIdentities];
  } else {
    if (!input.identityIds.every((id) => held.has(id))) return refuse("identity_not_found");
    const wanted = new Set(input.identityIds);
    chosen = facts.sourceIdentities.filter((identity) => wanted.has(identity.id));
  }
  if (chosen.length === 0) return refuse("identity_not_found");

  if (input.covers !== "account") {
    const covered = new Set(input.covers);
    if (!chosen.every((identity) => covered.has(identity.id))) return refuse("identity_not_proved");
  }
  const clash = chosen.find((identity) => facts.destinationProviders.has(identity.provider));
  if (clash) return { kind: "refused", result: { kind: "provider_conflict", provider: clash.provider } };
  return { kind: "move", identities: chosen };
}

/** The history a move writes about what it carried. */
export function movedRecord(identities: readonly StoredLinkedIdentity[]): StoredIdentityMove["moved"] {
  return identities.map((identity) => ({
    id: identity.id,
    provider: identity.provider,
    providerUserId: identity.providerUserId,
    credentialStripped: identity.accessTokenEncrypted !== undefined || identity.refreshTokenEncrypted !== undefined,
  }));
}
