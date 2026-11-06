# Answer Collector: Record and Consent

Status: specification. Nothing here is implemented. It fixes what an answer
record is and what a respondent has agreed to, so that a collector, a tally and
a training export can be built against one definition.

Scope: free-text and choice answers that members give to a sample put to them
by an experiment. Not identity proof (see `architecture.md`).

## Record

One record per answer. Fields:

| field | rule |
|---|---|
| `sample_id` | names the thing answered about, with a version component (`<sample>@<version>`). A changed sample is a new version. |
| `experiment_id` | the experiment that asked. |
| `member_id` | Heimdall member id of the respondent. Never a Matrix id, never a display name. |
| `scope` | `show` \| `study` \| `train`. Default `show`. |
| `text` | the answer as given. |
| `revoked` | boolean, default false. One-way: a revoked record is never un-revoked; a new answer is a new record. |
| `received_at` | collector clock, UTC. |

Key: `(experiment_id, sample_id, member_id)`. A member's later answer to the
same key replaces the earlier one (latest `received_at` wins); the earlier text
is not retained.

## Versions

Answers never tally across `sample_id` versions. A tally is computed for one
full `sample_id` including version; there is no "all versions" aggregate and no
API that takes a sample without a version. A version bump starts an empty tally.

## Scope

Scope is the widest use the respondent allowed. Each use reads exactly one
level:

- `show`: may be displayed back inside the experiment (to the respondent, and
  in aggregate to participants). Nothing else.
- `study`: `show`, plus analysis by the experiment's researchers. May be quoted
  in findings only unattributed.
- `train`: `study`, plus use as training or evaluation data for models.

Rule: nothing is training data unless `scope = train`. A missing, unparseable
or unknown scope is `show`, never wider. Scope can be narrowed by a new answer
or revocation; widening is a new answer by the respondent, never an inference.

## Identity: count once, reward without exposure

The Matrix sender is mapped to a Heimdall member id by Heimdall's linked
identity, at collection time. The collector stores `member_id` only; the Matrix
sender is discarded after mapping. A sender with no linked member is dropped,
not stored under a placeholder.

- Count once: the key above makes one member one answer per sample version,
  however many Matrix accounts or bridges they use.
- Reward without exposure: a reward is issued against `member_id` by the
  rewarding service. Researchers and displays see counts and text under their
  scope, never `member_id`. The mapping from a record to a person is available
  to the reward path only.

## Eureka's shape (Matrix)

- One room per experiment. The room is `experiment_id`.
- The sample is posted as a message; an answer is a thread reply to it whose
  body starts `scope: <x>` on its first line, the answer text following.
- The reply event is the receipt: its event id and timestamp are the proof the
  answer was received, and `received_at` comes from it.
- Redaction is revoke: redacting the reply event sets `revoked`.
- The collector is on demand (it reads the room when run, it is not a standing
  listener). It drops:
  - redacted replies;
  - replies with no `scope:` line (consent is explicit in Matrix; the `show`
    default applies to records created elsewhere, not to silence);
  - replies from unlinked senders;
  - replies to an old sample version when the tally is for a newer one.
- Records wider than `show` (`study`, `train`) are kept apart from `show`
  records: separate store or partition, so a read for one level cannot
  accidentally return another.

## What Matrix cannot guarantee

- **Receipt outliving a deleted reply.** Redaction removes content, and
  homeserver retention varies. If the collector holds a receipt for a reply that
  later disappears, it keeps a tombstone: event id, `sample_id`, `received_at`,
  and a hash of `text` (hash only, no text), so the count and the revoke are
  provable without the content. The record is marked `revoked`; `text` is
  erased.
- **Edits.** An edit is a new event, not the receipt. Only the original event
  counts; edits are ignored, so what was consented to is what was received. To
  change an answer, redact and reply again.
- **Bridge spoofing.** A bridge can post as any ghost user. Only senders whose
  Matrix id resolves through Heimdall's linked identity to a member count;
  bridged ghost ids are not linked identities. A bridge cannot raise scope, as
  scope comes only from the reply's own `scope:` line.
- **Discord material.** Nothing that originates from Discord is collected,
  even through a bridge, at any scope: Discord forbids training on its
  content. Bridged events are dropped by origin, not by judging text.

## What the respondent sees

Posted with the sample, in the room:

- the three scopes in one line each, as above;
- that no `scope:` line means the answer is not collected;
- how to revoke.

After answering, the respondent sees their receipt: the thread reply itself,
plus the collector's acknowledgement that names the scope it recorded. If it
recorded narrower than they asked, it says so.

## How to revoke

Redact your reply. That is all. The next collection run marks the record
`revoked`, erases `text`, and excludes it from every tally and export. Anything
already exported at `train` before the run cannot be recalled by Matrix; the
experiment's page states the export cadence so the window is known.
