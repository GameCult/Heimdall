# Answer Collector: Record and Consent

Status: specification. Nothing here is implemented. It fixes what an answer
record is and what a respondent has agreed to, so that a collector, a tally and
a training export can be built against one definition. Field names and types
below are the contract for the typed CultCache records.

Scope: free-text and choice answers that members give to a sample put to them
by an experiment. Not identity proof (see `architecture.md`). Personal details
(names, contact data, account identifiers, anything that identifies a person) are
out of scope: the collector does not ask for them and a sample must not solicit
them. The only identifier it keeps is `member_id`, and that stays on the reward
path.

## Notice

Consent is declared once per room, not per reply. Each experiment room carries
one notice line, pinned with the sample, that names the scope the room's answers
may be used for and the way out. A notice has a `notice_version`; any change to
its wording or scope is a new version.

| scope | what the notice allows |
|---|---|
| `show` | display back inside the experiment (to the respondent, and in aggregate to participants). Nothing else. |
| `study` | `show`, plus analysis by the experiment's researchers. Quoted in findings only unattributed. |
| `train` | `study`, plus use as training or evaluation data for models. |

`train` is a declared scope: it is used only when the notice for that room says
`train` in terms. It is never inferred, never a default, and never raised by a
reply.

The first reply a member posts in the room is their acceptance of the notice
version then pinned. No separate click, command or form. A later notice version
needs a new acceptance: the member's first reply under it.

### Notice acceptance record

| field | type | rule |
|---|---|---|
| `member_id` | Heimdall member id | the accepting member. |
| `experiment_id` | string | the room. |
| `notice_version` | integer | the version pinned when the reply was received. |
| `scope` | `show` \| `study` \| `train` | the scope that version declared. |
| `accepted_at` | UTC timestamp | `origin_server_ts` of the first reply. |
| `event_id` | Matrix event id | that reply, as proof. |

Key: `(experiment_id, member_id, notice_version)`. Written once, never updated.

## Terms (newcomers only)

Joining Heimdall is gated by terms. Acceptance is the terms version recorded by
the Matrix `m.login.terms` stage at registration: member field `terms_version`
(string) and `terms_accepted_at` (UTC timestamp). This applies to newcomers
only. Members who joined before the terms stage existed, and Minds, are not
re-asked and have no `terms_version`; the collector does not read it and does not
gate on it. The notice above is the only consent the collector itself checks.

## Answer record

One record per answer. Fields:

| field | type | rule |
|---|---|---|
| `sample_id` | string `<sample>@<version>` | names the thing answered about; `<version>` is a positive integer. A changed sample is a new version. |
| `experiment_id` | string | the experiment that asked. |
| `member_id` | Heimdall member id | the respondent. Never a Matrix id, never a display name. |
| `notice_version` | integer | the notice version in force when the answer was received; matches an acceptance record by the key above. |
| `scope` | `show` \| `study` \| `train` | copied from that notice version at answer time. Never edited afterwards. |
| `text` | string, or absent | the answer as given. Absent once exited. |
| `exited` | boolean, default false | one-way: set by redaction, never cleared. A new answer is a new record. |
| `received_at` | UTC timestamp | `origin_server_ts` of the reply. |
| `event_id` | Matrix event id | the reply; the receipt. |

Key: `(experiment_id, sample_id, member_id)`. A member's later answer to the
same key replaces the earlier one (latest `received_at` wins); the earlier text
is not retained.

A record whose `notice_version` or `scope` is missing, unparseable or has no
matching acceptance record is not collected. It is excluded from every use, and
from training in particular.

## Versions

Answers never tally across `sample_id` versions. A tally is computed for one
full `sample_id` including version; there is no "all versions" aggregate and no
API that takes a sample without a version. A version bump starts an empty tally.
Replies to an old version are dropped when the tally is for a newer one.

## Training rule

A record is training or evaluation data only if all hold:

1. `scope = train`, copied from a notice version that declared `train`;
2. an acceptance record exists for `(experiment_id, member_id, notice_version)`
   with `accepted_at <= received_at`, i.e. the author had accepted that notice
   version when they answered;
3. `exited = false` at export time.

No recorded scope, or no recorded acceptance, means excluded. Records wider than
`show` are kept apart from `show` records: separate store or partition, so a read
for one level cannot return another.

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
- The sample is posted as a message, with the notice pinned beside it. An answer
  is a thread reply to the sample, the answer text being the body. There is no
  per-reply scope syntax.
- The reply event is the receipt: its event id and timestamp are the proof the
  answer was received, and `received_at` comes from it.
- Redaction is exit (see below): redacting the reply event sets `exited`.
- The collector is on demand (it reads the room when run, it is not a standing
  listener). It drops:
  - redacted replies (recorded as exited);
  - replies from unlinked senders;
  - replies to an old sample version when the tally is for a newer one.

## What Matrix cannot guarantee

- **Receipt outliving a deleted reply.** Redaction removes content, and
  homeserver retention varies. If the collector holds a receipt for a reply that
  later disappears, it keeps a tombstone: `event_id`, `sample_id`, `received_at`,
  and a salted hash of `text`. Hash only, never text, and no `member_id`
  beyond what the record's key already holds. The count and the exit are
  provable without the content. The record is marked `exited`; `text` is erased.
- **Edits.** An edit is a new event, not the receipt. Only the original event
  counts; edits are ignored, so what was accepted is what was received. To
  change an answer, redact and reply again.
- **Bridge spoofing.** A bridge can post as any ghost user. Only senders whose
  Matrix id resolves through Heimdall's linked identity to a member count;
  bridged ghost ids are not linked identities. A bridge cannot raise scope: scope
  comes only from the pinned notice version.
- **Bridged origin.** Events that arrive through a bridge are dropped by origin,
  not by judging their text.

## What the respondent sees

Posted with the sample, in the room:

- the notice: its scope in one line, that the first reply accepts it, and how to
  exit;
- the notice version.

After answering, the respondent sees their receipt: the thread reply itself,
plus the collector's acknowledgement that names the notice version and scope it
recorded.

The consent and vote controls make no reward sound, animation or other
reinforcement. A reward is issued later, by the rewarding service, never as
feedback to the act of consenting or voting.

## How to exit

Redact your reply. That is all. The next collection run sets `exited`, erases
`text`, and excludes the record from every later tally and from training. It
cannot undo past use: tallies already shown and anything already exported
cannot be recalled by Matrix or by the collector. The experiment's page states
the export cadence so the window is known.
