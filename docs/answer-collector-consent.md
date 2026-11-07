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
one notice that names the scope the room's answers may be used for and the way
out. A notice has a `notice_version`; any change to its wording or scope is a new
version.

### Where the notice lives

A room's notice is a Matrix room state event: type `org.gamecult.notice`, empty
`state_key`, content `{version, scope}`.

- `version` follows the version rule under Representation.
- `scope` is `show`, `study` or `train`.
- The event is set under the room's power levels. A pinned message is not
  accepted as a notice: anyone who can pin could forge it.
- Absent or malformed (a missing or unknown field, a `version` the version rule
  does not accept, an unknown `scope`) means no `train`
  line and the narrowest scope, `show`. Malformed content is never repaired.

The wording shown to respondents is the room's own business; the collector reads
only `version` and `scope`. A change to either is a new state event and so a
new `version`.

| scope | what the notice allows |
|---|---|
| `show` | display back inside the experiment (to the respondent, and in aggregate to participants). Nothing else. |
| `study` | `show`, plus analysis by the experiment's researchers. Quoted in findings only unattributed. |
| `train` | `study`, plus use as training or evaluation data for models. |

`train` is a declared scope: it is used only when the notice for that room says
`train` in terms. It is never inferred, never a default, and never raised by a
reply.

The first reply a member posts in the room is their acceptance of the notice
version then in force. No separate click, command or form. A later notice version
needs a new acceptance: the member's first reply under it.

### Notice acceptance record

| field | type | rule |
|---|---|---|
| `member_id` | Heimdall member id | the accepting member. |
| `experiment_id` | string | the room. |
| `notice_version` | integer | the `version` of the room's notice state event when the reply was received. |
| `scope` | `show` \| `study` \| `train` | the scope that version declared. |
| `accepted_at` | UTC timestamp | `origin_server_ts` of the first reply. |
| `event_id` | Matrix event id | that reply, as proof. |

Key: `(experiment_id, member_id, notice_version)`. Written once, never updated.

## Terms (newcomers only)

Joining Heimdall is gated by terms. Acceptance is the terms version recorded by
the Matrix `m.login.terms` stage at registration: member field `terms_version`
(string) and `terms_accepted_at` (UTC timestamp). These fields belong to the
Heimdall member record. A typed `MemberTerms` record keyed by `member_id` is the
shape of that pair in a typed library; it is not a second store, and the
collector does not hold it. This applies to newcomers
only. Members who joined before the terms stage existed, and Minds, are not
re-asked and have no `terms_version`; the collector does not read it and does not
gate on it. The notice above is the only consent the collector itself checks.

Open gap: the registration checkbox records no version. Void is raising this;
nothing here rules it.

## Answer record

One record per answer. Fields:

| field | type | rule |
|---|---|---|
| `sample_id` | string `<sample>@<version>` | names the thing answered about; `<version>` follows the version rule under Representation. A changed sample is a new version. |
| `experiment_id` | string | the experiment that asked. |
| `member_id` | Heimdall member id | the respondent. Never a Matrix id, never a display name. |
| `notice_version` | integer | the notice version in force when the answer was received; matches an acceptance record by the key above. |
| `scope` | `show` \| `study` \| `train` | copied from that notice version at answer time. Never edited afterwards. |
| `text` | string, or absent | the answer as given. Non-empty while the answer is live; absent once exited. |
| `exited` | boolean, default false | one-way: set by redaction, never cleared. A new answer is a new record. |
| `text_hash` | 32 bytes, or absent | the tombstone hash of `text` (see "Tombstone"). Present only once exited, and only when the collector held `text` before the redaction. |
| `received_at` | UTC timestamp | assigned by the collector when it receives the reply. Not copied from the reply. |
| `event_id` | Matrix event id | the reply; the receipt. |

Key: `(experiment_id, sample_id, member_id)`. A member's later answer to the
same key replaces the earlier one (latest `received_at` wins); the earlier text
is not retained. Two replies to one key with equal `received_at` tie-break on
`event_id` compared bytewise: the greater `event_id` wins as the later reply.

Empty text: a live (non-exited) answer must have non-empty `text`, and the
collector rejects a reply whose text is empty. Empty text is valid only on an
exited answer, where redaction clears `text` and leaves the hash-only tombstone.

A reply whose `notice_version` or `scope` is missing, unparseable or has no
matching acceptance record is stored, with those fields absent. It is excluded
from every use: no tally, no display, and from training in particular. It
writes no acceptance record. The reply is kept so the member can still exit it
and the collector can show what it refused, but no scope was declared, so none
is inferred. The notice version of a reply is the one the room's notice state
event held at the reply's `origin_server_ts`; if the collector cannot establish
what it held then, the reply has no notice version.

### Representation

- Timestamps are Unix milliseconds in UTC, stored as a signed 64-bit integer,
  the unit of Matrix `origin_server_ts`. Every "UTC timestamp" above means this.
- `member_id`, `experiment_id` and `event_id` are non-empty strings;
  `member_id` is opaque and `event_id` is the Matrix event id verbatim.
- Version rule. Every version field in the consent system is a positive integer
  written in decimal with no leading zeros and at most 4294967295 (u32 max):
  the `<version>` of `sample_id` (`s@<version>`), `notice_version`, the
  `version` of the room notice `org.gamecult.notice`, and the notice acceptance
  and terms records (`terms_version`, carried as that decimal string). Anything
  else (zero, a sign, whitespace, a non-digit, a leading zero such as `s@01`, a
  value above the maximum) is refused, not normalised: `s@1` is the only
  spelling of version 1, so one version has exactly one key. A room notice
  whose `version` fails the rule is malformed: no `train` line, narrowest scope
  `show`. Nothing is silently rewritten to fit.
- Two encodings of the one version rule. In the `org.gamecult.notice` room state
  event, `version` is a JSON number; a string (including `"01"`) is malformed.
  In the answer key (`s@<version>`, and the composite keys), the version stays
  its encoded decimal text, held to the leading-zero refusal. The rule is the
  same in both: a positive integer, no leading zeros, at most 4294967295.
- A composite key is its parts joined with U+001F. A part that is empty or
  contains U+001F is refused, not escaped.

## Versions

Answers never tally across `sample_id` versions. A tally is computed for one
full `sample_id` including version; there is no "all versions" aggregate and no
API that takes a sample without a version. A version bump starts an empty tally.
Replies to an old version are dropped when the tally is for a newer one.

## Training rule

A record is training or evaluation data only if all hold:

1. `scope = train`, copied from a notice version that declared `train`;
2. an acceptance record exists for `(experiment_id, member_id, notice_version)`
   of the answer, its own `scope` is `train` and equals the answer's `scope`,
   and `accepted_at <= received_at`, i.e. the author had accepted that notice
   version when they answered;
3. `exited = false` at export time.

No recorded scope, or no recorded acceptance, means excluded. Records wider than
`show` are kept apart from `show` records: one store per scope (`show`, `study`,
`train`) plus a store for scopeless replies that no read path serves. A record
lives in the store its `scope` names, so a read for one level cannot return
another. A typed-record library need not model the partition; the collector's
store layout owns it.

## Tombstone

- Function: HMAC-SHA-256 (RFC 2104 with SHA-256, FIPS 180-4), output the raw 32
  bytes stored in `text_hash`. No truncation.
- Message: the ASCII string `heimdall.tombstone.v1`, U+001F, `event_id`
  (UTF-8), U+001F, `text` (UTF-8, as received, no normalisation). The `event_id`
  makes the hash specific to the reply, so equal texts hash differently.
- Key (the salt): 32 bytes from a cryptographically secure random source,
  generated once per member by the member-side service, which is the service that
  already maps Matrix sender to `member_id`. It is held there, beside the member
  record, and is never given to the collector, a researcher, an export or a log.
  The collector cannot compute or check a tombstone hash on its own.
- Redaction: when the collector sees a redaction of a reply whose text it holds,
  it sends `event_id` and `text` to the member-side service, which returns the
  hash; the collector writes `text_hash`, sets `exited`, and erases `text`. If the
  service does not answer, `text` is kept, the record is not yet exited, and the
  run retries. A reply the collector never collected has no text and gets no
  tombstone.
- Verification: only the member-side service can check a claimed text against a
  tombstone. If a member's salt is destroyed, their tombstones can no longer be
  tied to any text, and that is the member's erasure.

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
- The sample is posted as a message; the room's notice is its `org.gamecult.notice` state event. An answer
  is a thread reply to the sample, the answer text being the body. There is no
  per-reply scope syntax.
- The reply event is the receipt: its event id and timestamp are the proof the
  answer was received. `received_at` is the collector's own clock at receipt,
  not the reply's `origin_server_ts`.
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
  The tombstone is the exited `Answer` record itself, with `text_hash` set; it is
  not a separate record.
- **Edits.** An edit is a new event, not the receipt. Only the original event
  counts; edits are ignored, so what was accepted is what was received. To
  change an answer, redact and reply again.
- **Bridge spoofing.** A bridge can post as any ghost user. Only senders whose
  Matrix id resolves through Heimdall's linked identity to a member count;
  bridged ghost ids are not linked identities. A bridge cannot raise scope: scope
  comes only from the room's notice state event.
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
