# TON — Tipbot Oracle Node

Reference implementation of an oracle for the Xahau tipbot. It watches the X
filtered stream for `@XahauTipBot` / `@xrptipbot` commands, encodes each one as
an 85-byte *opinion*, and submits them to the tip Hook on Xahau
(`rtipboteEEZ6JkTNvcYgUZbiYyrV2W7DQ`) as `Invoke` transactions, up to 16
opinions per transaction with a Memo pointing back at the source post.

Several oracles run independently. A tip is only actioned once more than half
of the oracle game's members have submitted the same opinion for the same post,
so no single node can mint a tip on its own, and a node that misses a post
leaves the others' votes stranded until it is replayed.

**Try the parser in your browser:** <https://richardah.github.io/tipbot-oracle-node/bench.html>
loads the real `ton.js` from this repo and runs it against posts you type —
replies, hidden mentions, multitips, retweets, currencies — showing the verdict,
the decoded opinion bytes and the exact X payload. Use it to check a command
before posting it, to reproduce a report, or to compare a branch against main.

## Running an oracle

Requires Node 22.12+ (or 20.19+) and a git checkout of this repo.

```sh
git clone https://github.com/RichardAH/tipbot-oracle-node
cd tipbot-oracle-node
npm install
node ton.js
```

Run from the checkout, as above, and `ton.js` acts as a small supervisor: the
oracle runs in a child process, and the supervisor keeps the checkout on the
tip of `origin/main` and restarts the worker whenever that moves. Local edits
and commits are overwritten. Ctrl-C stops both.

### Configuration

`~/.tipbotcfg` (JSON):

```json
{
  "bearer_token": "...",            // X API v2 bearer
  "seed": "s...",                   // family seed of THIS oracle's member account
  "wss": "wss://xahau.network",     // optional
  "auto_update": true,              // optional, default true
  "update_branch": "main",          // optional
  "update_interval_s": 300,         // optional, poll period (jittered)
  "backfill_max_hours": 24,         // optional, 0 disables backfill
  "shortcuts_url": "https://...",   // optional, default RichardAH/TipBot-Shortcuts
  "shortcuts_interval_s": 300       // optional, poll period (jittered)
}
```

The member account must already be in the oracle game; a submission from any
other account is accepted by the Hook and ignored.

### State files

| File | Purpose |
| --- | --- |
| `~/.tipbot-seen` | post ids already turned into opinions, so a restart does not re-tip what the stream redelivers |
| `~/.tipbot-queue.json` | opinions not yet submitted when the process stopped; resubmitted at the next start |
| `~/.tipbot-alive` | last time the process was listening; the gap since is backfilled from recent search at start |
| `~/.tipbot-shortcuts.json` | last good copy of the token shortcut list, used when GitHub is unreachable at start |

### Other commands

```sh
node ton.js --replay <post id>...             # submit posts the stream missed
node ton.js --replay --dry-run <post id>...   # show what they would submit, touch nothing
node ton.js --check-shortcuts shortcuts.json  # validate a shortcut list before pushing it
```

`--replay` fetches the posts by id from X, runs them through the normal
parser and submits the opinions; use it when an oracle's log shows no
`Matching tweet received` line for a post that other oracles voted on.

## Command grammar

Tips are XAH unless a currency is written directly after the amount:
`+5`, `+5 EVR`, `+5 $RLUSD:rIssuer...`, `+5 <40 hex>`. A token in that slot
that looks like a currency but does not resolve is rejected rather than sent as
XAH; prose there (`+1 thanks`, emoji) leaves the tip in XAH. Ticker-only
tokens such as `EVR` resolve through the shortcut list in
[RichardAH/TipBot-Shortcuts](https://github.com/RichardAH/TipBot-Shortcuts).

The amount may come before or after the bot, or elsewhere in a post that
mentions it. The recipient is, in order:

1. the mention directly before the command, in either order:
   `@alice @XahauTipBot +1`, `@alice +1 @XahauTipBot`;
2. on a reply to someone else, the author of the post replied to — any other
   mention in the text is prose, so `great work @XahauNetwork! @XahauTipBot +5`
   in a reply tips the person replied to;
3. otherwise, the first mention the author typed:
   `Thanks @alice! +1 @XahauTipBot`.

Only what the author typed counts; the "replying to" mentions X hides are
never a recipient. Several commands that each name a recipient form a
multitip (`@alice +1 @XahauTipBot @bob +2 EVR @XahauTipBot`) and pay
separately. Retweets are dropped outright, edits are keyed to the original
post, and a user cannot tip themselves or the bot.

Withdrawals: `@XahauTipBot withdraw 20 XAH to r...` (currency mandatory).

## Reading the Hook's result

Once an `Invoke` validates, the oracle logs the Hook's return string. It ends
with one letter per opinion, in parameter order:

| Letter | Meaning |
| --- | --- |
| `S` | vote recorded, threshold not yet met |
| `A` | threshold met by this vote — tip actioned |
| `D` | already actioned by an earlier vote (duplicate) |
| `V` | this member already voted on the post |
| `B` | sender's balance too small |
| `X` | self-tip, retired |
| `W` | non-positive amount |
| `E` / `O` | internal arithmetic error, skipped |

An `S` with no later `A` from another oracle means the other oracles never
submitted the post — check their logs and `--replay` it there.

## Repository layout

- `ton.js` — the whole oracle: stream, parser, opinion codec, submitter,
  supervisor and self-updater. Comments in the file are the detailed spec.
- `bench.html` — the browser debug bench linked above; it loads `ton.js`
  from this repo through a small Node emulation, so there is no second copy
  of the parser to drift.
- The Hook contracts live in
  [RichardAH/tipbot-hooks](https://github.com/RichardAH/tipbot-hooks).
