#!/usr/bin/env node
'use strict';
/**
 * TON - Tipbot Oracle Node
 * Watches the X filtered stream for @xrptipbot / @xahtipbot commands,
 * encodes them as 85-byte opinions and submits them (batched, <=16 per
 * Invoke, parameter names 0x00..0x0F) to the tip Hook on Xahau.
 *
 * Each opinion carries a Memo holding the URL of the tweet it came from.
 * Memos[i] corresponds to HookParameter 0x0i, so the on-ledger record of
 * every opinion points back at its source post.
 *
 * An opinion is only ever minted for a command its own author wrote. Retweets
 * are dropped outright - not attributed to the retweeter, and not unwrapped
 * back to the original author - and a post's identity is the root of its edit
 * chain, so editing or redelivering a command cannot tip twice.
 *
 * Tips are XAH unless a currency is stated, and a currency is only ever the
 * token directly after the amount: '+5 EVR', '+5 $RLUSD:r...', '+5 <40 hex>'.
 * A token there that looks like a currency but does not resolve is rejected,
 * never sent as XAH; prose there ('+1 thanks', emoji) leaves the tip in XAH.
 *
 * Otherwise the grammar is the old xrptipbot's (WietseWind/xrptipbot,
 * cli/twitter/fetch_pbs.php): the amount may come before or after the bot
 * ('+100 @XahTipBot', '@XahTipBot +100'), or elsewhere in a post that mentions
 * it. See parseTipbotTweet() for where and why this deliberately differs.
 * A post with several commands that each name a recipient is a multitip:
 * '@alice +1 @XahTipBot @bob +2 EVR @XahTipBot' pays both, as one opinion each
 * under a derived post_id (see subPostId()).
 *
 * The recipient comes from what the author typed, never from the reply
 * mentions X hides: '@alice @XahTipBot +1' tips alice, and a reply saying just
 * '@XahTipBot +1' tips the author of the post it replies to.
 *
 * deps: npm i node-fetch@2 xrpl-client xrpl-accountlib
 *
 * usage: ton.js                                  run the oracle
 *        ton.js --replay <post id>...            submit posts the stream missed
 *        ton.js --replay --dry-run <post id>...  show what they would submit
 *        ton.js --check-shortcuts <file>         validate a shortcuts.json
 *
 * ~/.tipbot-seen: append-only list of post ids already turned into opinions,
 * so a restart does not re-tip whatever the stream redelivers.
 *
 * ~/.tipbot-queue.json: opinions still unsubmitted when the process stopped,
 * resubmitted at the next start. ~/.tipbot-alive: last time the process was
 * known to be listening; at start, the gap since is backfilled from search.
 *
 * ~/.tipbot-shortcuts.json: last good copy of the token shortcut list (see
 * "well-known token shortcuts"), used when a start cannot reach GitHub.
 *
 * Self-update: run it as `node ton.js` from a git checkout of
 * RichardAH/tipbot-oracle-node, with the checkout as cwd. That process is a
 * small supervisor; the oracle itself runs in a child `node ton.js --worker`
 * started from whatever ton.js is on disk. The supervisor keeps the checkout
 * on the tip of origin/main no matter what - rewritten history, local commits
 * and local edits are all overwritten - and restarts the worker onto it.
 * Ctrl-C stops both. See supervise().
 *
 * ~/.tipbotcfg (JSON):
 * {
 *   "bearer_token": "...",            // X API v2 bearer
 *   "seed": "s...",                   // family seed of THIS oracle's member account
 *   "wss": "wss://xahau.network",     // optional
 *   "auto_update": true,              // optional, default true
 *   "update_branch": "main",          // optional
 *   "update_interval_s": 300,         // optional, poll period (jittered)
 *   "backfill_max_hours": 24,         // optional, 0 disables backfill
 *   "shortcuts_url": "https://...",   // optional, default RichardAH/TipBot-Shortcuts
 *   "shortcuts_interval_s": 300       // optional, poll period (jittered)
 * }
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFile, execFileSync, spawn } = require('child_process');
// xrpl-accountlib's dependency tree now reaches ES-module-only packages
// (@noble/hashes 2, @scure/base 2, pulled in by patch releases of
// @xrplf/isomorphic and ripple-address-codec), which a CommonJS require() can
// only load on a Node with require(esm): 22.12+, or 20.19+ on the 20 line.
// Older Nodes fail with a bare ERR_REQUIRE_ESM that never mentions the
// version, so name it. Only on failure: a box whose node_modules predate those
// releases still loads fine on an older Node, and must keep doing so.
let fetch, XrplClient, lib;
try {
  fetch = require('node-fetch');
  ({ XrplClient } = require('xrpl-client'));
  lib = require('xrpl-accountlib');
} catch (e) {
  if (e?.code !== 'ERR_REQUIRE_ESM') throw e;
  console.error(`Node ${process.version} cannot require() ES modules, which the installed ` +
                `xrpl-accountlib dependencies need. Use Node 22.12+ (or 20.19+), or run ` +
                `\`node --experimental-require-module ton.js\`.\n  (${e.message.split('\n')[0]})`);
  process.exit(78);   // EXIT_CONFIG: cannot run as configured
}

const cfgPath = path.join(os.homedir(), '.tipbotcfg');

// The parentheses are load-bearing. X evaluates the implicit AND at a higher
// precedence than OR, so '@xrptipbot OR @xahtipbot -is:retweet' would parse as
// '@xrptipbot OR (@xahtipbot AND -is:retweet)' and retweets of @xrptipbot
// posts would keep arriving. This is the first of three retweet defences; see
// isRetweet() for why one is not enough.
const RULE = '(@xrptipbot OR @xahtipbot) -is:retweet';
const HOOK_ACCOUNT = 'rtipboteEEZ6JkTNvcYgUZbiYyrV2W7DQ';
const NETWORK_ID = 21337;                 // Xahau mainnet
const DEFAULT_WSS = 'wss://xahau.network';
const SNID_TWITTER = 1;
const MAX_OPINIONS_PER_INVOKE = 16;       // hook processes params 0..F
const FLUSH_INTERVAL_MS = 8000;
// xrpl-client only arms a per-call timeout when sendOptions.timeoutSeconds is
// given; without it a request whose response never arrives (dead uplink, lost
// reply) leaves the promise pending forever, which latches the flush mutex
const RPC_TIMEOUT_SECONDS = 15;
const SUBMIT_TIMEOUT_SECONDS = 30;
// if a flush somehow outlives this, force the mutex open rather than go quiet
const FLUSH_STUCK_MS = 120000;
// overlapping flushes below this are normal (a big backlog drains in batches)
const FLUSH_SLOW_MS = 30000;
const LLS_WINDOW = 20;                    // LastLedgerSequence = validated + this
const SEEN_CAP = 4096;                    // post-id dedupe FIFO size
// dedupe survives restarts: an in-memory-only set means a redeploy re-tips
// anything the stream redelivers, and X's filtered stream is at-least-once
const SEEN_PATH = path.join(os.homedir(), '.tipbot-seen');
// never accept the bot itself as a tip recipient
const BOT_HANDLES = new Set(['xrptipbot', 'xahtipbot']);
// most commands one multitip post may carry; each is one opinion
const MULTITIP_MAX = MAX_OPINIONS_PER_INVOKE;

// xahaud isMemoOkay() serializes the Memos array and rejects the txn if the
// result exceeds 1024 bytes, so a full batch of 16 memos has to fit inside it.
const MEMO_BYTES_MAX = 1024;
// keeping URLs under 193 bytes keeps the VL length prefix to a single byte,
// which is what memoCost() below assumes
const MEMO_URL_MAX = 192;

// Between the supervisor (whichever version was started by hand) and the
// workers it starts (whatever version is on disk). Keep these stable: a
// running supervisor will start every future version with them.
//   - `node ton.js --worker [args]` runs the oracle; SIGTERM/SIGINT stop it
//     after draining its queue
//   - TON_SUPERVISOR in the worker's environment: the supervisor keeps the
//     checkout updated, so the worker must not. Absent (a3c8366's supervisor,
//     or a worker started by hand), the worker updates itself.
//   - exit codes below
// `--supervisor-contract` printing '1' is what a3c8366's gated updater checks
// before it will take a new version, and is kept only so those oracles can
// move onto this one. It must be the only thing on stdout: no top-level logs.
const SUPERVISOR_CONTRACT = '1';
const SUPERVISOR_VERSION = '2';
const WORKER_FLAG = '--worker';
const EXIT_RESTART = 75;   // worker updated the checkout: start the code on disk now
const EXIT_CONFIG = 78;    // worker cannot run as configured

// ttINVOKE / ttHOOK_SET, from xahaud include/xrpl/protocol/detail/transactions.macro
const TT_INVOKE = 99;
// margin over a fee we worked out ourselves, rather than one the node quoted
const LOCAL_FEE_MARGIN = 130n;   // percent

function log(level, message, data = null) {
  const timestamp = new Date().toISOString();
  let output = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
  if (data !== null) {
    output += ` | ${typeof data === 'object' ? JSON.stringify(data, null, 2) : String(data)}`;
  }
  console.log(output);
}

function shortcutsUrl(data) {
  if (data.shortcuts_url === undefined) return SHORTCUTS_URL;
  if (typeof data.shortcuts_url !== 'string' || !/^https:\/\/\S+$/.test(data.shortcuts_url))
    throw new Error("'shortcuts_url' in ~/.tipbotcfg must be an https URL");
  return data.shortcuts_url;
}

function loadConfig() {
  try {
    if (!fs.existsSync(cfgPath))
      throw new Error(`Config file not found at ${cfgPath}`);
    const data = JSON.parse(fs.readFileSync(cfgPath, 'utf-8'));

    if (!data.bearer_token || typeof data.bearer_token !== 'string')
      throw new Error("please define 'bearer_token' in ~/.tipbotcfg (non-empty string)");
    if (!data.seed || typeof data.seed !== 'string')
      throw new Error("please define 'seed' in ~/.tipbotcfg (family seed of this oracle's member account)");

    log('INFO', 'Configuration loaded successfully');
    return {
      bearerToken: data.bearer_token,
      seed: data.seed,
      wss: data.wss || DEFAULT_WSS,
      update: updateSettings(data),
      // recent search only reaches back 7 days
      backfillMaxHours: Math.min(167, Math.max(0, Number(data.backfill_max_hours ?? 24) || 0)),
      shortcutsUrl: shortcutsUrl(data),
      shortcutsIntervalMs: Math.max(60, Number(data.shortcuts_interval_s) || 300) * 1000
    };
  } catch (error) {
    log('ERROR', 'Failed to load configuration', error.message);
    process.exit(EXIT_CONFIG);
  }
}

/* ------------------------------------------------------------------ */
/* base58 (ripple alphabet) r-address -> 20 byte accid hex            */
/* ------------------------------------------------------------------ */

const B58 = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
const B58_MAP = (() => {
  const m = Object.create(null);
  for (let i = 0; i < B58.length; i++) m[B58[i]] = BigInt(i);
  return m;
})();

function decodeAccountID(addr) {
  let num = 0n;
  for (const ch of addr) {
    const v = B58_MAP[ch];
    if (v === undefined) throw new Error(`invalid base58 character '${ch}' in ${addr}`);
    num = num * 58n + v;
  }
  let leading = 0;
  while (addr[leading] === B58[0]) leading++;

  let hex = num.toString(16);
  if (hex === '0') hex = '';
  if (hex.length % 2) hex = '0' + hex;

  const body = Buffer.concat([Buffer.alloc(leading), Buffer.from(hex, 'hex')]);
  if (body.length !== 25 || body[0] !== 0x00)
    throw new Error(`not an account address: ${addr}`);

  const payload = body.slice(0, 21);
  const checksum = body.slice(21);
  const h = crypto.createHash('sha256')
    .update(crypto.createHash('sha256').update(payload).digest())
    .digest();
  if (!h.slice(0, 4).equals(checksum))
    throw new Error(`bad address checksum: ${addr}`);

  return payload.slice(1).toString('hex').toUpperCase();
}

/* ------------------------------------------------------------------ */
/* tweet parsing                                                       */
/* ------------------------------------------------------------------ */

// A native retweet is not an annotation on the original - it is its own Tweet:
// fresh id, author_id = whoever pressed the button, and text set to
// "RT @original: <original text>". The command survives that prefix verbatim
// and still matches both regexes below, which leaves two failure modes that
// pull in opposite directions:
//
//   1. Treat it as the retweeter's own command. The retweeter is charged for a
//      tip - or, far worse, a *withdrawal to the original author's address* -
//      that they never wrote. Bait a tweet, farm retweets, drain everyone who
//      boosts it.
//   2. "Helpfully" unwrap it to referenced_tweets[].id and the original author.
//      Now every retweet resubmits the original author's tip, arbitrarily long
//      after they posted it, at a third party's discretion.
//
// Both mint an opinion that no one authorised, and neither is recoverable once
// it is on ledger. So: drop the retweet, and never look at what it points to.
// Note that referenced_tweets.id is deliberately NOT in the stream expansions,
// so the original tweet's payload is not even present to be unwrapped.
function isRetweet(tweet) {
  const refs = tweet?.data?.referenced_tweets;
  if (Array.isArray(refs) && refs.some(r => r?.type === 'retweeted'))
    return 'referenced_tweets';

  // Fallback for when referenced_tweets is missing - field not requested, an
  // API change, a truncated payload. X generates this prefix itself, so it is
  // a reliable positive. A user *can* type an old-style manual "RT @x:" by
  // hand and would be dropped here too, which is the direction to err in:
  // relaying someone else's command is exactly what we refuse to charge for.
  if (/^RT\s+@[A-Za-z0-9_]{1,15}:\s/.test(tweet?.data?.text ?? ''))
    return 'rt-prefix';

  return null;
}

// for logging only - we never act on the referenced id
function retweetedId(tweet) {
  const refs = tweet?.data?.referenced_tweets;
  if (!Array.isArray(refs)) return null;
  return refs.find(r => r?.type === 'retweeted')?.id ?? null;
}

// Quote tweets and replies are NOT retweets and must keep flowing: data.text
// on a quote carries only the quoter's own words, and a reply is the normal
// shape of a tip. Only 'retweeted' is dropped.

// Editing a post mints a new tweet id for the same post and the edited version
// is delivered again, so keying dedupe (or post_id) on data.id would tip twice
// for one command. edit_history_tweet_ids is returned by default, oldest first.
function rootTweetId(tweet) {
  const hist = tweet?.data?.edit_history_tweet_ids;
  if (Array.isArray(hist) && hist.length && /^\d{1,20}$/.test(String(hist[0])))
    return String(hist[0]);
  return String(tweet?.data?.id);
}

// A multitip needs one opinion per command, and the hook keys an opinion's
// state on (snid, post_id): a second opinion from the same oracle on the same
// post_id lands on 'V' (already voted) and never counts. So each command gets
// a post_id of its own, derived so that every oracle computes the same one:
// sha256('tipbot-multitip:<post id>:<n>'), top bit set. X ids are snowflakes,
// a 41 bit millisecond count shifted left 22, so they stay below 2^63 until
// about 2080 and a derived id can never collide with a real post. The memo
// still carries the real post's URL, with '#<n>' naming the command.
function subPostId(postId, sub) {
  const h = crypto.createHash('sha256').update(`tipbot-multitip:${postId}:${sub}`).digest();
  return (h.readBigUInt64BE(0) | (1n << 63n)).toString();
}

const ADDR_PATTERN = `r[${B58}]{24,33}`;
// 40 hex is a raw 160-bit currency field. Otherwise a ticker: 3 characters is
// the standard code, 4-20 the non-standard layout (RLUSD and friends).
const TICKER_PATTERN = `[A-Za-z][A-Za-z0-9]{2,19}`;
const CURRENCY_PATTERN = `[A-Fa-f0-9]{40}|${TICKER_PATTERN}`;

// The whole token after '+<amount>': optional cashtag '$', code, optional issuer
const CURRENCY_TOKEN = new RegExp(
  `^\\$?(?<currency>${CURRENCY_PATTERN})(?::(?<issuer>${ADDR_PATTERN}))?$`);

// Sentence punctuation after a token. None of these can occur in a currency
// code or a base58 address, so stripping them cannot change either.
const TRAILING_PUNCT = /[.,!?;)\]]+$/;

const NATIVE = Object.freeze({ currency: 'XAH', issuer: null });

// Currency codes are case-insensitive here: 'rlusd', 'Rlusd' and 'RLUSD' all
// mean RLUSD. On ledger a non-standard code is compared byte for byte, so a
// token actually issued with lower case letters in its code can then only be
// named by its 40 hex; nothing of note on Xahau is.
function normaliseCurrency(raw) {
  return raw.toUpperCase();
}

// The currency slot is the token directly after the number, on the same line,
// and nothing else. A currency must be *next to* the number or it is not
// there at all: in '+5 thanks EVR' the asset is XAH, not EVR.
//
// What sits in the slot is either an attempt at naming a currency or it is
// not. Anything with the shape of a currency code, in any case, is an attempt
// and is held to it: '+1 RLUSD' with no issuer is rejected, never quietly sent
// as XAH, because that is how the wrong asset gets sent. A token is an attempt
// when it is
//   - cashtagged                 $RLUSD, $EVR:r...
//   - issuer-qualified           Xoge:r...
//   - a raw 160 bit code         40 hex
//   - ticker-shaped, any case    EVR, evr, RLUSD, Xah
// Anything else - emoji, @mentions, punctuation, one or two letter words - is
// not a currency and the tip is XAH: '+100 @XahTipBot 💪🏼', '+1 🙏', '+1 ok'.
//
// The price of case-insensitivity is that an ordinary word directly after the
// amount is read as a ticker it cannot resolve, so '+1 thanks' and '+10 lol'
// are rejected where the XRP-only old bot, which ignored the slot, paid them.
const ISSUER_SUFFIX = new RegExp(`:${ADDR_PATTERN}$`);

function isCurrencyAttempt(tok) {
  if (tok.startsWith('@')) return false;
  if (tok.startsWith('$')) return true;
  if (ISSUER_SUFFIX.test(tok)) return true;
  return new RegExp(`^(?:${CURRENCY_PATTERN})$`).test(tok);
}

//   { currency: 'XAH', consumed: false }   empty slot, or prose in it
//   { currency, issuer, consumed: true }    a currency, parsed exactly
//   null                                    looked like a currency, isn't one: REJECT
function parseCurrencySlot(token) {
  if (token === undefined) return { ...NATIVE, consumed: false };
  const tok = token.replace(TRAILING_PUNCT, '');
  if (!isCurrencyAttempt(tok)) return { ...NATIVE, consumed: false };
  const m = tok.match(CURRENCY_TOKEN);
  if (!m) return null;
  return { currency: normaliseCurrency(m.groups.currency), issuer: m.groups.issuer ?? null, consumed: true };
}
// What the author actually typed. On a reply, X hides the auto-inserted
// mentions ("Replying to @a and @b") in the app, but v2 still puts them at the
// front of data.text, and display_text_range[0] is where they end. Parsing the
// raw text is how a tip meant for the post being replied to went to whichever
// other thread participant X happened to list last: '@Hodor @tequ @XahTipBot +1'
// reads as an explicit tip to @tequ, though Satish never typed either name.
//
// The hidden part is only ever mentions and whitespace - ASCII - so the index
// means the same in code points (X) and UTF-16 units (JS) wherever it is valid.
// Anything else there is refused rather than guessed at.
const REPLY_PREFIX = /^(?:@[A-Za-z0-9_]{1,50}\s*)*$/;

function visibleText(tweet) {
  const text  = tweet.data.text;
  const range = tweet.data.display_text_range;

  if (!Array.isArray(range)) {
    // Without the range a reply's hidden mentions look exactly like typed ones
    if (tweet.data.in_reply_to_user_id)
      return { error: 'reply without display_text_range - cannot separate hidden reply mentions (missing tweet.fields?)' };
    return { text };
  }

  const start = range[0];
  if (!Number.isInteger(start) || start < 0 || start > text.length)
    return { error: `bad display_text_range ${JSON.stringify(range)}` };
  if (!REPLY_PREFIX.test(text.slice(0, start)))
    return { error: `display_text_range ${JSON.stringify(range)} hides more than reply mentions` };

  return { text: text.slice(start) };
}

// X HTML-escapes these three in data.text. Unescaped only after the reply
// prefix is cut off: the prefix is mentions and spaces, which contain none of
// them, so display_text_range[0] is unaffected either way.
const unescapeX = s => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

const isBotHandle = h => BOT_HANDLES.has(String(h).toLowerCase());

// Every typed @mention, in order, ignoring email-like 'a@b'
const MENTION_G = /(?<![A-Za-z0-9_])@([A-Za-z0-9_]{1,50})/g;
const BOT_MENTION = /(?<![A-Za-z0-9_])@(?:xrptipbot|xahtipbot)(?![A-Za-z0-9_])/i;

// A '+<amount>', as the old tipbot understood one, minus its accidents:
//   '+5'  '+ 5'  '+0.5'  '+.5'  '+0,5'  '+5!'
// Not preceded by a word character or another '+' ('FOCUS+750', '2+2', 'C++ 1'),
// and not running into a letter, digit or anything else ('+750W', '+5XRP',
// '+10%'). Both the old gates are kept; its acceptance of '+10%' is not.
// ('+5@xrptipbot' was accepted too, but X does not link an @ that follows a
// digit, so such a post never reaches the stream rule.)
const AMOUNT_G = /(?<![A-Za-z0-9_+])\+[^\S\r\n]*(?<amount>\d+(?:[.,]\d+)?|[.,]\d+)(?=[.,!?;)\]]*(?:\s|$))/g;

// The old bot turned every comma into a dot, so '+1,000' tipped 1. A comma is
// a decimal point here only when it cannot be a thousands separator.
function parseAmount(raw) {
  if (/,\d{3}$/.test(raw))
    return { error: `ambiguous amount '${raw}': use a dot for decimals and no thousands separator` };
  const n = parseFloat(raw.replace(',', '.'));
  if (!(n > 0)) return { error: `amount '${raw}' is not positive` };
  return { amount: n };
}

// The mention directly before the command, skipping the bot itself:
// '@alice @XahTipBot +1' and '@alice +1 @XahTipBot' both name alice.
const TRAILING_MENTION = /(?<![A-Za-z0-9_])@([A-Za-z0-9_]{1,50})\s+$/;

function explicitRecipient(before) {
  let m = before.match(TRAILING_MENTION);
  if (!m) return null;
  if (isBotHandle(m[1])) {
    m = before.slice(0, m.index).match(TRAILING_MENTION);
    if (!m || isBotHandle(m[1])) return null;
  }
  return m[1];
}

function parseTipbotTweet(tweet) {
  const id = tweet?.data?.id;        // keep as STRING: snowflakes exceed 2^53
  const INVALID = { type: 'invalid' };

  if (!tweet?.data?.text || !id) return INVALID;

  const vis = visibleText(tweet);
  if (vis.error) return { type: 'invalid', reason: vis.error };
  const text = unescapeX(vis.text);

  // The author has to have mentioned the bot themselves. A reply that only
  // carries it in the hidden prefix is someone talking in a thread the bot is
  // in, which the old bot ignored too (isThreadWithTipBotMentionedButNotByUser).
  if (!BOT_MENTION.test(text)) return INVALID;

  const BOT = `@(?:xrptipbot|xahtipbot)`;
  const AMT = `(?<amount>\\d+(?:\\.\\d+)?)`;
  const CUR = `\\$?(?<currency>${CURRENCY_PATTERN})`;
  const ISS = `(?::(?<issuer>${ADDR_PATTERN}))?`;

  // currency is mandatory here, so a malformed one fails the whole match
  const w = text.match(new RegExp(`${BOT}\\s+withdraw\\s+${AMT}\\s+${CUR}${ISS}\\s+to\\s+(?<dest>${ADDR_PATTERN})(?=\\s|$)`, `im`));
  if (w) return { type: 'withdraw', id, amount: parseFloat(w.groups.amount), currency: normaliseCurrency(w.groups.currency), issuer: w.groups.issuer ?? null, dest: w.groups.dest };

  // Every '+<amount>' in the post, with its currency slot judged. A regex that
  // made the currency an optional group was free to backtrack past it and
  // succeed with "no currency", which is how '+1 $RLUSD:r...' once became a
  // 1 XAH tip; the slot is captured as a raw token and judged here instead.
  const cands = [];
  for (const m of text.matchAll(AMOUNT_G)) {
    const end = m.index + m[0].length;
    const slot = text.slice(end).match(/^[^\S\r\n]+(\S+)/);   // same line only
    const cur = parseCurrencySlot(slot?.[1]);
    const after = text.slice(end + (cur?.consumed ? slot[0].length : 0));
    cands.push({
      index: m.index,
      raw: m.groups.amount,
      token: slot?.[1],
      cur,
      // '@XahTipBot +5', '+5 @XahTipBot', '+5 EVR @XahTipBot', '+5\n@XahTipBot'
      adjacent: /(?<![A-Za-z0-9_])@(?:xrptipbot|xahtipbot)\s+$/i.test(text.slice(0, m.index))
             || /^[.,!?;)\]]*\s*@(?:xrptipbot|xahtipbot)(?![A-Za-z0-9_])/i.test(after)
    });
  }
  if (cands.length === 0) return INVALID;

  // The old bot's multitip ('@a +1 @xrptipbot @b +2 @xrptipbot') paid each
  // one. That cannot be expressed: an opinion is keyed by (snid, post_id) and
  // the hook refuses repeats, so a second command in the same post could never
  // apply. Refuse the post rather than pay one command and drop the rest.
  for (const c of cands) c.explicit = explicitRecipient(text.slice(0, c.index));
  const adjacent = cands.filter(c => c.adjacent);

  // Multitip, as the old bot had it: two or more commands that each name their
  // recipient, '@alice +1 @XahTipBot @bob +2 EVR @XahTipBot'. Each is its own
  // tip. A command in such a post that cannot be paid (bad amount, bad
  // currency, a self-tip) is skipped and the rest still pay, as they did.
  // Commands without a recipient of their own do not count towards it, again
  // as before - the post then falls through to the single-tip rules below.
  const multi = adjacent.filter(c => c.explicit);
  if (multi.length > 1) {
    if (multi.length > MULTITIP_MAX)
      return { type: 'invalid', reason: `${multi.length} tip commands in one post - at most ${MULTITIP_MAX}` };

    const tips = [], skipped = [];
    multi.forEach((c, sub) => {
      const amt = parseAmount(c.raw);
      if (amt.error) return skipped.push(`#${sub + 1}: ${amt.error}`);
      if (!c.cur) return skipped.push(`#${sub + 1}: unrecognised currency '${c.token}'`);
      tips.push({ sub, amount: amt.amount, currency: c.cur.currency, issuer: c.cur.issuer,
                  recipient: c.explicit, recipientVia: 'explicit' });
    });
    return { type: 'multitip', id, tips, skipped };
  }

  // A command next to the bot wins. Failing that, the first amount in the
  // post, which is what the old bot always took ('@xrptipbot great post +1').
  const c = adjacent[0] ?? cands[0];

  const amt = parseAmount(c.raw);
  if (amt.error) return { type: 'invalid', reason: amt.error };
  if (!c.cur) return { type: 'invalid', reason: `unrecognised currency '${c.token}'` };

  // Recipient, from the author's own text only (see visibleText()):
  //
  //   explicit   the mention directly before the command, either order:
  //              '@alice @XahTipBot +1', '@alice +1 @XahTipBot'
  //   reply      otherwise, on a reply to someone else, that someone else -
  //              unless the author typed a different @mention before the
  //              command, which could as easily mean them: rejected
  //   mention    otherwise (not a reply, or a reply to their own post), the
  //              first @mention they typed: 'Thanks @alice! +1 @XahTipBot'
  //
  // The old bot's rules, less its guessing. It could not tell the mentions X
  // inserts on a reply from typed ones, and resolved that by throwing both away
  // ('@bob @alice great +1' to bob, even though alice was typed); v2 can tell,
  // so a typed mention that disagrees with the reply target is refused instead.
  const authorName = (tweet?.includes?.users ?? [])
    .find(u => u.id === tweet?.data?.author_id)?.username?.toLowerCase();
  const typed = [...text.matchAll(MENTION_G)]
    .filter(m => !isBotHandle(m[1]) && m[1].toLowerCase() !== authorName)
    .map(m => ({ name: m[1], index: m.index }));

  const parent = tweet?.data?.in_reply_to_user_id ?? null;
  const replyToOther = !!parent && parent !== tweet?.data?.author_id;

  let recipient = c.explicit;
  let recipientVia = 'explicit';

  if (!recipient && replyToOther) {
    const stray = typed.find(t => t.index < c.index && resolveRecipientId(tweet, t.name) !== parent);
    if (stray)
      return { type: 'invalid', reason: `ambiguous recipient: @${stray.name} is typed before the command but the post replies to someone else` };
    recipientVia = 'reply';
  } else if (!recipient) {
    recipient = typed[0]?.name ?? null;
    recipientVia = 'mention';
    if (!recipient)
      return { type: 'invalid', reason: 'tip names no recipient and is not a reply to someone else' };
  }

  return { type: 'tip', id, amount: amt.amount, currency: c.cur.currency, issuer: c.cur.issuer, recipient, recipientVia };
}

// canonical permalink for the tweet an opinion was derived from.
// the author_id expansion puts the author in includes.users, so we can build
// the pretty /<handle>/status/<id> form; /i/web/status/<id> redirects to the
// same place and is the fallback when the handle is missing or absurdly long
function tweetUrl(tweet, id) {
  const authorId = tweet?.data?.author_id;
  const users = tweet?.includes?.users ?? [];
  const handle = users.find(u => u.id === authorId)?.username;

  if (handle && /^[A-Za-z0-9_]{1,50}$/.test(handle)) {
    const url = `https://x.com/${handle}/status/${id}`;
    if (Buffer.byteLength(url, 'utf8') <= MEMO_URL_MAX) return url;
  }

  return `https://x.com/i/web/status/${id}`;
}

function resolveRecipientId(tweet, username) {
  const users = tweet?.includes?.users ?? [];
  const uname = username.toLowerCase();
  const u = users.find(u => (u.username || '').toLowerCase() === uname);
  return u?.id ?? null; // string
}

/* ------------------------------------------------------------------ */
/* opinion codec (BigInt-safe for all u64 fields)                      */
/* ------------------------------------------------------------------ */

const makeOpinion = (
    social_network_id,   /* 0 - 255 */
    post_id,             /* u64: number (safe int) or BigInt */
    user_id_to,          /* u64 number/BigInt, or 40 hex chars of xahau accid */
    user_id_from,        /* u64: number (safe int) or BigInt */
    currency_code,       /* 0 for xah, or 40 hex chars of currency code */
    issuer_acc_id,       /* 0 for xah, or 40 hex chars of issuer accid */
    amount_tipped        /* positive JS float */
) =>
{
    const toU64 = (v, name) =>
    {
        if (typeof v === 'number')
        {
            if (!Number.isSafeInteger(v) || v < 0)
                throw new Error(name + " must be a safe non-negative integer (use BigInt for values > 2^53)");
            v = BigInt(v);
        }
        if (typeof v !== 'bigint' || v < 0n || v > 0xFFFFFFFFFFFFFFFFn)
            throw new Error(name + " must be a u64 (number or BigInt)");
        return v;
    };

    const checkHex = (hextocheck, hexsize, hexname) =>
    {
        if (typeof(hextocheck) != 'string' ||
            hextocheck.length != hexsize ||
            !/^[0-9a-fA-F]+$/.test(hextocheck))
            throw new Error(hexname + " must be a hex string of exactly " + hexsize + " characters");
    };

    const makeLEHex = (big, field_len_nibbles) =>
    {
        let tmp = big.toString(16);
        if (tmp.length % 2 == 1)
            tmp = '0' + tmp;
        tmp = tmp.toUpperCase();

        let fin = '';
        for (let i = tmp.length - 2; i >= 0; i -= 2)
            fin += tmp.slice(i, i + 2);

        return fin.padEnd(field_len_nibbles, '0');
    };

    const makeLEXFLHex = (num, field_len_nibbles) =>
    {
        const MIN_MANTISSA = 1000000000000000n;
        const MAX_MANTISSA = 9999999999999999n;
        const MIN_EXP = -96;
        const MAX_EXP = 80;

        function makeXfl(exp, man) {
            if (typeof exp !== 'bigint') exp = BigInt(exp);
            if (typeof man !== 'bigint') man = BigInt(man);
            if (man === 0n) return 0n;

            const neg = man < 0n;
            if (neg) man = -man;

            while (man > MAX_MANTISSA) { man /= 10n; exp++; }
            while (man < MIN_MANTISSA) { man *= 10n; exp--; }

            if (exp > MAX_EXP || exp < MIN_EXP) return -1n;

            let xfl = neg ? 0n : 1n;
            xfl = (xfl << 8n) | (BigInt(exp) + 97n);
            xfl = (xfl << 54n) | man;
            return xfl;
        }

        let d = String(parseFloat(String(num))).toLowerCase();
        let e = 0;
        let s = d.split('e');
        if (s.length === 2) { e = parseInt(s[1]); d = s[0]; }
        s = d.split('.');
        if (s.length === 2) { d = d.replace('.', ''); e -= s[1].length; }

        const xfl = makeXfl(e, d);
        if (xfl < 0n) throw new Error(`Cannot encode ${num} as XFL`);

        const be = xfl.toString(16).padStart(16, '0');
        let le = '';
        for (let i = 14; i >= 0; i -= 2) le += be.slice(i, i + 2);

        if (field_len_nibbles % 2 !== 0) throw new Error('field_len_nibbles must be even');
        if (field_len_nibbles < 16) throw new Error('field_len_nibbles must be >= 16 (XFL is 8 bytes)');
        return le.padEnd(field_len_nibbles, '0').toUpperCase();
    };

    if (typeof(social_network_id) != 'number' ||
        social_network_id < 0 || social_network_id > 255 ||
        Math.floor(social_network_id) != social_network_id)
        throw new Error("social_network_id must be an integer between 0 and 255");

    post_id = toU64(post_id, "post_id");

    if (typeof(user_id_to) == 'string')
        checkHex(user_id_to, 40, "user_id_to");
    else
        user_id_to = toU64(user_id_to, "user_id_to");

    user_id_from = toU64(user_id_from, "user_id_from");

    if (typeof(currency_code) == 'string')
        checkHex(currency_code, 40, "currency_code");
    else if (typeof(currency_code) != 'number' || currency_code != 0)
        throw new Error("currency_code must be either 0 or a 20 byte currency code in HEX");

    if (typeof(issuer_acc_id) == 'string')
        checkHex(issuer_acc_id, 40, "issuer_acc_id");
    else if (typeof(issuer_acc_id) != 'number' || issuer_acc_id != 0)
        throw new Error("issuer_acc_id must be either 0 or a 20 byte account id in HEX");

    if (typeof(amount_tipped) != 'number' || !(amount_tipped > 0))
        throw new Error("amount_tipped must be a positive number");

    // execution to here means inputs are well formed

    let out = '';

    out += makeLEHex(BigInt(social_network_id), 2);
    out += makeLEHex(post_id, 16);
    if (typeof(user_id_to) == 'string')
        out += user_id_to.toUpperCase();
    else
    {
        out += '0'.repeat(24);
        out += makeLEHex(user_id_to, 16);
    }

    out += makeLEHex(user_id_from, 16);
    out += (currency_code == 0 ? '0'.repeat(40) : currency_code.toUpperCase());
    out += (issuer_acc_id == 0 ? '0'.repeat(40) : issuer_acc_id.toUpperCase());
    out += makeLEXFLHex(amount_tipped, 16);

    if (out.length !== 170)
        throw new Error(`internal error: opinion is ${out.length} nibbles, expected 170`);

    return out;
};

// XAH -> 0; 40 hex passes through; 3 chars -> standard layout (ascii at bytes
// 12..14); 4-20 chars -> non-standard layout (ascii from byte 0, zero padded),
// which is how RLUSD is issued: 524C555344000000000000000000000000000000
function currencyField(cur) {
  if (cur === 'XAH') return 0;
  if (/^[A-Fa-f0-9]{40}$/.test(cur)) return cur.toUpperCase();
  if (/^[A-Za-z0-9]{3}$/.test(cur)) {
    const buf = Buffer.alloc(20);
    buf.write(cur.toUpperCase(), 12, 'ascii');
    return buf.toString('hex').toUpperCase();
  }
  if (/^[A-Za-z][A-Za-z0-9]{3,19}$/.test(cur)) {
    const buf = Buffer.alloc(20);
    buf.write(cur, 0, 'ascii');
    return buf.toString('hex').toUpperCase();
  }
  throw new Error(`unsupported currency: ${cur}`);
}

/* ------------------------------------------------------------------ */
/* well-known token shortcuts                                          */
/* ------------------------------------------------------------------ */

// Tokens that may be named by ticker alone, so '+5 EVR' works without the
// author pasting ':rEvernodee8dJLaFsujS6q1EiXvZYmHXr8' after it.
//
// This is a *default*, never an override. A ticker is not unique on ledger -
// anyone can issue 'EVR' - so 'EVR:rSomeoneElse' must keep resolving to
// whatever the author actually wrote. See opinionFromParsed().
//
// The list lives in RichardAH/TipBot-Shortcuts rather than here, so adding a
// token is a push to that repo, not a release of this one. It is fetched at
// start and every shortcuts_interval_s, and the last good copy is kept in
// ~/.tipbot-shortcuts.json for a start that cannot reach GitHub. Check an
// edit before pushing it with `node ton.js --check-shortcuts shortcuts.json`.
//
//   {
//     "version": 1,
//     "shortcuts": [
//       { "ticker": "EVR", "issuer": "rEvernodee8dJLaFsujS6q1EiXvZYmHXr8", "name": "Evernode" },
//       { "ticker": "ABC", "issuer": "r...", "from": "2026-11-01T00:00:00Z" },
//       { "ticker": "XYZ", "issuer": null,   "from": "2026-11-01T00:00:00Z" }
//     ]
//   }
//
//   ticker   3-20 characters or 40 hex, matched case-insensitively like every
//            currency code here (see normaliseCurrency())
//   issuer   r-address, or null to retire the ticker from 'from' on
//   from     optional, YYYY-MM-DDTHH:MM:SSZ: the entry applies to posts made
//            at or after this time. Absent means always.
//   name     optional, for people reading the file
//
// Why 'from': every oracle polls on its own jittered timer, through a CDN that
// caches for minutes, so for a while after a push some oracles have the new
// list and some do not. An entry that takes effect at once is judged
// differently across oracles for posts made in that window - one encodes the
// shortcut while another rejects the post, or two encode different issuers -
// and the votes split. An entry whose 'from' is safely past that window (an
// hour is plenty) is judged against the post's own time, which every oracle
// reads identically off the post id (snowflakeMs()), so they all agree.
// Several entries for one ticker with different 'from' form a history: the
// latest one not after the post wins. That is also what makes a backfilled or
// --replay'd post resolve the way it would have when it was live.
//
// A list is taken whole or not at all: one bad entry - a mistyped address, a
// failed checksum, a ticker the parser could never match - rejects the lot
// and the previous list stays in force. A half-applied list is just another
// way for oracles to disagree.
const SHORTCUTS_URL = 'https://raw.githubusercontent.com/RichardAH/TipBot-Shortcuts/main/shortcuts.json';
const SHORTCUTS_CACHE = path.join(os.homedir(), '.tipbot-shortcuts.json');
const SHORTCUTS_VERSION = 1;
const SHORTCUTS_MAX = 4096;               // entries
const SHORTCUTS_BYTES_MAX = 1 << 20;
const SHORTCUTS_FETCH_TIMEOUT_MS = 15000;
// until any list has loaded, every ticker-only tip is rejected: retry quickly
const SHORTCUTS_RETRY_MS = 30000;
const FROM_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

// currency field (as currencyField() returns it) -> [{ from, issuer, ticker }]
// sorted oldest first, from = -Infinity for an entry without one. null until a
// list has loaded. Replaced whole, never edited in place.
let shortcuts = null;
let shortcutsText = null;   // the document `shortcuts` was built from
let shortcutsEtag = null;

// Validate a shortcuts.json document and build its table. Throws on anything
// wrong; installs nothing.
function buildShortcuts(text) {
  const doc = JSON.parse(text);
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc))
    throw new Error('not a JSON object');
  if (doc.version !== SHORTCUTS_VERSION)
    throw new Error(`version ${JSON.stringify(doc.version)} - this ton.js reads version ${SHORTCUTS_VERSION}`);
  if (!Array.isArray(doc.shortcuts))
    throw new Error("'shortcuts' is not an array");
  if (doc.shortcuts.length > SHORTCUTS_MAX)
    throw new Error(`${doc.shortcuts.length} entries, at most ${SHORTCUTS_MAX}`);

  // only codes the tweet parser can produce: anything else could never match
  const typeable = new RegExp(`^(?:${CURRENCY_PATTERN})$`);
  const table = new Map();

  doc.shortcuts.forEach((e, i) => {
    const at = `shortcuts[${i}]`;
    if (e === null || typeof e !== 'object' || Array.isArray(e))
      throw new Error(`${at} is not an object`);

    if (typeof e.ticker !== 'string' || !typeable.test(e.ticker))
      throw new Error(`${at}: ticker ${JSON.stringify(e.ticker)} is not a currency code a post can name`);
    const ticker = normaliseCurrency(e.ticker);
    if (ticker === 'XAH')
      throw new Error(`${at}: XAH is native and cannot have an issuer`);
    const cur = currencyField(ticker);
    if (cur === 0 || /^0{40}$/.test(cur))
      throw new Error(`${at}: ${ticker} is the native currency field`);

    if (e.issuer !== null) {
      if (typeof e.issuer !== 'string')
        throw new Error(`${at}: issuer must be an r-address, or null to retire ${ticker}`);
      try { decodeAccountID(e.issuer); }
      catch (err) { throw new Error(`${at}: ${err.message}`); }
    }

    let from = -Infinity;
    if (e.from !== undefined) {
      const ms = typeof e.from === 'string' && FROM_UTC.test(e.from) ? Date.parse(e.from) : NaN;
      // Date.parse rolls 2026-02-30 over to March: only a time that reads
      // back as written is accepted
      if (!Number.isFinite(ms) || new Date(ms).toISOString() !== e.from.replace('Z', '.000Z'))
        throw new Error(`${at}: from ${JSON.stringify(e.from)} is not a UTC time like 2026-11-01T00:00:00Z`);
      from = ms;
    }

    const hist = table.get(cur) ?? [];
    if (hist.some(h => h.from === from))
      throw new Error(`${at}: a second ${ticker} entry ${from === -Infinity ? 'without a from' : `from ${e.from}`}`);
    hist.push({ from, issuer: e.issuer, ticker });
    table.set(cur, hist);
  });

  // at most one -Infinity per ticker (checked above), so no NaN comparisons
  for (const hist of table.values()) hist.sort((a, b) => a.from - b.from);
  return table;
}

const describeShortcut = h =>
  `${h.ticker}${h.from === -Infinity ? '' : `@${new Date(h.from).toISOString()}`}=${h.issuer ?? 'retired'}`;

// Validate and swap in a whole new table. Throws, leaving the current one in
// force, if the document is bad. Returns whether anything changed.
function installShortcuts(text, source) {
  const next = buildShortcuts(text);
  if (text === shortcutsText) return false;

  const was = new Set([...(shortcuts?.values() ?? [])].flat().map(describeShortcut));
  const now = new Set([...next.values()].flat().map(describeShortcut));
  shortcuts = next;
  shortcutsText = text;

  // operators compare this hash across oracles to confirm they agree
  const hash = crypto.createHash('sha256').update(text).digest('hex').slice(0, 16);
  log('INFO', `Shortcut list loaded from ${source}: ${now.size} entr${now.size === 1 ? 'y' : 'ies'}, sha256 ${hash}`, {
    added: [...now].filter(d => !was.has(d)),
    removed: [...was].filter(d => !now.has(d))
  });
  return true;
}

function persistShortcuts(text) {
  // pid in the name: a --replay alongside the live oracle writes here too
  const tmp = `${SHORTCUTS_CACHE}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, text);
    fs.renameSync(tmp, SHORTCUTS_CACHE);
  } catch (e) {
    log('WARN', 'Could not cache the shortcut list', e.message);
    try { fs.rmSync(tmp, { force: true }); } catch (e2) { /* best effort */ }
  }
}

function loadShortcutsCache() {
  let text;
  try {
    text = fs.readFileSync(SHORTCUTS_CACHE, 'utf8');
  } catch (e) {
    if (e.code !== 'ENOENT') log('WARN', `Could not read ${SHORTCUTS_CACHE}`, e.message);
    return;
  }
  try {
    installShortcuts(text, SHORTCUTS_CACHE);
  } catch (e) {
    log('WARN', `Cached shortcut list ${SHORTCUTS_CACHE} unusable - ignored`, e.message);
  }
}

async function fetchShortcuts() {
  const headers = {};
  if (shortcuts && shortcutsEtag) headers['If-None-Match'] = shortcutsEtag;

  // node-fetch@2: `timeout` covers the whole exchange, `size` caps the body
  const response = await fetch(CONFIG.shortcutsUrl, {
    headers, timeout: SHORTCUTS_FETCH_TIMEOUT_MS, size: SHORTCUTS_BYTES_MAX
  });
  if (response.status === 304) return;
  if (!response.ok)
    throw new Error(`HTTP ${response.status} from ${CONFIG.shortcutsUrl}`);

  const text = await response.text();
  if (installShortcuts(text, CONFIG.shortcutsUrl)) persistShortcuts(text);
  // only once the document is known good: a bad one is fetched (and
  // reported) again next time rather than hidden behind a 304
  shortcutsEtag = response.headers.get('etag');
}

// Never throws: whatever goes wrong, the list in force stays in force
async function refreshShortcuts() {
  try {
    await fetchShortcuts();
  } catch (e) {
    if (shortcuts)
      log('WARN', 'Shortcut list not refreshed - keeping the current one', e.message);
    else
      log('ERROR', 'No shortcut list loaded - ticker-only tokens (+5 EVR) are rejected until one is', e.message);
  }
}

function startShortcutRefresher() {
  const tick = () => setTimeout(async () => {
    if (stopping) return;
    await refreshShortcuts();
    tick();
  }, shortcuts ? CONFIG.shortcutsIntervalMs * (0.8 + Math.random() * 0.4) : SHORTCUTS_RETRY_MS);
  tick();
  log('INFO', `Shortcut list: following ${CONFIG.shortcutsUrl}, every ~${CONFIG.shortcutsIntervalMs / 1000}s`);
}

// X post ids are snowflakes: milliseconds since X's epoch, shifted left 22.
// Every oracle reads the same time off the same id, which is what lets a
// shortcut's 'from' be judged identically everywhere. Always the root of the
// edit chain (rootTweetId()), never a multitip's derived id.
const X_EPOCH_MS = 1288834974657n;

function snowflakeMs(id) {
  if (!/^\d{1,20}$/.test(String(id))) return null;
  return Number((BigInt(id) >> 22n) + X_EPOCH_MS);
}

// Issuer a ticker-only mention resolves to on a post made at postMs, or null
function shortcutIssuer(cur, postMs) {
  const t = postMs ?? -Infinity;   // unknown time: only entries without a from
  let issuer = null;
  for (const h of shortcuts?.get(cur) ?? []) {
    if (h.from > t) break;
    issuer = h.issuer;
  }
  return issuer;
}

// parsed tweet + author id + post time -> 170-nibble opinion hex
function opinionFromParsed(parsed, authorId, postMs) {
  const cur = currencyField(parsed.currency);

  // Fill in the issuer only where the author left one out. Written back onto
  // `parsed` so the queue log records the issuer that was actually encoded
  // rather than the blank that was typed - the two must never disagree.
  if (cur !== 0 && !parsed.issuer)
    parsed.issuer = shortcutIssuer(cur, postMs);

  const iss = parsed.issuer ? decodeAccountID(parsed.issuer) : 0;

  if (cur !== 0 && iss === 0)
    throw new Error(`issued currency requires an issuer (${parsed.currency}:issuer)` +
                    (shortcuts ? '' : ' - no shortcut list loaded'));
  if (cur === 0 && iss !== 0)
    throw new Error('XAH cannot have an issuer');

  let to;
  if (parsed.type === 'withdraw')
    to = decodeAccountID(parsed.dest);
  else
    to = BigInt(parsed.recipientId);

  return makeOpinion(
    SNID_TWITTER,
    BigInt(parsed.id),
    to,
    BigInt(authorId),
    cur,
    iss,
    parsed.amount
  );
}

/* ------------------------------------------------------------------ */
/* xahau submission                                                    */
/* ------------------------------------------------------------------ */

// Strict lower bound on what xahaud will charge for this Invoke, derived from
// Transactor::calculateBaseFee(): the network base fee, plus one drop per byte
// of every HookParameter name and value, plus one drop per byte of every memo
// field - before any hook execution fee, which only ever adds. Anything the
// node quotes at or below this was computed for some other transaction.
function minimumInvokeFee(tx, networkBase) {
  const hexBytes = s => (typeof s === 'string' ? BigInt(s.length >> 1) : 0n);

  let n = networkBase;
  for (const p of tx.HookParameters ?? [])
    n += hexBytes(p?.HookParameter?.HookParameterName)
       + hexBytes(p?.HookParameter?.HookParameterValue);
  for (const m of tx.Memos ?? [])
    for (const v of Object.values(m?.Memo ?? {}))
      n += hexBytes(v);

  return n;
}

// hook::canHook() flips the ttHOOK_SET bit, inverts the whole field, then tests
// the bit for the transaction type. For anything that is not HookSet that
// reduces to: the hook fires when its bit is clear. UINT256_BIT[n] is 2^n, so
// the bit index maps straight onto a BigInt shift.
function hookFiresOnInvoke(hookOnHex) {
  if (typeof hookOnHex !== 'string' || !/^[0-9a-fA-F]{1,64}$/.test(hookOnHex))
    return true;   // unreadable: assume it fires. Overpaying beats telINSUF_FEE_P
  return ((BigInt('0x' + hookOnHex) >> BigInt(TT_INVOKE)) & 1n) === 0n;
}

class XahauSubmitter {
  constructor(wss, seed) {
    this.wss = wss;
    this.account = lib.derive.familySeed(seed);
    this.client = new XrplClient(wss);
    this.definitions = null;
    this.sequence = null;
    // consecutive telINSUF_FEE_P results. checkFee() compares what we paid
    // against the *load-scaled* base fee while `fee` quotes the unscaled one,
    // so a load spike can reject a perfectly correct quote. Escalate headroom
    // rather than sit in a retry loop paying the same rejected fee.
    this.feeBump = 0;
    // set by probeFeePricing() at startup
    this.nodePricesFees = true;
    this.networkBase = 10n;
    this.hookChainFee = 0n;
    this.tracking = new Set();
  }

  // every request must carry a deadline. xrpl-client's applyCallTimeout() is a
  // no-op unless timeoutSeconds is set, and pending calls are only rejected on
  // destroy() - never on a plain close or reconnect - so an un-timed send() can
  // stay pending indefinitely and stall whatever is awaiting it
  async req(payload, timeoutSeconds = RPC_TIMEOUT_SECONDS) {
    const r = await this.client.send(payload, { timeoutSeconds });
    if (r?.error)
      throw new Error(`${payload.command}: ${r.error_message || r.error}`);
    return r;
  }

  async init() {
    await this.client.ready();
    log('INFO', `Connected to ${this.wss} as ${this.account.address}`);

    this.client.on('offline', () => log('WARN', 'Uplink offline'));
    this.client.on('retry', () => log('WARN', 'Uplink reconnect attempt'));
    this.client.on('nodeswitch', ep => log('WARN', 'Uplink switched', ep));
    this.client.on('error', e => log('WARN', 'Uplink error', e?.message ?? e));
    this.client.on('online', () => {
      // the account may have moved on while we were disconnected
      this.sequence = null;
      log('INFO', 'Uplink online - sequence marked for resync');
    });

    // pull live definitions from the node so Invoke/HookParameters
    // always serialize against what the network actually runs
    const defs = await this.req({ command: 'server_definitions' });
    this.definitions = new lib.XrplDefinitions(defs);

    await this.syncSequence();
    await this.probeFeePricing();
  }

  async syncSequence() {
    const ai = await this.req({
      command: 'account_info',
      account: this.account.address,
      ledger_index: 'current'
    });
    this.sequence = ai.account_data.Sequence;
    log('INFO', `Account sequence synced: ${this.sequence}`);
  }

  async currentValidatedLedger() {
    const r = await this.req({ command: 'ledger', ledger_index: 'validated' });
    const idx = r?.ledger_index ?? r?.ledger?.ledger_index;
    if (!Number.isInteger(idx))
      throw new Error('retryable: no validated ledger index in response');
    return idx;
  }

  // Margin over whatever number we are working from, escalating while the
  // network keeps rejecting us. checkFee() compares what we paid against the
  // *load-scaled* base fee while `fee` quotes the unscaled one, so a load spike
  // can reject a perfectly correct quote. Percent - callers divide by 100n.
  margin(basePercent) {
    return BigInt(basePercent) + 60n * BigInt(Math.min(this.feeBump, 8));
  }

  // Sign at Fee:'0' so the node can price this exact transaction. Returns the
  // blob as well, since probeFeePricing() wants to reuse it.
  feeProbe(tx) {
    const { signedTransaction } = lib.sign({ ...tx, Fee: '0' }, this.account, this.definitions);
    if (typeof signedTransaction !== 'string' || signedTransaction.length === 0)
      throw new Error('retryable: fee probe produced no tx_blob');
    return signedTransaction;
  }

  // Ask the node what this transaction costs, and refuse the answer unless it
  // demonstrably priced *our* blob. `fee` answers a request it could not parse
  // a tx_blob out of with the generic network base fee rather than an error,
  // and JSON.stringify drops an undefined tx_blob on the way out, so a broken
  // probe is indistinguishable from a very cheap Invoke. That is how a 12 drop
  // fee gets submitted for a transaction that costs hundreds.
  async quoteFee(tx) {
    const feeResp = await this.req({ command: 'fee', tx_blob: this.feeProbe(tx) });

    const quoted = BigInt(feeResp?.drops?.base_fee ?? 0);
    if (quoted <= 0n)
      throw new Error('retryable: no base_fee in fee response');

    // doFee() sets fee_hooks_feeunits if and only if it parsed a tx_blob and
    // priced it, so its absence is proof the quote has nothing to do with us.
    if (feeResp?.fee_hooks_feeunits === undefined)
      throw new Error(`unpriced: quote of ${quoted} drops carries no fee_hooks_feeunits`);

    // Belt and braces for a node that reports the field but prices something
    // else: base_fee_no_hooks is the plain network base fee, which is what
    // base_fee degrades to, and this Invoke provably costs more than that.
    const noHooks = feeResp?.drops?.base_fee_no_hooks;
    if (noHooks !== undefined) {
      const floor = minimumInvokeFee(tx, BigInt(noHooks));
      if (quoted < floor)
        throw new Error(`unpriced: quote of ${quoted} drops is below the ${floor} ` +
                        `this transaction costs in bytes alone (base ${noHooks})`);
    }

    return (quoted * this.margin(120)) / 100n;
  }

  // What xahaud will charge, worked out here instead. Mirrors
  // Transactor::calculateBaseFee(): network base, one drop per HookParameter
  // name and value byte, one drop per memo field byte, plus the execution fee
  // of every hook that will run. The byte terms we count exactly; the hook fee
  // is read off the ledger by syncHookFees() because it is the one term a byte
  // count cannot see, and on a hook like tip.c it is much the largest.
  localFee(tx) {
    const total = minimumInvokeFee(tx, this.networkBase) + this.hookChainFee;
    return (total * this.margin(LOCAL_FEE_MARGIN)) / 100n;
  }

  async estimateFee(tx) {
    if (this.nodePricesFees) {
      try {
        return (await this.quoteFee(tx)).toString();
      } catch (e) {
        if (!e.message.startsWith('unpriced:')) throw e;
        // it priced blobs at startup and has stopped: switch over and say so
        log('WARN', `Node stopped pricing transactions (${e.message}) - using local fees`);
        this.nodePricesFees = false;
        await this.syncHookFees().catch(err =>
          log('WARN', 'Hook fee read failed', err.message));
      }
    }
    return this.localFee(tx).toString();
  }

  // Sum of HookDefinition.Fee for every hook that will run for our Invoke: our
  // own chain on the way out, and the tip hook's on the way in. Read once at
  // startup and re-read when the network rejects a local estimate, since the
  // only thing that changes it is somebody redeploying a hook.
  async syncHookFees() {
    const chainFee = async (address, direction) => {
      let hookSLE;
      try {
        hookSLE = await this.req({
          command: 'ledger_entry',
          hook: { account: address },
          ledger_index: 'validated'
        });
      } catch (e) {
        return 0n;   // no Hook object on this account, or no hook support
      }

      let total = 0n;
      for (const entry of hookSLE?.node?.Hooks ?? []) {
        const h = entry?.Hook;
        if (!h?.HookHash) continue;

        const def = (await this.req({
          command: 'ledger_entry',
          hook_definition: h.HookHash,
          ledger_index: 'validated'
        }))?.node;
        if (!def) continue;

        // hook::getHookOn() precedence: the installed hook overrides the
        // definition, and the directional field overrides the general one
        const hookOn = h[direction] ?? h.HookOn ?? def[direction] ?? def.HookOn;
        if (!hookFiresOnInvoke(hookOn)) continue;

        total += BigInt(def.Fee ?? 0);
      }
      return total;
    };

    this.hookChainFee =
        await chainFee(this.account.address, 'HookOnOutgoing')
      + await chainFee(HOOK_ACCOUNT, 'HookOnIncoming');

    return this.hookChainFee;
  }

  // A transaction the same shape as the ones we submit, for pricing probes
  sampleInvoke() {
    return {
      TransactionType: 'Invoke',
      Account: this.account.address,
      Destination: HOOK_ACCOUNT,
      NetworkID: NETWORK_ID,
      Sequence: this.sequence,
      LastLedgerSequence: this.sequence + LLS_WINDOW,
      Fee: '0',
      HookParameters: [{
        HookParameter: { HookParameterName: '00', HookParameterValue: '00'.repeat(85) }
      }],
      Memos: [{
        Memo: { MemoData: Buffer.from(`https://x.com/i/web/status/${'0'.repeat(19)}`, 'utf8')
                                .toString('hex').toUpperCase() }
      }]
    };
  }

  // Find out at boot, not when the first tip is on the line, whether this
  // endpoint prices hook transactions - a node that does not returns the
  // generic base fee with no error at all.
  async probeFeePricing() {
    const feeResp = await this.req({ command: 'fee' });
    this.networkBase = BigInt(
      feeResp?.drops?.base_fee_no_hooks ?? feeResp?.drops?.base_fee ?? 10);

    try {
      const quote = await this.quoteFee(this.sampleInvoke());
      this.nodePricesFees = true;
      log('SUCCESS', `Fee pricing available: ${quote} drops for a 1-opinion Invoke`);
      return;
    } catch (e) {
      if (!e.message.startsWith('unpriced:')) throw e;
      log('WARN', `${this.wss} does not price hook transactions - ${e.message}`);
    }

    this.nodePricesFees = false;
    await this.syncHookFees();

    if (this.hookChainFee === 0n)
      log('ERROR', 'No hook execution fee could be read from the ledger either - ' +
                   'local estimates cover transaction bytes only and are likely ' +
                   'to be rejected. Check the endpoint.');

    log('WARN', `Falling back to local fees: base ${this.networkBase} + ` +
                `${this.hookChainFee} drops hook execution + txn bytes, ` +
                `+${LOCAL_FEE_MARGIN - 100n}% margin ` +
                `(${this.localFee(this.sampleInvoke())} drops for a 1-opinion Invoke)`);
  }

  async submitOpinions(opinions /* array of { hex, url }, <=16 */) {
    if (opinions.length === 0) return;
    if (opinions.length > MAX_OPINIONS_PER_INVOKE)
      throw new Error('too many opinions for one Invoke');

    if (this.sequence === null) await this.syncSequence();

    const validated = await this.currentValidatedLedger();
    const lls = validated + LLS_WINDOW;

    // one memo per opinion, same order as HookParameters, so Memos[i] is the
    // source tweet for parameter 0x0i. no MemoType/MemoFormat: they'd cost
    // ~14 bytes each per memo and eat into the 1024 byte ceiling for no gain
    const memos = opinions.map(o => ({
      Memo: { MemoData: Buffer.from(o.url, 'utf8').toString('hex').toUpperCase() }
    }));
    const memoBytes = opinions.reduce((n, o) => n + memoCost(o.url), 0);

    const tx = {
      TransactionType: 'Invoke',
      Account: this.account.address,
      Destination: HOOK_ACCOUNT,
      NetworkID: NETWORK_ID,
      Sequence: this.sequence,
      LastLedgerSequence: lls,
      Fee: '0',
      HookParameters: opinions.map((o, i) => ({
        HookParameter: {
          HookParameterName: i.toString(16).toUpperCase().padStart(2, '0'),
          HookParameterValue: o.hex
        }
      }))
    };

    // peekBatch() sizes batches to stay under the ceiling; this only trips if a
    // single memo is oversized, in which case drop the annotation rather than
    // let the whole batch be rejected as malformed
    if (memoBytes <= MEMO_BYTES_MAX)
      tx.Memos = memos;
    else
      log('WARN', `Memos omitted: ${memoBytes} bytes exceeds ${MEMO_BYTES_MAX}`);

    tx.Fee = await this.estimateFee(tx);

    const { signedTransaction, id } = lib.sign(tx, this.account, this.definitions);

    log('INFO', `Submitting Invoke seq=${tx.Sequence} fee=${tx.Fee} opinions=${opinions.length} memos=${tx.Memos ? `${memos.length}/${memoBytes}B` : 'none'} hash=${id}`);

    const res = await this.client.send(
      { command: 'submit', tx_blob: signedTransaction },
      { timeoutSeconds: SUBMIT_TIMEOUT_SECONDS }
    );
    const er = res?.engine_result ?? res?.error ?? 'unknown';

    if (er === 'tesSUCCESS' || er === 'terQUEUED') {
      this.sequence++;
      this.feeBump = 0;
      log('SUCCESS', `Submitted (${er})`, { hash: id });
      // fire and forget: report hook results once validated. Held in
      // this.tracking only so --replay can wait for them before exiting
      const p = this.reportHookResults(id, lls).catch(e =>
        log('WARN', 'Result tracking failed', e.message));
      this.tracking.add(p);
      p.finally(() => this.tracking.delete(p));
      return;
    }

    // sequence drift: resync and let caller retry
    if (er === 'tefPAST_SEQ' || er === 'terPRE_SEQ' || er === 'tefALREADY') {
      log('WARN', `Sequence issue (${er}), resyncing`);
      await this.syncSequence();
      throw new Error(`retryable: ${er}`);
    }

    // tel* is a purely *local* verdict and ter* means "try again later":
    // neither applied, neither consumed the sequence, and the identical blob
    // submits fine once the condition clears. Dropping one destroys the tip for
    // good - markSeen() recorded the post id at enqueue, so not even a restart
    // brings it back, and no other oracle is obliged to have seen it either.
    if (typeof er === 'string' && (er.startsWith('tel') || er.startsWith('ter'))) {
      if (er === 'telINSUF_FEE_P') {
        this.feeBump++;
        // a redeployed hook is the usual reason a local estimate goes stale
        if (!this.nodePricesFees)
          await this.syncHookFees().catch(e =>
            log('WARN', 'Hook fee resync failed', e.message));
        log('WARN', `Fee of ${tx.Fee} drops rejected - raising margin and requeueing`);
      }
      throw new Error(`retryable: ${er}`);
    }

    // tec results consume the sequence and a fee
    if (typeof er === 'string' && er.startsWith('tec')) {
      this.sequence++;
      throw new Error(`claimed fee, not applied: ${er}`);
    }

    throw new Error(`submit failed: ${er} ${res?.engine_result_message ?? ''}`);
  }

  // poll until validated (or LLS passes), then decode HookReturnString
  async reportHookResults(hash, lls) {
    // hard stop so a failed lookup can't spin forever queueing requests
    const deadline = Date.now() + 180000;

    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 3000));

      const r = await this.client.send(
        { command: 'tx', transaction: hash },
        { timeoutSeconds: RPC_TIMEOUT_SECONDS }
      );

      if (r?.validated) {
        const result = r.meta?.TransactionResult;
        const execs = r.meta?.HookExecutions ?? [];
        for (const e of execs) {
          const he = e.HookExecution;
          if (!he) continue;
          const msg = he.HookReturnString
            ? Buffer.from(he.HookReturnString, 'hex').toString('utf8')
            : '(no return string)';
          log('HOOK', `${result} rc=${he.HookReturnCode}`, msg);
        }
        if (execs.length === 0)
          log('HOOK', `Validated ${result}, no hook executions`);
        return;
      }

      const validated = await this.currentValidatedLedger();
      if (validated > lls) {
        log('WARN', `Txn ${hash} not found after LastLedgerSequence ${lls} - dropped`);
        return;
      }
    }

    log('WARN', `Gave up tracking ${hash}`);
  }
}

/* ------------------------------------------------------------------ */
/* opinion queue                                                       */
/* ------------------------------------------------------------------ */

const opinionQueue = [];
let flushing = false;
let flushStartedAt = 0;
let flushGen = 0;
let submitter = null;

function enqueueOpinion(hex, url, context) {
  opinionQueue.push({ hex, url });
  log('QUEUE', `Opinion queued (${opinionQueue.length} pending)`, context);
  if (opinionQueue.length >= MAX_OPINIONS_PER_INVOKE)
    flushOpinions().catch(e => log('ERROR', 'Flush failed', e.message));
}

// serialized cost of one Memos element carrying only MemoData:
//   sfMemo field id (1) + sfMemoData field id (1) + VL prefix (1)
//   + data + end-of-object marker (1)
// STArray::add() writes exactly this per element and nothing else, so the sum
// is what isMemoOkay() measures against MEMO_BYTES_MAX
const memoCost = url => 4 + Buffer.byteLength(url, 'utf8');

// take as many opinions as will fit under both the parameter count cap and the
// memo size cap. this only *looks* at the head of the queue: entries stay
// queued until the submit is confirmed, so a failed or stalled flush can never
// lose them. safe because enqueueOpinion only ever pushes to the tail, and
// flushOpinions is the sole consumer of the head
function peekBatch() {
  let bytes = 0;
  let n = 0;

  while (n < opinionQueue.length && n < MAX_OPINIONS_PER_INVOKE) {
    const cost = memoCost(opinionQueue[n].url);
    if (n > 0 && bytes + cost > MEMO_BYTES_MAX) break;
    bytes += cost;
    n++;
  }

  return opinionQueue.slice(0, n);
}

// transport-level failures mean "we don't know if this landed, try again";
// anything else is a verdict from the network and shouldn't be retried blindly
function isRetryable(message) {
  return /^retryable/i.test(message)
    || /timeout|not ready|socket|econn|network|clos|offline|destroyed/i.test(message);
}

async function flushOpinions() {
  if (!submitter || opinionQueue.length === 0) return;

  // the original silent failure: a flush that never finished left this flag set
  // and every later tick returned here without logging anything at all.
  // overlapping a healthy multi-batch drain is normal, so only speak up once a
  // flush has been running longer than any legitimate one should
  if (flushing) {
    const stuckFor = Date.now() - flushStartedAt;
    if (stuckFor > FLUSH_SLOW_MS)
      log('WARN', `Flush still in progress after ${(stuckFor / 1000).toFixed(1)}s ` +
                  `(${opinionQueue.length} pending)`);
    if (stuckFor > FLUSH_STUCK_MS) {
      // abandon it: bump the generation so the stalled run can't commit or
      // clear the mutex out from under its replacement
      flushGen++;
      flushing = false;
      log('ERROR', `Flush abandoned after ${(stuckFor / 1000).toFixed(1)}s - forcing retry`);
    }
    return;
  }

  flushing = true;
  flushStartedAt = Date.now();
  const myGen = flushGen;

  try {
    while (opinionQueue.length > 0) {
      const batch = peekBatch();
      try {
        await submitter.submitOpinions(batch);
        if (myGen !== flushGen) return;        // superseded, don't touch the queue
        opinionQueue.splice(0, batch.length);  // only now are they safely gone
      } catch (e) {
        if (myGen !== flushGen) return;
        const msg = String(e.message);
        if (isRetryable(msg)) {
          log('WARN', `Batch of ${batch.length} left queued for retry`, msg);
        } else {
          opinionQueue.splice(0, batch.length);
          log('ERROR', `Batch of ${batch.length} opinions dropped`, msg);
        }
        break;
      }
    }
  } finally {
    if (myGen === flushGen) flushing = false;
  }
}

/* ------------------------------------------------------------------ */
/* twitter stream                                                      */
/* ------------------------------------------------------------------ */

// loaded in main(), so the parser can be required by tests without a config
let CONFIG = null;
// --dry-run: judge and encode, but never mark seen or submit
let DRY_RUN = false;

// Checking and inserting are separate on purpose. The old alreadySeen() did
// both on every tweet that matched the rule, so the ~99% that carry no command
// churned the cap and evicted real tip ids within minutes of traffic. Only a
// post that actually became an opinion consumes a slot now.
const seenIds = new Set();

function loadSeen() {
  try {
    if (!fs.existsSync(SEEN_PATH)) return;
    const ids = fs.readFileSync(SEEN_PATH, 'utf8')
      .split('\n').map(s => s.trim()).filter(s => /^\d{1,20}$/.test(s));
    for (const id of ids.slice(-SEEN_CAP)) seenIds.add(id);
    log('INFO', `Loaded ${seenIds.size} previously-processed post id(s)`);
    if (ids.length > SEEN_CAP * 2) {
      fs.writeFileSync(SEEN_PATH, [...seenIds].join('\n') + '\n');
      log('INFO', 'Compacted seen-id file');
    }
  } catch (e) {
    log('WARN', 'Could not load seen-id file (starting empty)', e.message);
  }
}

function hasSeen(id) {
  return seenIds.has(id);
}

// Marked at enqueue, not at submit: a crash between the two loses a tip, which
// is the right way to fail. This set is an optimisation, not the guarantee -
// with several oracles each keeping their own view, the only authoritative
// duplicate rejection is the hook refusing a repeated (snid, post_id).
function markSeen(id) {
  seenIds.add(id);
  if (seenIds.size > SEEN_CAP) seenIds.delete(seenIds.values().next().value);
  try {
    fs.appendFileSync(SEEN_PATH, id + '\n');
  } catch (e) {
    log('WARN', 'Could not persist seen id', e.message);
  }
}

// Who a tip goes to, as a numeric X user id, or why it cannot be paid
function resolveTip(tweet, tip, authorId) {
  let recipientId, recipientName;

  if (tip.recipient) {
    // explicit '@alice @XahTipBot +1', or the first typed mention of a post
    // that is not a reply to someone else
    recipientName = tip.recipient;
    recipientId = resolveRecipientId(tweet, tip.recipient);
    if (!recipientId)
      return { skip: ['WARN', `Could not resolve @${tip.recipient} to a user id (missing expansions?)`] };
  } else {
    // implicit: the author of the post being replied to. Never a mention -
    // on a reply those include every thread participant X chose to list.
    recipientId = tweet?.data?.in_reply_to_user_id ?? null;
    if (!recipientId) return { skip: ['WARN', 'Tip names no recipient and is not a reply'] };
    recipientName = (tweet?.includes?.users ?? [])
      .find(u => u.id === recipientId)?.username ?? null;
  }

  if (!/^\d{1,20}$/.test(String(recipientId)))
    return { skip: ['WARN', `Recipient id is not a user id: ${recipientId}`] };
  if (recipientName && BOT_HANDLES.has(recipientName.toLowerCase()))
    return { skip: ['DEBUG', 'Ignoring tip addressed to the bot itself'] };
  if (recipientId === authorId)
    return { skip: ['DEBUG', 'Ignoring self-tip'] };

  return {
    recipientId,
    label: (recipientName ? `@${recipientName}` : `x:${recipientId}`)
         + (tip.recipientVia === 'explicit' ? '' : ` (${tip.recipientVia})`)
  };
}

// Everything handleTweet decides, with no side effects. Returns either
// { drop: { level, msg, data } } or { postId, opinions: [{ hex, url, context }] }
// - one opinion for a tip or withdrawal, one per payable command of a multitip.
function evaluateTweet(tweet) {
  const drop = (level, msg, data) => ({ drop: { level, msg, data } });
  const id = tweet?.data?.id;
  if (!id) return drop('DEBUG', 'Payload without a tweet id', null);

  // Defence two: the rule set lives on the app and can be edited out from
  // under us, and -is:retweet cannot be relied on alone. Drop before parsing,
  // so a retweet never reaches the point of becoming anybody's command.
  const rt = isRetweet(tweet);
  if (rt) return drop('DEBUG', 'Ignoring retweet', { id, via: rt, of: retweetedId(tweet) });

  const parsed = parseTipbotTweet(tweet);
  if (parsed.type === 'invalid')
    return parsed.reason
      ? drop('WARN', `Tipbot command rejected: ${parsed.reason}`, { id })
      : drop('DEBUG', 'Tweet matched rule but no valid command', { id });

  const authorId = tweet?.data?.author_id;
  if (!authorId) return drop('WARN', 'No author_id on tweet (missing tweet.fields?)', { id });

  // Identity of the post, not of this delivery of it. Used for both the dedupe
  // key and the opinion's post_id so the two agree, and so the hook's own
  // (snid, post_id) check sees the same value we did.
  const postId = rootTweetId(tweet);
  if (hasSeen(postId))
    return drop('DEBUG', 'Duplicate post ignored (redelivery or edit)', { id, postId });

  const url = tweetUrl(tweet, postId);
  // when the post was made, for shortcut 'from' times: see shortcutIssuer()
  const postMs = snowflakeMs(postId);
  const multi = parsed.type === 'multitip';
  const opinions = [];
  const skipped = [...(parsed.skipped ?? [])];

  // post_id is always this author's own post, or for a multitip an id derived
  // from it. It is never taken from referenced_tweets - see isRetweet().
  const items = parsed.type === 'withdraw' ? [parsed]
              : multi ? parsed.tips
              : [parsed];

  for (const item of items) {
    const tag = multi ? `#${item.sub + 1}: ` : '';
    try {
      const op = { ...item, type: item.type === 'withdraw' ? 'withdraw' : 'tip',
                   id: multi ? subPostId(postId, item.sub) : postId };
      let to;
      if (op.type === 'tip') {
        const r = resolveTip(tweet, item, authorId);
        if (r.skip) {
          if (!multi) return drop(r.skip[0], r.skip[1], { id });
          skipped.push(tag + r.skip[1]);
          continue;
        }
        op.recipientId = r.recipientId;
        to = r.label;
      } else {
        to = op.dest;
      }

      const hex = opinionFromParsed(op, authorId, postMs);
      const opUrl = multi ? `${url}#${item.sub + 1}` : url;
      opinions.push({
        hex, url: opUrl,
        context: {
          id: op.id,
          ...(multi ? { post: postId, command: item.sub + 1 } : {}),
          type: op.type,
          amount: op.amount,
          currency: op.currency,
          issuer: op.issuer,   // resolved, so a shortcut is visible in the log
          to,
          url: opUrl
        }
      });
    } catch (e) {
      if (!multi) return drop('WARN', `Skipping tweet ${id}`, e.message);
      skipped.push(tag + e.message);
    }
  }

  if (opinions.length === 0)
    return drop('WARN', `Multitip ${id}: no command could be paid`, skipped);
  return { postId, opinions, skipped };
}

function handleTweet(tweet) {
  const r = evaluateTweet(tweet);
  if (r.drop) {
    log(r.drop.level, r.drop.msg, r.drop.data);
    return null;
  }
  if (r.skipped.length)
    log('WARN', `Multitip ${r.postId}: ${r.skipped.length} command(s) skipped`, r.skipped);
  if (DRY_RUN) {
    for (const o of r.opinions)
      log('DRYRUN', 'Would queue opinion', { ...o.context, hex: o.hex });
    return r;
  }
  // one post, one seen entry, however many opinions it became
  markSeen(r.postId);
  for (const o of r.opinions)
    enqueueOpinion(o.hex, o.url, o.context);
  return r;
}

async function rulesApi(method, body) {
  const response = await fetch('https://api.x.com/2/tweets/search/stream/rules', {
    method,
    headers: {
      Authorization: `Bearer ${CONFIG.bearerToken}`,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!response.ok)
    throw new Error(`HTTP ${response.status} - ${await response.text()}`);
  return response.json();
}

// Defence one, and the reason the old addRule() was not enough on its own: the
// rule set is app state, not process state, and POST { add } only ever adds.
// A previous deployment's '@xrptipbot OR @xahtipbot' stays live forever and
// keeps feeding retweets in beside the new rule. Reconcile: delete anything
// that is not exactly the rule we want, then add ours if it is missing.
async function syncRules() {
  const current = (await rulesApi('GET')).data ?? [];

  const stale = current.filter(r => r.value !== RULE);
  if (stale.length) {
    log('WARN', `Deleting ${stale.length} stale stream rule(s)`, stale.map(r => r.value));
    await rulesApi('POST', { delete: { ids: stale.map(r => r.id) } });
  }

  if (current.some(r => r.value === RULE)) {
    log('INFO', 'Stream rule already current', RULE);
    return;
  }

  const result = await rulesApi('POST', { add: [{ value: RULE }] });
  if (result?.errors?.length)
    throw new Error(`Rule rejected: ${JSON.stringify(result.errors)}`);
  log('SUCCESS', 'Rule added', RULE);
}

// A stream that has been up this long is healthy. X answers a duplicate
// connection by accepting it and closing it immediately, so "connected" on its
// own is not evidence of anything - time spent connected is. Waiting for a data
// line instead (the old rule) is not equivalent: the only thing that arrives on
// a quiet rule is the keep-alive newline, which is skipped before the reset, so
// the backoff only ever reset when somebody happened to tweet.
const STREAM_HEALTHY_MS = 60000;

const wasHealthy = openedAt => openedAt > 0 && Date.now() - openedAt >= STREAM_HEALTHY_MS;

// author_id gives us user_id_from; the mention expansion resolves the
// tip recipient's numeric user id from their @username; referenced_tweets
// is what isRetweet() reads. display_text_range separates X's hidden reply
// mentions from what the author typed, and in_reply_to_user_id (expanded for
// the handle) is the recipient of a tip that names nobody - see visibleText().
//
// referenced_tweets.id is deliberately NOT expanded. We have no use for the
// retweeted post's body, and leaving it out means a future edit here cannot
// accidentally start attributing an opinion to the original author.
//
// Shared by the stream and --replay, so a replayed post is judged on exactly
// the payload the stream would have delivered.
const TWEET_QUERY =
    'tweet.fields=author_id,entities,referenced_tweets,display_text_range,in_reply_to_user_id,edit_history_tweet_ids'
  + '&expansions=author_id,entities.mentions.username,in_reply_to_user_id'
  + '&user.fields=id,username';

async function connectStream() {
  const MAX_RETRIES = 12;
  const BASE_DELAY_MS = 5000;
  let retryCount = 0;

  const streamUrl = `https://api.x.com/2/tweets/search/stream?${TWEET_QUERY}`;

  // one iteration per connection attempt. a loop rather than a recursive call:
  // reconnecting by recursing leaves every previous attempt's frame and buffers
  // pinned by the promise chain for the life of the process
  while (!stopping) {
    let openedAt = 0;

    try {
      log('INFO', `Connecting to streaming endpoint (attempt ${retryCount + 1}/${MAX_RETRIES + 1})`);

      streamAbort = new AbortController();
      const response = await fetch(streamUrl, {
        headers: { Authorization: `Bearer ${CONFIG.bearerToken}` },
        signal: streamAbort.signal
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      openedAt = Date.now();
      writeAlive();
      log('SUCCESS', 'Stream connected (live only) - waiting for data');

      const decoder = new TextDecoder();
      let buffer = '';

      for await (const chunk of response.body) {
        buffer += decoder.decode(chunk, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.length === 0) continue; // keep-alive

          try {
            const tweet = JSON.parse(trimmed);

            if (tweet.data) {
              log('TWEET', 'Matching tweet received', {
                id: tweet.data.id,
                author_id: tweet.data.author_id,
                text_preview: tweet.data.text?.substring(0, 120) + (tweet.data.text?.length > 120 ? '...' : '')
              });
              handleTweet(tweet);
            } else if (tweet.errors) {
              log('ERROR', 'Error payload from stream', tweet.errors);
            } else {
              log('DEBUG', 'Non-tweet message received', tweet);
            }
          } catch (parseErr) {
            log('WARN', 'Failed to parse JSON line', {
              linePreview: trimmed.substring(0, 200),
              error: parseErr.message
            });
          }
        }
      }

      if (stopping) return;
      // server closed the stream cleanly: reconnect rather than exit
      log('WARN', 'Stream closed by server - reconnecting');
      if (wasHealthy(openedAt)) retryCount = 0;
      await new Promise(r => setTimeout(r, BASE_DELAY_MS));
      continue;
    } catch (error) {
      if (stopping) return;   // aborted by shutdown()
      log('ERROR', 'Stream error occurred', error.message);

      // The budget counts *consecutive* failures. A connection that stayed up and
      // then dropped hours later is the endpoint behaving normally, not the next
      // step of an outage, so it starts a fresh budget. Without this the counter
      // only ever climbs and the oracle exits on the thirteenth disconnect of its
      // life, however many days apart they were.
      if (wasHealthy(openedAt)) {
        log('INFO', `Stream had been up ${((Date.now() - openedAt) / 1000).toFixed(0)}s - resetting backoff`);
        retryCount = 0;
      }

      if (retryCount >= MAX_RETRIES) {
        log('FATAL', 'Maximum consecutive reconnection attempts reached');
        process.exit(1);
      }

      let delay = Math.min(BASE_DELAY_MS * Math.pow(2, retryCount), 90000);

      if (error.message.includes('429') || error.message.includes('TooManyConnections')) {
        delay = 30000 + (retryCount * 15000);
        log('WARN', `TooManyConnections detected - using extended ${delay / 1000}s backoff`);
      }

      retryCount++;
      log('INFO', `Reconnecting in ${delay / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}


/* ------------------------------------------------------------------ */

// A plain exit drops every queued opinion, and each of those posts has already
// been through markSeen(), so nothing would ever bring it back. Stop taking
// new posts, give the queue a bounded chance to drain, persist what is left
// for the next start, then go. Used by signals and by the updater alike.
let stopping = false;
let streamAbort = null;
const DRAIN_TIMEOUT_MS = 90000;

async function shutdown(reason, code = 0) {
  if (stopping) return;
  stopping = true;
  log('INFO', `Shutting down: ${reason}`);
  try { streamAbort?.abort(); } catch (e) { /* already gone */ }

  const deadline = Date.now() + DRAIN_TIMEOUT_MS;
  while (submitter && opinionQueue.length > 0 && Date.now() < deadline) {
    await flushOpinions().catch(e => log('WARN', 'Flush during shutdown failed', e.message));
    if (opinionQueue.length > 0) await new Promise(r => setTimeout(r, 2000));
  }

  persistQueue();
  writeAlive();
  process.exit(code);
}


/* ------------------------------------------------------------------ */
/* restart safety: queue persistence, heartbeat, backfill              */
/* ------------------------------------------------------------------ */

const QUEUE_PATH = path.join(os.homedir(), '.tipbot-queue.json');
const ALIVE_PATH = path.join(os.homedir(), '.tipbot-alive');

// Entries still queued may include a batch that was in flight when we
// stopped. Resubmitting it costs a fee at worst: the hook records one vote
// per member per post, so a repeat comes back 'V' and changes nothing.
function persistQueue() {
  try {
    if (opinionQueue.length === 0) {
      fs.rmSync(QUEUE_PATH, { force: true });
      return;
    }
    fs.writeFileSync(QUEUE_PATH + '.tmp', JSON.stringify(opinionQueue));
    fs.renameSync(QUEUE_PATH + '.tmp', QUEUE_PATH);
    log('WARN', `${opinionQueue.length} unsubmitted opinion(s) saved for the next start`);
  } catch (e) {
    log('ERROR', `Could not save ${opinionQueue.length} queued opinion(s) - they are lost`, e.message);
  }
}

function loadQueue() {
  let saved;
  try {
    if (!fs.existsSync(QUEUE_PATH)) return;
    saved = JSON.parse(fs.readFileSync(QUEUE_PATH, 'utf8'));
  } catch (e) {
    log('ERROR', 'Saved opinion queue unreadable - left in place', e.message);
    return;
  }
  const ok = (Array.isArray(saved) ? saved : [])
    .filter(o => typeof o?.hex === 'string' && /^[0-9A-F]{170}$/i.test(o.hex) && typeof o?.url === 'string');
  opinionQueue.push(...ok);
  fs.rmSync(QUEUE_PATH, { force: true });
  log('INFO', `Restored ${ok.length} unsubmitted opinion(s) from the last run`);
}

function writeAlive() {
  try { fs.writeFileSync(ALIVE_PATH, String(Date.now())); } catch (e) { /* best effort */ }
}

// The stream is live-only: whatever was posted while we were down, whether for
// an update, a restart or a crash, is never delivered. Search recent posts for
// the same rule over the gap and treat them as if they had been streamed.
// Anything already turned into an opinion is caught by hasSeen(), and the hook
// refuses a second vote on a post regardless.
async function backfill() {
  if (!CONFIG.backfillMaxHours) return;
  let since;
  try { since = Number(fs.readFileSync(ALIVE_PATH, 'utf8')); } catch (e) { return; }
  if (!Number.isFinite(since) || since <= 0) return;

  const end = Date.now() - 15000;        // end_time must be at least 10s ago
  let start = since - 60000;             // overlap the last minute we were up
  const maxMs = CONFIG.backfillMaxHours * 3600000;
  if (end - start > maxMs) {
    log('WARN', `Down since ${new Date(since).toISOString()} - backfilling only the last ${CONFIG.backfillMaxHours}h`);
    start = end - maxMs;
  }
  if (end <= start) return;

  const found = [];
  let next = null, pages = 0;
  do {
    const q = new URLSearchParams({
      query: RULE, max_results: '100',
      start_time: new Date(start).toISOString(), end_time: new Date(end).toISOString()
    });
    if (next) q.set('next_token', next);
    const response = await fetch(`https://api.x.com/2/tweets/search/recent?${q}&${TWEET_QUERY}`, {
      headers: { Authorization: `Bearer ${CONFIG.bearerToken}` }
    });
    if (!response.ok)
      throw new Error(`HTTP ${response.status} - ${await response.text()}`);
    const body = await response.json();
    for (const data of body.data ?? []) found.push({ data, includes: body.includes ?? {} });
    next = body.meta?.next_token ?? null;
  } while (next && ++pages < 50);

  log('INFO', `Backfill: ${found.length} post(s) between ${new Date(start).toISOString()} and ${new Date(end).toISOString()}`);
  for (const t of found.reverse())   // oldest first, as the stream would have
    handleTweet(t);
}

/* ------------------------------------------------------------------ */
/* self-update: always the tip of origin/<branch>                      */
/* ------------------------------------------------------------------ */

const REPO_DIR = __dirname;
// written by the gated updater in a3c8366; see defuseLegacyRollback()
const LEGACY_UPDATE_STATE = path.join(os.homedir(), '.tipbot-update.json');
const FIRST_UPDATE_CHECK_MS = 15000;
const NPM = (() => {
  const beside = path.join(path.dirname(process.execPath), 'npm');
  return fs.existsSync(beside) ? beside : 'npm';
})();

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) =>
    execFile(cmd, args, { cwd: REPO_DIR, timeout: 300000, maxBuffer: 32 << 20, ...opts },
      (err, stdout, stderr) => err
        ? reject(new Error(`${path.basename(cmd)} ${args.join(' ')}: ${String(stderr || err.message).trim().slice(-2000)}`))
        : resolve(String(stdout).trim())));
}
const git = (...args) => run('git', args);
const gitSync = (...args) => execFileSync('git', args, { cwd: REPO_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const short = rev => String(rev).slice(0, 8);

function isGitCheckout() {
  try { return gitSync('rev-parse', '--is-inside-work-tree') === 'true'; } catch (e) { return false; }
}

// Update settings, from ~/.tipbotcfg as parsed JSON. Shared by loadConfig()
// and the supervisor, which reads the file itself.
function updateSettings(data) {
  return {
    enabled: data?.auto_update !== false,
    branch: typeof data?.update_branch === 'string' && /^[\w./-]+$/.test(data.update_branch)
      ? data.update_branch : 'main',
    intervalMs: Math.max(60, Number(data?.update_interval_s) || 300) * 1000
  };
}

// Put the checkout on the tip of origin/<branch>, unconditionally: whatever
// the tip is (a rewrite, an older commit, a broken one) and whatever is in the
// way here (local commits, edited files - both are discarded). There is no
// judging the new version first; if it cannot run, the supervisor fetches
// again every time it restarts it, so the fix for a broken tip is to push one.
// Returns { from, to } when the checkout moved, null when it was already there.
let updating = false;

async function forceToTip(branch, who) {
  if (updating) return null;
  updating = true;
  try {
    await git('fetch', '--quiet', '--force', 'origin',
              `+refs/heads/${branch}:refs/remotes/origin/${branch}`);
    const head = await git('rev-parse', 'HEAD');
    const tip = await git('rev-parse', `refs/remotes/origin/${branch}`);
    if (head === tip) return null;

    const pkg = rev => git('rev-parse', `${rev}:package.json`).catch(() => '');
    const depsChanged = (await pkg(head)) !== (await pkg(tip));

    await git('checkout', '--quiet', '--force', '-B', branch, `refs/remotes/origin/${branch}`);
    log('INFO', `${who}forced checkout to origin/${branch}: ${short(head)} -> ${short(tip)}`);

    if (depsChanged) {
      try { await run(NPM, ['install', '--omit=dev', '--no-audit', '--no-fund']); }
      catch (e) { log('WARN', `${who}npm install failed - starting ${short(tip)} anyway`, e.message); }
    }
    return { from: head, to: tip };
  } finally {
    updating = false;
  }
}

// a3c8366's supervisor rolls the checkout back after a worker crashes three
// times with an update "pending" in this file. That fights forceToTip(), so a
// worker removes the file first thing - and with it the list of revisions the
// old updater refused, which no longer means anything.
function defuseLegacyRollback() {
  try { fs.rmSync(LEGACY_UPDATE_STATE, { force: true }); } catch (e) { /* best effort */ }
}

// For a worker whose parent does not update it: a supervisor from before
// this version (a3c8366), or a worker started by hand. Polls like the
// supervisor would, and on a move drains and exits EXIT_RESTART, which every
// supervisor version answers by starting the code now on disk.
function startWorkerUpdater() {
  if (!CONFIG.update.enabled) return log('INFO', 'Auto-update disabled');
  if (!isGitCheckout()) return log('WARN', `${REPO_DIR} is not a git checkout - auto-update disabled`);

  const tick = first => setTimeout(async () => {
    try {
      const moved = await forceToTip(CONFIG.update.branch, '');
      if (moved) return shutdown(`updated ${short(moved.from)} -> ${short(moved.to)}, restarting`, EXIT_RESTART);
    } catch (e) {
      log('WARN', 'Update check failed', e.message);
    }
    if (!stopping) tick(false);
  }, first ? FIRST_UPDATE_CHECK_MS : CONFIG.update.intervalMs * (0.8 + Math.random() * 0.4));
  tick(true);
  log('INFO', `Auto-update (in worker): following origin/${CONFIG.update.branch}, every ~${CONFIG.update.intervalMs / 1000}s`);
}

/* ------------------------------------------------------------------ */
/* supervisor                                                          */
/* ------------------------------------------------------------------ */

// `node ton.js` lands here. A process cannot replace its own code, so this
// one never tries: it keeps a single worker, `node ton.js --worker`, running
// from whatever ton.js is on disk, sharing the terminal, and it is the one
// that keeps the checkout on the tip of origin/<branch>:
//   - before the first worker starts
//   - every update_interval_s (jittered); on a move the worker is asked to
//     stop (SIGTERM: it drains its queue, persists the rest) and the new
//     code is started
//   - every time a worker dies unasked, before it is restarted, so a crash
//     caused by a bad commit clears as soon as a good one is pushed
// Being the old, already-running code, it keeps working whatever the new
// code does - including when the new code cannot load at all.
//
// Ctrl-C reaches both processes: the worker drains and exits, the supervisor
// follows. A signal sent to the supervisor alone is passed on.
//
// Changes to supervise() itself take effect only when TON is restarted by
// hand; everything else takes effect on the next update.
function supervise() {
  const slog = (level, msg, data) => log(level, `[supervisor] ${msg}`, data);

  let upd;
  try {
    const data = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    if (!data.bearer_token || !data.seed) throw new Error("needs 'bearer_token' and 'seed'");
    upd = updateSettings(data);
  } catch (e) {
    slog('ERROR', `cannot use ${cfgPath}`, e.message);
    process.exit(EXIT_CONFIG);
  }
  const canUpdate = upd.enabled && isGitCheckout();
  if (!upd.enabled) slog('INFO', 'auto-update disabled');
  else if (!canUpdate) slog('WARN', `${REPO_DIR} is not a git checkout - not updating`);

  let child = null;
  let stopping = false;
  let restarting = false;   // we asked the worker to stop, to start new code
  let pendingStart = null;  // backoff timer while no worker is running
  let fails = 0;

  const update = async () => {
    if (!canUpdate || stopping) return null;
    try { return await forceToTip(upd.branch, '[supervisor] '); }
    catch (e) { slog('WARN', 'update check failed', e.message); return null; }
  };

  const stop = sig => () => {
    stopping = true;
    if (child) child.kill(sig);   // the worker's shutdown() is idempotent
    else process.exit(0);
  };
  process.on('SIGINT', stop('SIGINT'));
  process.on('SIGTERM', stop('SIGTERM'));
  process.on('SIGHUP', stop('SIGTERM'));

  const start = () => {
    pendingStart = null;
    if (stopping) process.exit(0);
    const startedAt = Date.now();
    child = spawn(process.execPath,
                  [...process.execArgv, path.join(REPO_DIR, 'ton.js'), WORKER_FLAG, ...process.argv.slice(2)],
                  { stdio: 'inherit', cwd: REPO_DIR,
                    env: { ...process.env, TON_SUPERVISOR: SUPERVISOR_VERSION } });
    slog('INFO', `worker ${child.pid} started at ${(() => { try { return short(gitSync('rev-parse', 'HEAD')); } catch (e) { return '?'; } })()}`);

    child.on('exit', async (code, signal) => {
      child = null;
      if (stopping) process.exit(code ?? 0);
      if (restarting || code === EXIT_RESTART) {   // new code on disk
        restarting = false;
        fails = 0;
        return start();
      }

      const up = Date.now() - startedAt;
      fails = up > 60000 ? 1 : fails + 1;
      slog('WARN', `worker exited (${signal ?? `code ${code}`}) after ${Math.round(up / 1000)}s`);

      // whatever took it down may already be fixed on the branch
      const moved = await update();
      const delay = moved ? 1000 : Math.min(2000 * 2 ** (fails - 1), 300000);
      slog('INFO', `restarting in ${delay / 1000}s`);
      pendingStart = setTimeout(start, delay);
    });
  };

  const poll = () => setTimeout(async () => {
    const moved = await update();
    if (moved && !stopping) {
      if (child) {
        restarting = true;
        slog('INFO', 'stopping the worker to start the new version');
        child.kill('SIGTERM');
      } else if (pendingStart) {
        clearTimeout(pendingStart);
        start();
      }
    }
    if (!stopping) poll();
  }, upd.intervalMs * (0.8 + Math.random() * 0.4));

  (async () => {
    await update();
    start();
    if (canUpdate) {
      poll();
      slog('INFO', `following origin/${upd.branch}, every ~${upd.intervalMs / 1000}s`);
    }
  })();
}

// Posts the stream never delivered (the oracle was down, or the parser of the
// day rejected them) can only be fetched. They go through handleTweet() like
// any other, so ~/.tipbot-seen and the hook's (snid, post_id) check both still
// stand between a replay and a double tip.
async function fetchTweets(ids) {
  const response = await fetch(`https://api.x.com/2/tweets?ids=${ids.join(',')}&${TWEET_QUERY}`, {
    headers: { Authorization: `Bearer ${CONFIG.bearerToken}` }
  });
  if (!response.ok)
    throw new Error(`HTTP ${response.status} - ${await response.text()}`);
  const body = await response.json();
  for (const e of body.errors ?? [])
    log('WARN', 'Post could not be fetched', { id: e.resource_id ?? e.value, error: e.detail ?? e.title });
  return (body.data ?? []).map(data => ({ data, includes: body.includes ?? {} }));
}

async function replay(ids) {
  if (ids.length === 0 || ids.length > 100 || !ids.every(i => /^\d{1,20}$/.test(i)))
    throw new Error('--replay takes 1 to 100 numeric post ids');

  if (!DRY_RUN) {
    submitter = new XahauSubmitter(CONFIG.wss, CONFIG.seed);
    await submitter.init();
  }

  const tweets = await fetchTweets(ids);
  log('INFO', `Replaying ${tweets.length} of ${ids.length} post(s)${DRY_RUN ? ' (dry run)' : ''}`);
  for (const t of tweets) {
    log('TWEET', 'Replayed tweet', { id: t.data.id, author_id: t.data.author_id, text: t.data.text });
    handleTweet(t);
  }
  if (DRY_RUN) return;

  // retryable failures leave the batch queued; give them a few goes
  for (let attempt = 0; opinionQueue.length > 0 && attempt < 6; attempt++) {
    if (attempt) await new Promise(r => setTimeout(r, 5000));
    await flushOpinions();
  }
  if (opinionQueue.length > 0)
    log('ERROR', `${opinionQueue.length} opinion(s) still queued - not submitted`);

  await Promise.allSettled([...submitter.tracking]);
}

async function main() {
  const args = process.argv.slice(2);
  DRY_RUN = args.includes('--dry-run');

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  try {
    CONFIG = loadConfig();
    loadSeen();
    loadShortcutsCache();

    if (args.includes('--replay')) {
      await refreshShortcuts();
      await replay(args.filter(a => !a.startsWith('--')));
      process.exit(0);
    }

    loadQueue();

    // Before anything that talks to the network, so that a version which
    // cannot get past init (a bad endpoint, a bug) can still be fixed by push.
    defuseLegacyRollback();
    if (!process.env.TON_SUPERVISOR) startWorkerUpdater();

    // before the stream and backfill, so the first post is judged on the
    // current list. Never throws: on failure the cached list stays in force
    await refreshShortcuts();
    startShortcutRefresher();

    submitter = new XahauSubmitter(CONFIG.wss, CONFIG.seed);
    await submitter.init();

    setInterval(() => {
      if (!stopping) writeAlive();
      flushOpinions().catch(e => log('ERROR', 'Flush failed', e.message));
    }, FLUSH_INTERVAL_MS);

    await syncRules();

    // stream first, then backfill up to now, so the two overlap and nothing
    // posted while we were down falls between them
    const stream = connectStream();
    await backfill().catch(e => log('WARN', 'Backfill failed - posts made while down may be missed', e.message));


    await stream;
  } catch (error) {
    log('FATAL', 'Application failed to start', error.message);
    process.exit(1);
  }
}

module.exports = {
  parseTipbotTweet, evaluateTweet, parseCurrencySlot, parseAmount,
  // for test-update.sh only
  _internals: { forceToTip, shutdown, loadQueue, opinionQueue, setConfig: c => { CONFIG = c; },
                installShortcuts, loadShortcutsCache, refreshShortcuts, snowflakeMs }
};

// `ton.js --check-shortcuts <file>`: the same validation every oracle applies,
// so a bad edit is caught before it is pushed rather than refused by them all
function checkShortcuts(file) {
  try {
    if (!file) throw new Error('usage: ton.js --check-shortcuts <shortcuts.json>');
    const table = buildShortcuts(fs.readFileSync(file, 'utf8'));
    for (const h of [...table.values()].flat()) console.log(describeShortcut(h));
    console.log(`OK: ${[...table.values()].flat().length} entries`);
  } catch (e) {
    console.error(`INVALID: ${e.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.includes('--supervisor-contract')) console.log(SUPERVISOR_CONTRACT);
  else if (args.includes('--check-shortcuts')) checkShortcuts(args[args.indexOf('--check-shortcuts') + 1]);
  else if (args.includes(WORKER_FLAG) || args.includes('--replay')) main();
  else supervise();
}
