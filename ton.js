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
 * deps: npm i node-fetch@2 xrpl-client xrpl-accountlib
 *
 * ~/.tipbot-seen: append-only list of post ids already turned into opinions,
 * so a restart does not re-tip whatever the stream redelivers.
 *
 * ~/.tipbotcfg (JSON):
 * {
 *   "bearer_token": "...",            // X API v2 bearer
 *   "seed": "s...",                   // family seed of THIS oracle's member account
 *   "wss": "wss://xahau.network"      // optional
 * }
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const fetch = require('node-fetch');
const { XrplClient } = require('xrpl-client');
const lib = require('xrpl-accountlib');

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

// xahaud isMemoOkay() serializes the Memos array and rejects the txn if the
// result exceeds 1024 bytes, so a full batch of 16 memos has to fit inside it.
const MEMO_BYTES_MAX = 1024;
// keeping URLs under 193 bytes keeps the VL length prefix to a single byte,
// which is what memoCost() below assumes
const MEMO_URL_MAX = 192;

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
      wss: data.wss || DEFAULT_WSS
    };
  } catch (error) {
    log('ERROR', 'Failed to load configuration', error.message);
    process.exit(1);
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

function parseTipbotTweet(tweet) {
  const text = tweet?.data?.text;
  const id   = tweet?.data?.id;      // keep as STRING: snowflakes exceed 2^53
  const INVALID = { type: 'invalid' };

  if (!text || !id) return INVALID;

  const ADDR = `r[${B58}]{24,33}`;
  const BOT  = `@(?:xrptipbot|xahtipbot)`;
  const AMT  = `(?<amount>\\d+(?:\\.\\d+)?)`;
  const CUR  = `(?<currency>[A-Fa-f0-9]{40}|[A-Za-z]{3})`;
  const ISS  = `(?::(?<issuer>${ADDR}))?`;

  let m;

  m = text.match(new RegExp(`${BOT}\\s+withdraw\\s+${AMT}\\s+${CUR}${ISS}\\s+to\\s+(?<dest>${ADDR})(?=\\s|$)`, `im`));
  if (m) return { type: 'withdraw', id, amount: parseFloat(m.groups.amount), currency: m.groups.currency.toUpperCase(), issuer: m.groups.issuer ?? null, dest: m.groups.dest };

  m = text.match(new RegExp(`@(?<recipient>[A-Za-z0-9_]{1,50})\\s+${BOT}\\s+\\+${AMT}(?:\\s+${CUR}${ISS})?(?=\\s|$)`, `im`));
  if (m) return { type: 'tip', id, amount: parseFloat(m.groups.amount), currency: (m.groups.currency ?? 'XAH').toUpperCase(), issuer: m.groups.issuer ?? null, recipient: m.groups.recipient };

  return INVALID;
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

// 3-char code -> standard 160-bit currency layout (ascii at bytes 12..14),
// 40-hex passes through, XAH -> 0
function currencyField(cur) {
  if (cur === 'XAH') return 0;
  if (/^[A-Fa-f0-9]{40}$/.test(cur)) return cur.toUpperCase();
  if (/^[A-Za-z]{3}$/.test(cur)) {
    const buf = Buffer.alloc(20);
    buf.write(cur.toUpperCase(), 12, 'ascii');
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
// This is a *default*, never an override. A 3-letter ticker is not unique on
// ledger - anyone can issue 'EVR' - so 'EVR:rSomeoneElse' must keep resolving
// to whatever the author actually wrote. See opinionFromParsed().
//
// To add a token, add a line here. Nothing else needs to change.
const TOKEN_SHORTCUTS = {
  EVR: 'rEvernodee8dJLaFsujS6q1EiXvZYmHXr8'   // Evernode, Xahau mainnet
};

// Keyed by the normalised 160-bit currency field rather than the ticker, so
// '+5 EVR' and '+5 <40 hex of EVR>' land on the same entry.
//
// Built (and validated) once at startup: a mistyped ticker or a bad address
// checksum is then a loud boot failure, rather than a per-tweet throw that
// surfaces months later as a WARN in the stream log while tips quietly fail.
const TOKEN_DEFAULT_ISSUER = (() => {
  const m = Object.create(null);
  for (const [ticker, issuer] of Object.entries(TOKEN_SHORTCUTS)) {
    const key = ticker.toUpperCase();
    if (key === 'XAH')
      throw new Error('TOKEN_SHORTCUTS must not contain XAH: it is native and cannot have an issuer');
    const cur = currencyField(key);   // throws on a malformed ticker
    if (cur === 0)
      throw new Error(`TOKEN_SHORTCUTS[${ticker}] resolves to the native currency`);
    decodeAccountID(issuer);          // throws on a bad address or checksum
    if (m[cur] && m[cur] !== issuer)
      throw new Error(`TOKEN_SHORTCUTS has conflicting issuers for ${ticker}`);
    m[cur] = issuer;
  }
  return m;
})();

// parsed tweet + author id -> 170-nibble opinion hex
function opinionFromParsed(parsed, authorId) {
  const cur = currencyField(parsed.currency);

  // Fill in the issuer only where the author left one out. Written back onto
  // `parsed` so the queue log records the issuer that was actually encoded
  // rather than the blank that was typed - the two must never disagree.
  if (cur !== 0 && !parsed.issuer)
    parsed.issuer = TOKEN_DEFAULT_ISSUER[cur] ?? null;

  const iss = parsed.issuer ? decodeAccountID(parsed.issuer) : 0;

  if (cur !== 0 && iss === 0)
    throw new Error(`issued currency requires an issuer (${parsed.currency}:issuer)`);
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
      // fire and forget: report hook results once validated
      this.reportHookResults(id, lls).catch(e =>
        log('WARN', 'Result tracking failed', e.message));
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

const CONFIG = loadConfig();

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

function handleTweet(tweet) {
  const id = tweet?.data?.id;
  if (!id) return;

  // Defence two: the rule set lives on the app and can be edited out from
  // under us, and -is:retweet cannot be relied on alone. Drop before parsing,
  // so a retweet never reaches the point of becoming anybody's command.
  const rt = isRetweet(tweet);
  if (rt) {
    log('DEBUG', 'Ignoring retweet', { id, via: rt, of: retweetedId(tweet) });
    return;
  }

  const parsed = parseTipbotTweet(tweet);
  if (parsed.type === 'invalid') {
    log('DEBUG', 'Tweet matched rule but no valid command', { id });
    return;
  }

  const authorId = tweet?.data?.author_id;
  if (!authorId) {
    log('WARN', 'No author_id on tweet (missing tweet.fields?)', { id });
    return;
  }

  // Identity of the post, not of this delivery of it. Used for both the dedupe
  // key and the opinion's post_id so the two agree, and so the hook's own
  // (snid, post_id) check sees the same value we did.
  const postId = rootTweetId(tweet);
  if (hasSeen(postId)) {
    log('DEBUG', 'Duplicate post ignored (redelivery or edit)', { id, postId });
    return;
  }

  try {
    if (parsed.type === 'tip') {
      const uname = parsed.recipient.toLowerCase();
      if (BOT_HANDLES.has(uname)) {
        log('DEBUG', 'Ignoring tip addressed to the bot itself', { id });
        return;
      }
      const recipientId = resolveRecipientId(tweet, parsed.recipient);
      if (!recipientId) {
        log('WARN', `Could not resolve @${parsed.recipient} to a user id (missing expansions?)`, { id });
        return;
      }
      if (recipientId === authorId) {
        log('DEBUG', 'Ignoring self-tip', { id });
        return;
      }
      parsed.recipientId = recipientId;
    }

    // post_id is always this author's own post. It is never taken from
    // referenced_tweets - see isRetweet().
    parsed.id = postId;

    const hex = opinionFromParsed(parsed, authorId);
    const url = tweetUrl(tweet, postId);

    markSeen(postId);
    enqueueOpinion(hex, url, {
      id: postId,
      type: parsed.type,
      amount: parsed.amount,
      currency: parsed.currency,
      issuer: parsed.issuer,   // resolved, so a shortcut is visible in the log
      to: parsed.type === 'withdraw' ? parsed.dest : `@${parsed.recipient}`,
      url
    });
  } catch (e) {
    log('WARN', `Skipping tweet ${id}`, e.message);
  }
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

async function connectStream() {
  const MAX_RETRIES = 12;
  const BASE_DELAY_MS = 5000;
  let retryCount = 0;

  // author_id gives us user_id_from; the mention expansion resolves the
  // tip recipient's numeric user id from their @username; referenced_tweets
  // is what isRetweet() reads.
  //
  // referenced_tweets.id is deliberately NOT expanded. We have no use for the
  // retweeted post's body, and leaving it out means a future edit here cannot
  // accidentally start attributing an opinion to the original author.
  const streamUrl = 'https://api.x.com/2/tweets/search/stream'
    + '?tweet.fields=author_id,entities,referenced_tweets'
    + '&expansions=author_id,entities.mentions.username'
    + '&user.fields=id,username';

  // one iteration per connection attempt. a loop rather than a recursive call:
  // reconnecting by recursing leaves every previous attempt's frame and buffers
  // pinned by the promise chain for the life of the process
  for (;;) {
    let openedAt = 0;

    try {
      log('INFO', `Connecting to streaming endpoint (attempt ${retryCount + 1}/${MAX_RETRIES + 1})`);

      const response = await fetch(streamUrl, {
        headers: { Authorization: `Bearer ${CONFIG.bearerToken}` }
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      openedAt = Date.now();
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

      // server closed the stream cleanly: reconnect rather than exit
      log('WARN', 'Stream closed by server - reconnecting');
      if (wasHealthy(openedAt)) retryCount = 0;
      await new Promise(r => setTimeout(r, BASE_DELAY_MS));
      continue;
    } catch (error) {
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

process.on('SIGINT', () => {
  log('INFO', 'Received SIGINT - shutting down gracefully');
  process.exit(0);
});
process.on('SIGTERM', () => {
  log('INFO', 'Received SIGTERM - shutting down gracefully');
  process.exit(0);
});

async function main() {
  try {
    loadSeen();

    submitter = new XahauSubmitter(CONFIG.wss, CONFIG.seed);
    await submitter.init();

    setInterval(() => {
      flushOpinions().catch(e => log('ERROR', 'Flush failed', e.message));
    }, FLUSH_INTERVAL_MS);

    await syncRules();
    await connectStream();
  } catch (error) {
    log('FATAL', 'Application failed to start', error.message);
    process.exit(1);
  }
}

main();
