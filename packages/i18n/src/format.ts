/**
 * A small subset of ICU MessageFormat:
 *
 * - `{name}` inserts a parameter.
 * - `{count, plural, =0 {none} one {# item} other {# items}}` picks a branch
 *   with `Intl.PluralRules`; `#` is the formatted number.
 * - `{kind, select, web {Browser} other {App}}` picks a branch by value.
 *
 * Branches may nest. Use `'{'` to write a literal brace.
 */
export type Params = Record<string, string | number | undefined>;

interface Cursor {
  text: string;
  pos: number;
}

export function formatMessage(message: string, params: Params, locale: string): string {
  return parseUntil({ text: message, pos: 0 }, params, locale, undefined, false);
}

function parseUntil(c: Cursor, params: Params, locale: string, hash: string | undefined, nested: boolean): string {
  let out = "";
  while (c.pos < c.text.length) {
    const ch = c.text[c.pos];
    if (ch === "'" && c.text[c.pos + 1] === "{" && c.text[c.pos + 2] === "'") {
      out += "{";
      c.pos += 3;
    } else if (ch === "'" && c.text[c.pos + 1] === "}" && c.text[c.pos + 2] === "'") {
      out += "}";
      c.pos += 3;
    } else if (ch === "{") {
      c.pos++;
      out += argument(c, params, locale, hash);
    } else if (ch === "}" && nested) {
      c.pos++;
      return out;
    } else if (ch === "#" && hash !== undefined) {
      out += hash;
      c.pos++;
    } else {
      out += ch;
      c.pos++;
    }
  }
  return out;
}

function readUntil(c: Cursor, stops: string): string {
  const start = c.pos;
  while (c.pos < c.text.length && !stops.includes(c.text[c.pos] ?? "")) c.pos++;
  return c.text.slice(start, c.pos).trim();
}

function argument(c: Cursor, params: Params, locale: string, hash: string | undefined): string {
  const name = readUntil(c, ",}");
  const value = params[name];
  if (c.text[c.pos] === "}") {
    c.pos++;
    if (value === undefined) return `{${name}}`;
    return typeof value === "number" ? new Intl.NumberFormat(locale).format(value) : value;
  }
  c.pos++; // ","
  const kind = readUntil(c, ",}");
  c.pos++; // ","
  const bodies = new Map<string, number>();
  while (c.pos < c.text.length) {
    while (c.text[c.pos] === " " || c.text[c.pos] === "\n") c.pos++;
    if (c.text[c.pos] === "}") {
      c.pos++;
      break;
    }
    const key = readUntil(c, "{");
    c.pos++; // "{"
    bodies.set(key, c.pos);
    skipBranch(c);
  }
  const end = c.pos;
  const render = (key: string, branchHash: string | undefined) => {
    const start = bodies.get(key);
    if (start === undefined) return undefined;
    const branch: Cursor = { text: c.text, pos: start };
    return parseUntil(branch, params, locale, branchHash, true);
  };
  let result: string | undefined;
  if (kind === "plural") {
    const n = typeof value === "number" ? value : Number(value ?? 0);
    const formatted = new Intl.NumberFormat(locale).format(n);
    result =
      render(`=${n}`, formatted) ??
      render(new Intl.PluralRules(locale).select(n), formatted) ??
      render("other", formatted);
  } else {
    result = render(String(value ?? ""), hash) ?? render("other", hash);
  }
  c.pos = end;
  return result ?? "";
}

/** Moves past a `{...}` branch body whose opening brace was consumed. */
function skipBranch(c: Cursor) {
  let depth = 1;
  while (c.pos < c.text.length && depth > 0) {
    const ch = c.text[c.pos];
    if (ch === "'" && (c.text[c.pos + 1] === "{" || c.text[c.pos + 1] === "}") && c.text[c.pos + 2] === "'") {
      c.pos += 3;
      continue;
    }
    if (ch === "{") depth++;
    else if (ch === "}") depth--;
    c.pos++;
  }
}
