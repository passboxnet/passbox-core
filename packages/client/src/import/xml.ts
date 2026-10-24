/**
 * A minimal, non-validating XML reader for password manager exports (KeePass
 * 2 XML). It builds an element tree with attributes and text, decodes the
 * predefined and numeric entities and CDATA sections, and skips comments,
 * processing instructions and the doctype. It never resolves external
 * entities or DTDs.
 */

export interface XmlElement {
  name: string;
  attributes: Record<string, string>;
  children: XmlElement[];
  text: string;
}

const ENTITIES: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

export function decodeEntities(value: string): string {
  return value.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (match, entity: string) => {
    if (entity.startsWith("#x")) return safeCodePoint(Number.parseInt(entity.slice(2), 16)) ?? match;
    if (entity.startsWith("#")) return safeCodePoint(Number.parseInt(entity.slice(1), 10)) ?? match;
    return ENTITIES[entity] ?? match;
  });
}

function safeCodePoint(code: number): string | undefined {
  return Number.isFinite(code) && code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : undefined;
}

export class XmlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "XmlError";
  }
}

/** Parses an XML document and returns its root element. */
export function parseXml(input: string): XmlElement {
  const root: XmlElement = { name: "#document", attributes: {}, children: [], text: "" };
  const stack: XmlElement[] = [root];
  let i = 0;
  const len = input.length;
  while (i < len) {
    const lt = input.indexOf("<", i);
    const top = stack[stack.length - 1] as XmlElement;
    if (lt === -1) {
      top.text += decodeEntities(input.slice(i));
      break;
    }
    if (lt > i) top.text += decodeEntities(input.slice(i, lt));
    if (input.startsWith("<!--", lt)) {
      const end = input.indexOf("-->", lt + 4);
      if (end === -1) throw new XmlError("unterminated comment");
      i = end + 3;
    } else if (input.startsWith("<![CDATA[", lt)) {
      const end = input.indexOf("]]>", lt + 9);
      if (end === -1) throw new XmlError("unterminated CDATA section");
      top.text += input.slice(lt + 9, end);
      i = end + 3;
    } else if (input.startsWith("<?", lt)) {
      const end = input.indexOf("?>", lt + 2);
      if (end === -1) throw new XmlError("unterminated processing instruction");
      i = end + 2;
    } else if (input.startsWith("<!", lt)) {
      // Doctype or other declaration; internal subsets are skipped, never used.
      let depth = 0;
      let j = lt + 2;
      for (; j < len; j++) {
        const c = input[j];
        if (c === "[") depth++;
        else if (c === "]") depth--;
        else if (c === ">" && depth <= 0) break;
      }
      i = j + 1;
    } else if (input[lt + 1] === "/") {
      const end = input.indexOf(">", lt);
      if (end === -1) throw new XmlError("unterminated end tag");
      const name = input.slice(lt + 2, end).trim();
      if (top.name !== name) throw new XmlError(`unexpected </${name}>`);
      stack.pop();
      i = end + 1;
    } else {
      const end = findTagEnd(input, lt);
      let body = input.slice(lt + 1, end);
      const selfClosing = body.endsWith("/");
      if (selfClosing) body = body.slice(0, -1);
      const nameMatch = /^[^\s/>]+/.exec(body);
      if (!nameMatch) throw new XmlError("invalid start tag");
      const element: XmlElement = {
        name: nameMatch[0],
        attributes: parseAttributes(body.slice(nameMatch[0].length)),
        children: [],
        text: "",
      };
      top.children.push(element);
      if (!selfClosing) stack.push(element);
      i = end + 1;
    }
  }
  if (stack.length !== 1) throw new XmlError(`unclosed <${stack[stack.length - 1]?.name}>`);
  const [first] = root.children;
  if (!first) throw new XmlError("no root element");
  return first;
}

function findTagEnd(input: string, start: number): number {
  let quote: string | undefined;
  for (let j = start + 1; j < input.length; j++) {
    const c = input[j];
    if (quote) {
      if (c === quote) quote = undefined;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === ">") return j;
  }
  throw new XmlError("unterminated start tag");
}

function parseAttributes(source: string): Record<string, string> {
  const attributes: Record<string, string> = {};
  const pattern = /([^\s=]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
  for (let match = pattern.exec(source); match; match = pattern.exec(source)) {
    attributes[match[1] as string] = decodeEntities(match[3] ?? match[4] ?? "");
  }
  return attributes;
}

/** The first direct child named `name`. */
export function child(element: XmlElement, name: string): XmlElement | undefined {
  return element.children.find((c) => c.name === name);
}

/** All direct children named `name`. */
export function children(element: XmlElement, name: string): XmlElement[] {
  return element.children.filter((c) => c.name === name);
}

/** Text of the first direct child named `name`, or "". */
export function childText(element: XmlElement, name: string): string {
  return child(element, name)?.text ?? "";
}
