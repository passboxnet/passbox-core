/**
 * A small RFC 4180 CSV reader and writer. Handles quoted fields with
 * embedded delimiters, quotes and line breaks, CRLF and LF line endings, a
 * UTF-8 byte order mark, and the semicolon and tab delimiters that German
 * spreadsheet programs use.
 */

export type Delimiter = "," | ";" | "\t";

/** Guesses the delimiter from the first line (outside quotes). */
export function detectDelimiter(text: string): Delimiter {
  const counts: Record<Delimiter, number> = { ",": 0, ";": 0, "\t": 0 };
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') quoted = !quoted;
    else if (!quoted && (c === "\n" || c === "\r")) break;
    else if (!quoted && (c === "," || c === ";" || c === "\t")) counts[c]++;
  }
  if (counts[";"] > counts[","] && counts[";"] >= counts["\t"]) return ";";
  if (counts["\t"] > counts[","]) return "\t";
  return ",";
}

/** Parses CSV text into rows of cells. Empty lines are dropped. */
export function parseCsv(input: string, delimiter: Delimiter = detectDelimiter(stripBom(input))): string[][] {
  const text = stripBom(input);
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  let i = 0;
  const pushRow = () => {
    row.push(cell);
    cell = "";
    if (row.length > 1 || row[0] !== "") rows.push(row);
    row = [];
  };
  while (i < text.length) {
    const c = text[i] as string;
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i += 2;
          continue;
        }
        quoted = false;
        i++;
        continue;
      }
      cell += c;
      i++;
      continue;
    }
    if (c === '"' && cell === "") {
      quoted = true;
    } else if (c === delimiter) {
      row.push(cell);
      cell = "";
    } else if (c === "\r") {
      pushRow();
      if (text[i + 1] === "\n") i++;
    } else if (c === "\n") {
      pushRow();
    } else {
      cell += c;
    }
    i++;
  }
  if (cell !== "" || row.length > 0) pushRow();
  return rows;
}

/** A CSV file as header names plus one record (header → value) per row. */
export interface CsvTable {
  headers: string[];
  rows: string[][];
}

export function parseCsvTable(text: string, delimiter?: Delimiter): CsvTable {
  const [headers = [], ...rows] = parseCsv(text, delimiter);
  return { headers: headers.map((h) => h.trim()), rows };
}

/** Records keyed by the exact header name. Duplicate headers keep the first value. */
export function toRecords(table: CsvTable): Record<string, string>[] {
  return table.rows.map((row) => {
    const record: Record<string, string> = {};
    table.headers.forEach((header, index) => {
      if (!(header in record)) record[header] = row[index] ?? "";
    });
    return record;
  });
}

export function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function escapeCell(value: string, delimiter: string): string {
  return /["\r\n]/.test(value) || value.includes(delimiter) || /^\s|\s$/.test(value)
    ? `"${value.replace(/"/g, '""')}"`
    : value;
}

/** Writes rows as CSV with CRLF line endings. */
export function writeCsv(rows: readonly (readonly string[])[], delimiter: Delimiter = ","): string {
  return `${rows.map((row) => row.map((cell) => escapeCell(cell, delimiter)).join(delimiter)).join("\r\n")}\r\n`;
}
