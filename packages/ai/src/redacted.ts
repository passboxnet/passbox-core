/**
 * The redaction layer's output type. Only this package's feature modules
 * can create a `Redacted` (through `seal`, which the package does not
 * export), so callers cannot hand raw vault data to a provider.
 */
import type { DataClass } from "./types";

const SEAL: unique symbol = Symbol("passbox.redacted");

let create: <T>(value: T, classes: readonly DataClass[], pseudonymized: boolean) => Redacted<T>;

export class Redacted<T> {
  readonly #value: T;
  /** The data classes the input contains, sorted. */
  readonly classes: readonly DataClass[];
  /** Whether names and domains were replaced by placeholders ("Site A"). */
  readonly pseudonymized: boolean;

  static {
    create = (value, classes, pseudonymized) => new Redacted(SEAL, value, classes, pseudonymized);
  }

  private constructor(seal: symbol, value: T, classes: readonly DataClass[], pseudonymized: boolean) {
    if (seal !== SEAL) throw new TypeError("Redacted values can only be created by the redaction layer.");
    this.#value = value;
    this.classes = Object.freeze([...new Set(classes)].sort());
    this.pseudonymized = pseudonymized;
    Object.freeze(this);
  }

  get value(): T {
    return this.#value;
  }

  /** The input as sent to a model. */
  toJSON(): T {
    return this.#value;
  }
}

/** Internal: wraps redacted data. Not exported from the package. */
export function seal<T>(value: T, classes: readonly DataClass[], pseudonymized = false): Redacted<T> {
  return create(value, classes, pseudonymized);
}

/**
 * Values that must never leave the device (the vault's secrets, the cells
 * of an imported file). Every string a redaction function lets through is
 * checked against it. Memory only, for one request.
 */
export class SecretGuard {
  static readonly MIN_LENGTH = 4;
  readonly #values = new Set<string>();
  readonly #lower = new Set<string>();

  add(value: string | undefined): void {
    const v = value?.trim() ?? "";
    if ([...v].length < SecretGuard.MIN_LENGTH) return;
    this.#values.add(v);
    this.#lower.add(v.toLowerCase());
  }

  addAll(values: Iterable<string | undefined>): void {
    for (const v of values) this.add(v);
  }

  get size(): number {
    return this.#values.size;
  }

  /** Whether `text` equals (ignoring case) or contains one of the values. */
  leaks(text: string): boolean {
    const t = text.trim();
    if (!t) return false;
    if (this.#lower.has(t.toLowerCase())) return true;
    for (const v of this.#values) if (t.includes(v)) return true;
    return false;
  }

  toString(): string {
    return `SecretGuard(${this.#values.size} values)`;
  }

  toJSON(): string {
    return this.toString();
  }
}
