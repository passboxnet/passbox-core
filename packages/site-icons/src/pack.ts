/**
 * The atlas pack format of the bundled website icons (written by
 * scripts/update-site-icons.mjs). Little endian, version 1:
 *
 *   "PBIA" | u8 version | u8 tile size (px) | u16 columns | u32 count | u32 image offset
 *   count × ( u8 domain length | domain (ASCII) ), sorted by domain
 *   one WebP image with every icon: the n-th domain's tile is at column
 *   n % columns, row ⌊n / columns⌋
 *
 * One image for all icons compresses to less than half of one file per icon.
 */

export interface AtlasPack {
  /** Tile size in pixels (32 or 64). */
  size: number;
  columns: number;
  /** Tile number by domain. */
  tiles: Map<string, number>;
  /** The WebP atlas. */
  image: Uint8Array<ArrayBuffer>;
}

const MAGIC = "PBIA";

/** Reads an atlas pack. Throws for anything that is not one. */
export function parseAtlas(data: ArrayBuffer | Uint8Array): AtlasPack {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.byteLength < 16 || String.fromCharCode(...bytes.subarray(0, 4)) !== MAGIC) {
    throw new Error("not a website icon pack");
  }
  if (view.getUint8(4) !== 1) throw new Error("unsupported website icon pack version");
  const size = view.getUint8(5);
  const columns = view.getUint16(6, true);
  const count = view.getUint32(8, true);
  const imageOffset = view.getUint32(12, true);
  if (!size || !columns || imageOffset > bytes.byteLength) throw new Error("corrupt website icon pack");
  const tiles = new Map<string, number>();
  let at = 16;
  for (let n = 0; n < count; n++) {
    const length = view.getUint8(at);
    if (at + 1 + length > imageOffset) throw new Error("corrupt website icon pack");
    tiles.set(String.fromCharCode(...bytes.subarray(at + 1, at + 1 + length)), n);
    at += 1 + length;
  }
  return { size, columns, tiles, image: bytes.slice(imageOffset) };
}

/** Where a tile is in the atlas, in pixels. */
export function tilePosition(pack: AtlasPack, tile: number): { x: number; y: number } {
  return { x: (tile % pack.columns) * pack.size, y: Math.floor(tile / pack.columns) * pack.size };
}
