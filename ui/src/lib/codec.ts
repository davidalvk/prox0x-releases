export type CodecMode =
  | "url-encode"
  | "url-decode"
  | "base64-encode"
  | "base64-decode"
  | "hex-encode"
  | "hex-decode"
  | "md5"
  | "sha1"
  | "sha256"
  | "json-pretty";

const MD5_SHIFTS = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5,
  9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11,
  16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10,
  15, 21,
];

const MD5_CONSTANTS = Array.from(
  { length: 64 },
  (_, index) => Math.floor(Math.abs(Math.sin(index + 1)) * 0x100000000) >>> 0,
);

function rotateLeft(value: number, bits: number): number {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

/** MD5 sobre UTF-8, en hexadecimal minúsculas (Web Crypto no lo incluye). */
export function md5Hex(text: string): string {
  const bytes = new TextEncoder().encode(text);
  const bitLength = bytes.length * 8;
  const paddedLength = (((bytes.length + 8) >> 6) + 1) * 64;
  const buffer = new Uint8Array(paddedLength);
  buffer.set(bytes);
  buffer[bytes.length] = 0x80;

  const view = new DataView(buffer.buffer);
  view.setUint32(paddedLength - 8, bitLength >>> 0, true);
  view.setUint32(paddedLength - 4, Math.floor(bitLength / 0x100000000), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  for (let offset = 0; offset < paddedLength; offset += 64) {
    const words: number[] = [];
    for (let index = 0; index < 16; index += 1) {
      words.push(view.getUint32(offset + index * 4, true));
    }

    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;

    for (let index = 0; index < 64; index += 1) {
      let mixed: number;
      let wordIndex: number;
      if (index < 16) {
        mixed = (b & c) | (~b & d);
        wordIndex = index;
      } else if (index < 32) {
        mixed = (d & b) | (~d & c);
        wordIndex = (5 * index + 1) % 16;
      } else if (index < 48) {
        mixed = b ^ c ^ d;
        wordIndex = (3 * index + 5) % 16;
      } else {
        mixed = c ^ (b | ~d);
        wordIndex = (7 * index) % 16;
      }

      const rotated = (a + mixed + MD5_CONSTANTS[index] + words[wordIndex]) >>> 0;
      const nextB = (b + rotateLeft(rotated, MD5_SHIFTS[index])) >>> 0;
      a = d;
      d = c;
      c = b;
      b = nextB;
    }

    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  return [a0, b0, c0, d0]
    .map((word) => {
      let hex = "";
      for (let byte = 0; byte < 4; byte += 1) {
        hex += ((word >>> (byte * 8)) & 0xff).toString(16).padStart(2, "0");
      }
      return hex;
    })
    .join("");
}

export function base64Encode(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function base64Decode(text: string): string {
  const clean = text
    .trim()
    .replace(/\s+/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const padded = clean.padEnd(Math.ceil(clean.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

export function hexEncode(text: string): string {
  return Array.from(new TextEncoder().encode(text), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export function hexDecode(text: string): string {
  const clean = text
    .trim()
    .replace(/^0x/i, "")
    .replace(/[\s:_-]/g, "");
  if (clean.length === 0) return "";
  if (!/^[0-9a-f]+$/i.test(clean)) {
    throw new Error("Hex inválido: solo se admiten dígitos 0-9 y A-F.");
  }
  if (clean.length % 2 !== 0) {
    throw new Error("Hex inválido: el número de dígitos debe ser par.");
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16);
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

async function shaHex(algorithm: "SHA-1" | "SHA-256", text: string): Promise<string> {
  const digest = await crypto.subtle.digest(algorithm, new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export async function transform(mode: CodecMode, input: string): Promise<string> {
  if (input === "") return "";
  switch (mode) {
    case "url-encode":
      return encodeURIComponent(input);
    case "url-decode":
      return decodeURIComponent(input);
    case "base64-encode":
      return base64Encode(input);
    case "base64-decode":
      return base64Decode(input);
    case "hex-encode":
      return hexEncode(input);
    case "hex-decode":
      return hexDecode(input);
    case "md5":
      return md5Hex(input);
    case "sha1":
      return shaHex("SHA-1", input);
    case "sha256":
      return shaHex("SHA-256", input);
    case "json-pretty":
      return JSON.stringify(JSON.parse(input), null, 2);
    default:
      return input;
  }
}
