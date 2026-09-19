import type { PasswordRangeResponse } from "./api";

type RangeLookup = (prefix: string) => Promise<PasswordRangeResponse>;

async function sha1(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

export async function checkPasswordExposure(
  password: string,
  lookup: RangeLookup,
): Promise<number> {
  const hash = await sha1(password);
  const range = await lookup(hash.slice(0, 5));
  const match = range.suffixes.find((item) => item.suffix === hash.slice(5));
  return match?.count ?? 0;
}
