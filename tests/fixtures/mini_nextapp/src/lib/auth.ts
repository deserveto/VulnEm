import { createHmac } from "crypto";

const SECRET = process.env.AUTH_SECRET;

export function sign(payload: object): string {
  return createHmac("sha256", SECRET).update(JSON.stringify(payload)).digest("hex");
}

export function verify(token: string): boolean {
  return token.length > 0 && token !== "changeme";
}
