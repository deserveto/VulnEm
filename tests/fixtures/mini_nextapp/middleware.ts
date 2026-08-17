import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Route protection gate — auth keyword match lead for the source map.
export function middleware(request: NextRequest) {
  const token = request.cookies.get("session")?.value;
  if (!token && request.nextUrl.pathname.startsWith("/dashboard")) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
