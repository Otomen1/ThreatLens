import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

const PROTECTED_PREFIXES = ["/workspace", "/detections", "/cases", "/settings", "/identity"];

export async function proxy(request: NextRequest) {
  if (process.env.NODE_ENV !== "production" && process.env.THREATLENS_E2E_AUTH_BYPASS === "1") {
    return NextResponse.next({ request });
  }
  let response = NextResponse.next({ request });
  const owner = process.env.THREATLENS_OWNER_USER_ID?.trim().toLowerCase();
  if (!owner || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(owner) || !process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY) {
    return new NextResponse("Owner authentication is not configured.", { status: 503, headers: { "Cache-Control": "private, no-store" } });
  }
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
    {
      cookies: {
        getAll: () => request.cookies.getAll(),
        setAll: (cookiesToSet) => {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
          response = NextResponse.next({ request });
          cookiesToSet.forEach(({ name, value, options }) => response.cookies.set(name, value, options));
        },
      },
    },
  );
  const { data: { user } } = await supabase.auth.getUser();
  const protectedRoute = PROTECTED_PREFIXES.some((prefix) => request.nextUrl.pathname.startsWith(prefix));
  if (protectedRoute && !user) {
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = "/login";
    loginUrl.searchParams.set("next", request.nextUrl.pathname);
    return NextResponse.redirect(loginUrl);
  }
  if (protectedRoute && user?.id !== owner) {
    return new NextResponse("This personal workspace is owner-only.", { status: 403, headers: { "Cache-Control": "private, no-store" } });
  }
  return response;
}

export const config = {
  matcher: ["/workspace/:path*", "/detections/:path*", "/cases/:path*", "/settings/:path*", "/identity/:path*"],
};
