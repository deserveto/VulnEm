import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const form = await request.formData();
  const file = form.get("file") as File | null;
  if (!file) {
    return NextResponse.json({ error: "no file" }, { status: 400 });
  }
  return NextResponse.json({ size: file.size }, { status: 201 });
}
