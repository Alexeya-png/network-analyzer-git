import { NextResponse } from "next/server";
import { spawn }        from "child_process";
import os   from "os";
import path from "path";

export async function POST(req: Request) {
  try {
    const body = await req.json();                         // { features, true_labels? }
    const payload = JSON.stringify(body);

    // cross-platform python command
    const pyCmd = os.platform().startsWith("win") ? "python" : "python3";
    const script = path.resolve(process.cwd(), "scripts", "run_ml.py");

    const data = await new Promise<string>((res, rej) => {
      const p = spawn(pyCmd, [script]);
      let out = "", err = "";

      p.stdout.on("data", c => out += c);
      p.stderr.on("data", c => err += c);
      p.on("close", code => {
        if (code !== 0) return rej(new Error(err || `exit ${code}`));
        res(out);
      });

      p.stdin.write(payload);
      p.stdin.end();
    });

    return NextResponse.json(JSON.parse(data));
  } catch (e: any) {
    console.error("[ml-analyze] error:", e);
    return NextResponse.json({ error: e.message || "ML error" }, { status: 500 });
  }
}
