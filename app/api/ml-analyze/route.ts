// app/api/ml-analyze/route.ts
import { NextResponse } from 'next/server';
import { spawn } from 'child_process';
import os from 'os';
import path from 'path';

export async function POST(request: Request) {
  try {
    const { features, true_labels } = await request.json();
    const payload = JSON.stringify({ features, true_labels });

    // 1) Определяем команду python
    const pythonCmd = os.platform().startsWith('win') ? 'python' : 'python3';

    // 2) Абсолютный путь до run_ml.py
    const scriptPath = path.resolve(process.cwd(), 'scripts', 'run_ml.py');

    // 3) Запускаем скрипт
    const result: any = await new Promise((resolve, reject) => {
      const py = spawn(pythonCmd, [scriptPath], { stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';

      py.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
      py.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

      py.on('close', (code) => {
        if (code !== 0) {
          console.error('[run_ml.py] exited with', code, 'stderr:', stderr);
          return reject(new Error(`ML script failed (code ${code}): ${stderr.trim()}`));
        }
        try {
          resolve(JSON.parse(stdout));
        } catch (err) {
          console.error('[run_ml.py] JSON parse error:', err, 'stdout:', stdout);
          reject(err);
        }
      });

      py.stdin.write(payload);
      py.stdin.end();
    });

    return NextResponse.json(result);

  } catch (err: any) {
    console.error('[ml-analyze] error:', err.message ?? err);
    return NextResponse.json(
      { error: err.message ?? 'Internal Server Error' },
      { status: 500 }
    );
  }
}
