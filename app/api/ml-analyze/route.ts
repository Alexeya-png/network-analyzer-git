// app/api/ml-analyze/route.ts
import { NextResponse } from 'next/server';
import { spawn } from 'child_process';
import path from 'path';

export async function POST(req: Request) {
  try {
    const { features, true_labels } = await req.json();

    // Абсолютные пути
    const script = path.resolve(process.cwd(), 'scripts', 'syn_detector.py');
    const modelPath = path.resolve(process.cwd(), 'scripts', 'rf_model.pkl');
    const pythonCmd = 'python'; // или у вас может быть 'python3', если на сервере

    const result = await new Promise<any>((resolve, reject) => {
      const py = spawn(pythonCmd, [script], {
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';

      py.stdout.on('data', (chunk) => (stdout += chunk.toString()));
      py.stderr.on('data', (chunk) => (stderr += chunk.toString()));

      py.on('close', (code) => {
        if (code !== 0) {
          // возвращаем stderr в теле ответа
          return reject(new Error(stderr || `Exit code ${code}`));
        }
        try {
          resolve(JSON.parse(stdout));
        } catch (err) {
          reject(err);
        }
      });

      // Передаём модель и признаки
      py.stdin.write(
        JSON.stringify({ features, true_labels, model: modelPath })
      );
      py.stdin.end();
    });

    return NextResponse.json(result);
  } catch (err: any) {
    console.error('ml-analyze error:', err);
    // Возвращаем текст ошибки в теле
    return NextResponse.json(
      { error: err.message || 'Unknown error' },
      { status: 500 }
    );
  }
}
