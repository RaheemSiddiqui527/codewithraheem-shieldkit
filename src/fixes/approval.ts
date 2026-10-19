import readline from 'node:readline';

export async function promptUserApproval(question: string): Promise<boolean> {
  // If stdin is not a TTY (running in CI, script, or non-interactive pipe), reject automatically
  if (!process.stdin.isTTY) {
    return false;
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise<boolean>((resolve) => {
    rl.question(`${question} (y/N): `, (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      resolve(normalized === 'y' || normalized === 'yes');
    });
  });
}
