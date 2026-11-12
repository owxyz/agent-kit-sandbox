// Runs in the PR container. Exposes one PR module over stdin/stdout as JSON lines.
// This process holds untrusted code, so nothing here is relied on for security.
import fs from 'node:fs';
import readline from 'node:readline';

// Keep fd 1 for frames, so that PR prints can't corrupt the protocol.
process.stdout.write = process.stderr.write.bind(process.stderr);
const send = (frame) => fs.writeSync(1, `${JSON.stringify(frame)}\n`);

let target;
try {
  target = await import(process.env.HELDOUT_TARGET);
} catch (error) {
  console.error(error);
  process.exit(3);
}
send({ ready: true });

for await (const line of readline.createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  const reply = { id: request.id };
  try {
    const value = await target[request.fn](...(request.args ?? []));
    reply.ok = value === undefined ? null : value;
    JSON.stringify(reply);
  } catch (error) {
    delete reply.ok;
    reply.raise = { type: error?.name ?? 'Error', message: String(error?.message ?? error).slice(0, 2000) };
  }
  send(reply);
}
