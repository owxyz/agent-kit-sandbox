// Test-side client. Held-out tests call PR code only through target().
//   const { lineTotal } = target();
// Calls are synchronous. Arguments and results are plain JSON. A PR exception is
// rethrown as an Error whose name is the name the PR side reported.
import fs from 'node:fs';

const RPC_IN = 3;
const RPC_OUT = 4;
let buffered = Buffer.alloc(0);

function readLine() {
  const chunk = Buffer.alloc(65536);
  for (;;) {
    const index = buffered.indexOf(10);
    if (index >= 0) {
      const line = buffered.subarray(0, index).toString();
      buffered = buffered.subarray(index + 1);
      return line;
    }
    let count;
    try {
      count = fs.readSync(RPC_IN, chunk, 0, chunk.length, null);
    } catch (error) {
      if (error.code === 'EAGAIN') continue;
      throw error;
    }
    if (count === 0) throw new Error('broker closed the channel');
    buffered = Buffer.concat([buffered, chunk.subarray(0, count)]);
  }
}

export function call(fn, args) {
  fs.writeSync(RPC_OUT, `${JSON.stringify({ fn, args })}\n`);
  const reply = JSON.parse(readLine());
  if ('fatal' in reply) throw new Error(`adapter gone: ${reply.fatal}`);
  if ('raise' in reply) {
    const error = new Error(reply.raise.message);
    error.name = reply.raise.type;
    throw error;
  }
  return reply.ok;
}

export function target() {
  return new Proxy({}, { get: (_, name) => (...args) => call(String(name), args) });
}
