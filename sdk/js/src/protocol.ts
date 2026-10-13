import * as grpc from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import { fileURLToPath } from 'node:url';

// The package carries the repository schema; a test prevents schema drift.
const definition = loadSync(fileURLToPath(new URL('../proto/tunnel.proto', import.meta.url)), {
  keepCase: false, longs: Number, enums: String, defaults: true, oneofs: true,
});
const loaded = grpc.loadPackageDefinition(definition) as unknown as {
  tunn: { v1: { TunnelService: grpc.ServiceClientConstructor } };
};
export const TunnelService = loaded.tunn.v1.TunnelService;
// Dynamic protobuf objects are kept behind the public typed API.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Message = Record<string, any>;
export type Stream = grpc.ClientDuplexStream<Message, Message>;
export const capabilities = ['http-stream-v1', 'connection-stream-v1', 'http-response-trailers-v1'];

export function write(stream: Stream, message: Message, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(new Error('session closed'));
  return new Promise((resolve, reject) => {
    const abort = () => finish(new Error('session closed'));
    let settled = false;
    const finish = (error?: Error | null) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', abort);
      if (error) reject(new Error('session closed')); else resolve();
    };
    signal.addEventListener('abort', abort, { once: true });
    try { stream.write(message, finish); } catch { finish(new Error('session closed')); }
  });
}
