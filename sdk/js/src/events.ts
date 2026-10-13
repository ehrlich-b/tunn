import type { TunnelError } from './options.js';
export type State = 'connecting' | 'ready' | 'reconnecting' | 'failed' | 'closed';
export interface Event {
  readonly state: State;
  readonly url?: string;
  readonly error?: TunnelError;
  readonly retryDelayMs?: number;
}
/** Bounded single-consumer iterator; lifecycle producers never wait for readers. */
export class Events implements AsyncIterableIterator<Event> {
  #queue: Event[] = [];
  #pending?: (result: IteratorResult<Event>) => void;
  #closed = false;
  push(event: Event): void {
    if (this.#closed) return;
    if (this.#pending) {
      const resolve = this.#pending; this.#pending = undefined;
      resolve({ done: false, value: event });
    } else {
      if (this.#queue.length === 16) this.#queue.shift();
      this.#queue.push(event);
    }
    if (event.state === 'closed') this.#closed = true;
  }
  next(): Promise<IteratorResult<Event>> {
    const value = this.#queue.shift();
    if (value) return Promise.resolve({ done: false, value });
    if (this.#closed) return Promise.resolve({ done: true, value: undefined });
    if (this.#pending) return Promise.reject(new Error('tunn: events require one consumer'));
    return new Promise(resolve => { this.#pending = resolve; });
  }
  [Symbol.asyncIterator](): AsyncIterableIterator<Event> { return this; }
}
