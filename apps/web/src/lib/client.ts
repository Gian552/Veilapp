// The only place the concrete engine is constructed. The rest of the app
// depends solely on the VeilClientApi interface (via React context).
import { IndexedDbStorage, VeilClient } from '@veil/client';
import type { VeilClientApi } from '@veil/client';

export function createClient(): VeilClientApi {
  return new VeilClient({ baseUrl: window.location.origin, storage: new IndexedDbStorage() });
}
