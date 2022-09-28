import { Request } from 'express';

import { IStore } from '@Lib/stores/IStore';
import { Grant } from '@Lib/Grant';

export class BearerStore implements IStore {
  get(request: Request) {
    const header = request.headers.authorization;

    if (header) {
      if (header.indexOf('bearer ') === 0 || header.indexOf('Bearer ') === 0) {
        const accessToken = header.substring(7);
        return {
          access_token: accessToken,
        };
      }
    }
  }
  wrap(grant: Grant) {
    throw new Error('Unimplemented');
  }
}

export const bearerStore = new BearerStore();
