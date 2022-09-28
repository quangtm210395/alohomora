import { Request, Response } from 'express';

import { IStore } from '@Lib/stores/IStore';
import { Grant } from '@Lib/Grant';

const TOKEN_KEY = 'keycloak-token';
export class CookieStore implements IStore {
  get(request: Request) {
    const value = request.cookies[TOKEN_KEY];
    if (value) {
      try {
        return JSON.parse(value);
      } catch (err) {
      // ignore
      }
    }
  }

  wrap(grant: Grant) {
    grant.store = store(grant);
    grant.unstore = unstore;
  }
}

const store = (grant: Grant) => {
  return (request: Request, response: Response) => {
    response.cookie(TOKEN_KEY, grant.__raw);
  };
};

const unstore = (request: Request, response: Response) => {
  response.clearCookie(TOKEN_KEY);
};

export const cookieStore = new CookieStore();
