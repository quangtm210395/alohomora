import { Request, Response } from 'express';

import { IStore } from '@Lib/stores/IStore';
import { Grant } from '@Lib/Grant';

const TOKEN_KEY = 'keycloak-token';
export class SessionStore implements IStore {
  store: any;
  constructor(store: any) {
    this.store = store;
  }

  get(request: Request & {session: any}) {
    return request.session[TOKEN_KEY];
  }

  clear(sessionId: string) {
    // const self = this;
    this.store.get(sessionId, (err, session) => {
      if (err) {
        console.error(err);
      }
      if (session) {
        delete session[TOKEN_KEY];
        this.store.set(sessionId, session);
      }
    });
  }

  wrap(grant: Grant) {
    grant.store = store(grant);
    grant.unstore = unstore;
  }
}

const store = (grant: Grant) => {
  return (request: Request & {session: any}, response: Response) => {
    request.session[TOKEN_KEY] = grant.__raw;
  };
};

const unstore = (request: Request & {session: any}, response: Response) => {
  delete request.session[TOKEN_KEY];
};
