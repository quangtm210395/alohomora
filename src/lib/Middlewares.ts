import { NextFunction, Response } from 'express';

import { Grant } from '@Lib/Grant';
import { AlohomoraRequest } from '@Lib/AlohomoraRequest';
import { Alohomora } from '@Lib/Alohomora';

export class Middlewares {
  static setup (request: AlohomoraRequest, response: Response, next: NextFunction) {
    request.kauth = {};
    next();
  }

  static grantAttacher (keycloak: Alohomora) {
    return (request: AlohomoraRequest, response: Response, next: NextFunction) => {
      keycloak.getGrant(request, response)
        .then((grant: Grant) => {
          request.kauth.grant = grant;
        })
        .then(next)
        .catch(() => next());
    };
  }
}
