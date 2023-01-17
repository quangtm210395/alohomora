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
          if (grant) {
            request.kauth.grant = grant;
          }
        })
        .then(next)
        .catch(() => {
          keycloak.logger.warn('Middleware.grantAttacher:: Invalid grant! Unauthorized request!');
          return keycloak.unauthorized(request, response, next);
        });
    };
  }
}
