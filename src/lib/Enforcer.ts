import { NextFunction, Request, Response } from 'express';

import { AlohomoraRequest } from '@Lib/AlohomoraRequest';
import { Grant } from '@Lib/Grant';
import { AuthZRequest } from '@Lib/AuthZRequest';
import { AlohomoraConfig } from '@Lib/Alohomora';
import { EnforcerOptions } from '@Lib/EnforcerOptions';
import { Alohomora } from '@Lib/Alohomora';
import { ResponsePermission } from '@Lib/ResponsePermission';
import { Permission } from '@Lib/Permission';
import { ILogger } from '@Lib/logger/ILoggerFactory';

function handlePermissions (permissions: string[], callback: Function) {
  for (let i = 0; i < permissions.length; i++) {
    const expected = permissions[i].split('#');
    const resource = expected[0];
    let scope: string;

    if (expected.length > 1) {
      scope = expected[1];
    }

    const r = callback(resource, scope);

    if (r === false) {
      return r;
    }
  }

  return true;
}

export class Enforcer {
  keycloak: Alohomora;
  config: EnforcerOptions;
  logger: ILogger;
  constructor(alohomora: Alohomora, config?: EnforcerOptions) {
    this.keycloak = alohomora;
    this.config = config || {};

    if (!this.config.response_mode) {
      this.config.response_mode = 'permissions';
    }

    if (!this.config.resource_server_id) {
      this.config.resource_server_id = this.keycloak.getConfig().clientId;
    }

    if (this.keycloak.LoggerFactory) {
      this.logger = this.keycloak.LoggerFactory.create(module);
    } else {
      this.logger = console;
    }
  }

  enforce (requestPermissions?: string[] | string) {
    const keycloak = this.keycloak;
    const config = this.config;
    let expectedPermissions = [];

    if (typeof requestPermissions === 'string') {
      expectedPermissions = [requestPermissions];
    } else {
      expectedPermissions = [].concat(requestPermissions || []);
    }

    return (request: AlohomoraRequest, response: Response, next: NextFunction) => {
      let auth = true;
      // let authz = false;
      if (!expectedPermissions || expectedPermissions.length === 0) {
        expectedPermissions = [];
        if (keycloak.getConfig().jsonEnforcerEnabled) {
          const policyEnforcer = keycloak.getConfig().policyEnforcer;
          if (policyEnforcer.paths && policyEnforcer.paths.length > 0) {
            const path = policyEnforcer.paths.find((p: any) => p.path === request.route.path);
            if (path) {
              if (path.auth === false) {
                auth = false;
              }
              const method = path.methods.find((m: {
                method: string, scopes: string[] | string
              }) => m.method.toLowerCase() === request.method.toLowerCase());
              if (method) {
                expectedPermissions.push(...method.scopes);
                if (method.auth === false) {
                  auth = false;
                }
              }
            }
          }
        }
        if (auth === false) {
          this.logger.info('enforcer:: ignoring authentication for this path: ', request.route.path);
          return next();
        }
      }

      const authzRequest: AuthZRequest = {
        audience: config.resource_server_id,
        response_mode: config.response_mode,
      };

      handlePermissions(expectedPermissions, (resource: string, scope: string) => {
        if (!authzRequest.permissions) {
          authzRequest.permissions = [];
        }

        const permission: Permission = { id: resource };

        if (scope) {
          permission.scopes = [scope];
        }

        authzRequest.permissions.push(permission);
      });

      if (request.kauth && request.kauth.grant) {
        if (handlePermissions(expectedPermissions, (resource: string, scope: string) => {
          if (!request.kauth.grant.access_token.hasPermission(resource, scope)) {
            return false;
          }
        })) {
          return next();
        }
      }

      if (config.claims) {
        const claims = config.claims(request);

        if (claims) {
          authzRequest.claim_token = Buffer.from(JSON.stringify(claims)).toString('base64');
          authzRequest.claim_token_format = 'urn:ietf:params:oauth:token-type:jwt';
        }
      }

      if (config.response_mode === 'permissions') {
        return keycloak.checkPermissions(authzRequest, request, response, (permissions: ResponsePermission[]) => {
          this.logger.info('enforce:: checkPermission response: ', permissions);
          if (handlePermissions(expectedPermissions, (resource: string, scope: string) => {
            if (!permissions || permissions.length === 0) {
              return false;
            }

            for (let j = 0; j < permissions.length; j++) {
              const permission = permissions[j];

              if (permission.rsid === resource || permission.rsname === resource) {
                if (scope) {
                  if (permission.scopes && permission.scopes.length > 0) {
                    if (!permission.scopes.includes(scope)) {
                      return false;
                    }
                    break;
                  }
                  return false;
                }
              }
            }
          })) {
            request.permissions = permissions;
            return next();
          }

          return keycloak.accessDenied(request, response, next);
        }).catch((error) => {
          this.logger.error('enforce:: pers checkPermission:: error ', error.message, error);
          if (error.message === 'No bearer in header') {
            return keycloak.unauthorized(request, response, next);
          }
          return keycloak.accessDenied(request, response, next);
        });
      } else if (config.response_mode === 'token') {
        authzRequest.response_mode = undefined;
        return keycloak.checkPermissions(authzRequest, request, response).then((grant: Grant) => {
          if (handlePermissions(expectedPermissions, (resource: string, scope: string) => {
            if (!grant.access_token.hasPermission(resource, scope)) {
              return false;
            }
          })) {
            return next();
          }

          return keycloak.accessDenied(request, response, next);
        }).catch((error) => {
          this.logger.error('enforce:: token checkPermission:: error ', error.message, error);
          if (error.message === 'No bearer in header') {
            return keycloak.unauthorized(request, response, next);
          }
          return keycloak.accessDenied(request, response, next);
        });
      }
    };
  }
}
