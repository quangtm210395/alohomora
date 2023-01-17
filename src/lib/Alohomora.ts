import { NextFunction, Request, Response } from 'express';

import { EnforcerOptions } from '@Lib/EnforcerOptions';
import { AuthZRequest } from '@Lib/AuthZRequest';
import { IStore } from '@Lib/stores/IStore';
import { Config } from '@Lib/Config';
import { GrantManager } from '@Lib/GrantManager';
import { bearerStore } from '@Lib/stores/BearerStore';
import { SessionStore } from '@Lib/stores/SessionStore';
import { cookieStore } from '@Lib/stores/CookieStore';
import { Grant } from '@Lib/Grant';
import { Middlewares } from '@Lib/Middlewares';
import { Enforcer } from '@Lib/Enforcer';
import { AlohomoraRequest } from '@Lib/AlohomoraRequest';
import { ILogger, ILoggerFactory } from '@Lib/logger/ILoggerFactory';

export interface AlohomoraConfig {
  realm: string;
  authServerUrl: string;
  bearerOnly: boolean;
  jsonEnforcerEnabled: boolean;
  clientId: string;
  secret: string;
}
export interface AlohomoraOptions {
  scope?: string
  store?: any
  cookies?: boolean
  accessDenied?: (request: AlohomoraRequest, response: Response) => void
  unauthorized?: (request: AlohomoraRequest, response: Response) => void
  LoggerFactory?: ILoggerFactory;
}

export class Alohomora {
  config: Config;
  grantManager: GrantManager;
  stores: IStore[];
  accessDenied: (request: Request, response: Response, next?: NextFunction) => void;
  unauthorized: (request: Request, response: Response, next?: NextFunction) => void;
  logger: ILogger;
  LoggerFactory?: ILoggerFactory;
  constructor(options: AlohomoraOptions, alohomoraConfig?: AlohomoraConfig) {
    // If keycloakConfig is null, Config() will search for `keycloak.json`.
    this.config = new Config(alohomoraConfig);

    this.grantManager = new GrantManager(this.config);

    if (options?.LoggerFactory) {
      this.LoggerFactory = options.LoggerFactory;
      this.logger = options.LoggerFactory.create(module);
    } else {
      this.logger = console;
    }

    if (options && options.store && options.cookies) {
      throw new Error('Either `store` or `cookies` may be set, but not both');
    }

    this.stores = [bearerStore];

    if (options && options.store) {
      this.stores.push(new SessionStore(options.store));
    } else if (options && options.cookies) {
      this.stores.push(cookieStore);
    }

    if (options.accessDenied) {
      this.accessDenied = options.accessDenied;
    } else {
      this.accessDenied = (request: Request, response: Response) => {
        response.status(403).send('Access Denied');
      };
    }

    if (options.unauthorized) {
      this.unauthorized = options.unauthorized;
    } else {
      this.unauthorized = (request: Request, response: Response) => {
        response.status(401).send('Unauthorized');
      };
    }
  }

  init() {
    return [
      Middlewares.setup,
      Middlewares.grantAttacher(this),
    ];
  }

  enforce(requestPermissions?: string[] | string, options?: EnforcerOptions) {
    return new Enforcer(this, options).enforce(requestPermissions);
  }

  async getGrant (request: Request, response: Response) {
    let rawData: any;

    for (let i = 0; i < this.stores.length; ++i) {
      rawData = this.stores[i].get(request);
      if (rawData) {
      // store = this.stores[i];
        break;
      }
    }

    let grantData = rawData;
    if (typeof (grantData) === 'string') {
      grantData = JSON.parse(grantData);
    }

    if (grantData && !grantData.error) {
      return this.grantManager.createGrant(JSON.stringify(grantData))
        .then(grant => {
          this.storeGrant(grant, request, response);
          return grant;
        })
        .catch(() => { return Promise.reject(new Error('Could not store grant code error')); });
    }
    return Promise.resolve(null);
    // return Promise.reject(new Error('Could not obtain grant code error'));
  }

  storeGrant (grant: Grant, request: Request, response: Response) {
    if (this.stores.length < 2 || bearerStore.get(request)) {
    // cannot store bearer-only, and should not store if grant is from the
    // authorization header
      return;
    }
    if (!grant) {
      this.unauthorized(request, response);
      return;
    }

    this.stores[1].wrap(grant);
    grant.store(request, response);
    return grant;
  }

  async checkPermissions(authzRequest: AuthZRequest, request: AlohomoraRequest, response: Response,
    callback?: Function) {
    return this.grantManager.obtainPermissions(authzRequest, request, callback)
      .then((grant) => {
        this.logger.info('checkPermissions:: response data ', grant);
        if (!authzRequest.response_mode) {
          this.storeGrant(grant, request, response);
        }
        return grant;
      });
  }

  public getConfig() {
    return this.config;
  }
}
