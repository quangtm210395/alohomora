import { parse, URLSearchParams } from 'url';
import http from 'http';
import https from 'https';
import { createVerify } from 'crypto';

import { Grant } from '@Lib/Grant';
import { Token } from '@Lib/Token';
import { Rotation } from '@Lib/Rotation';
import { Config } from '@Lib/Config';
import { RequestOptions } from '@Lib/RequestOptions';
import { AlohomoraRequest } from '@Lib/AlohomoraRequest';
import { AuthZRequest } from '@Lib/AuthZRequest';

export class GrantManager {
  realmUrl: string;
  clientId: string;
  secret: string;
  publicKey: string;
  public: boolean;
  bearerOnly: boolean;
  notBefore = 0;
  rotation: Rotation;
  verifyTokenAudience: boolean;

  constructor(config: Config) {
    this.realmUrl = config.realmUrl;
    this.clientId = config.clientId;
    this.secret = config.secret;
    this.publicKey = config.publicKey;
    this.public = config.public;
    this.bearerOnly = config.bearerOnly;
    this.rotation = new Rotation(config);
    this.verifyTokenAudience = config.verifyTokenAudience;
  }

  /**
   * Use the direct grant API to obtain a grant from Keycloak.
   *
   * The direct grant API must be enabled for the configured realm
   * for this method to work. This function ostensibly provides a
   * non-interactive, programatic way to login to a Keycloak realm.
   *
   * This method can either accept a callback as the last parameter
   * or return a promise.
   *
   * @param username The username.
   * @param password The cleartext password.
   * @param callback Optional callback, if not using promises.
   */
  obtainDirectly (username: string, password: string,
    callback: Function, scopeParam: string) {
    const params = {
      client_id: this.clientId,
      username,
      password,
      grant_type: 'password',
      scope: scopeParam || 'openid',
    };
    const handler = createHandler(this);
    const options = postOptions(this);
    return nodeify(fetch(handler, options, params), callback);
  }

  /**
   * Obtain a grant from a previous interactive login which results in a code.
   *
   * This is typically used by servers which receive the code through a
   * redirect_uri when sending a user to Keycloak for an interactive login.
   *
   * An optional session ID and host may be provided if there is desire for
   * Keycloak to be aware of this information.  They may be used by Keycloak
   * when session invalidation is triggered from the Keycloak console itself
   * during its postbacks to `/k_logout` on the server.
   *
   * This method returns or promise or may optionally take a callback function.
   *
   * @param {String} code The code from a successful login redirected from Keycloak.
   * @param {String} sessionId Optional opaque session-id.
   * @param {String} sessionHost Optional session host for targetted Keycloak console post-backs.
   * @param {Function} callback Optional callback, if not using promises.
   */
  obtainFromCode (request: AlohomoraRequest, code: string, sessionId: string, sessionHost: string, callback: Function) {
    const params = {
      client_session_state: sessionId,
      client_session_host: sessionHost,
      code,
      grant_type: 'authorization_code',
      client_id: this.clientId,
      redirect_uri: (request as any).session ? (request as any).session.auth_redirect_uri : {},
    };
    const handler = createHandler(this);
    const options = postOptions(this);

    return nodeify(fetch(handler, options, params), callback);
  }

  /**
   * obtain the permissions from the keycloak server
   * @param authzRequest the authz request data
   * @param request the express request object
   * @param callback
   * @returns
   */
  obtainPermissions (authzRequest: AuthZRequest, request: AlohomoraRequest, callback?: Function) {
    const params: any = {
      grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
    };

    if (authzRequest.audience) {
      params.audience = authzRequest.audience;
    } else {
      params.audience = this.clientId;
    }

    if (authzRequest.response_mode) {
      params.response_mode = authzRequest.response_mode;
    }

    if (authzRequest.claim_token) {
      params.claim_token = authzRequest.claim_token;
      params.claim_token_format = authzRequest.claim_token_format;
    }

    const options = postOptions(this);

    if (this.public) {
      if (request.kauth && request.kauth.grant && request.kauth.grant.access_token) {
        options.headers.Authorization = 'Bearer ' + request.kauth.grant.access_token.token;
      }
    } else {
      const header = request.headers.authorization;
      let bearerToken: string;

      if (header && (header.indexOf('bearer ') === 0 || header.indexOf('Bearer ') === 0)) {
        bearerToken = header.substring(7);
      }

      if (!bearerToken) {
        if (request.kauth && request.kauth.grant && request.kauth.grant.access_token) {
          bearerToken = request.kauth.grant.access_token.token;
        } else {
          return Promise.reject(new Error('No bearer in header'));
        }
      }

      params.subject_token = bearerToken;
    }

    let permissions = authzRequest.permissions;

    if (!permissions) {
      permissions = [];
    }

    for (let i = 0; i < permissions.length; i++) {
      const resource = permissions[i];
      let permission = resource.id;

      if (resource.scopes && resource.scopes.length > 0) {
        permission += '#';

        for (let j = 0; j < resource.scopes.length; j++) {
          const scope = resource.scopes[j];
          if (permission.indexOf('#') !== permission.length - 1) {
            permission += ',';
          }
          permission += scope;
        }
      }

      if (!params.permission) {
        params.permission = [];
      }

      params.permission.push(permission);
    }

    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const manager = this;

    const handler = (resolve, reject, json) => {
      try {
        if (authzRequest.response_mode === 'decision' || authzRequest.response_mode === 'permissions') {
          if (callback) {
            callback(JSON.parse(json));
          }
        } else {
          resolve(manager.createGrant(json));
        }
      } catch (err) {
        reject(err);
      }
    };

    return nodeify(fetch(handler, options, params));
  }

  /**
   * Ensure that a grant is *fresh*, refreshing if required & possible.
   *
   * If the access_token is not expired, the grant is left untouched.
   *
   * If the access_token is expired, and a refresh_token is available,
   * the grant is refreshed, in place (no new object is created),
   * and returned.
   *
   * If the access_token is expired and no refresh_token is available,
   * an error is provided.
   *
   * The method may either return a promise or take an optional callback.
   *
   * @param {Grant} grant The grant object to ensure freshness of.
   * @param {Function} callback Optional callback if promises are not used.
   */
  ensureFreshness (grant: Grant, callback?: Function) {
    if (!grant.isExpired()) {
      return nodeify(Promise.resolve(grant), callback);
    }

    if (!grant.refresh_token) {
      return nodeify(Promise.reject(new Error('Unable to refresh without a refresh token')), callback);
    }

    if (grant.refresh_token.isExpired()) {
      return nodeify(Promise.reject(new Error('Unable to refresh with expired refresh token')), callback);
    }

    const params = {
      grant_type: 'refresh_token',
      refresh_token: grant.refresh_token.token,
      client_id: this.clientId,
    };
    const handler = refreshHandler(this);
    const options = postOptions(this);

    return nodeify(fetch(handler, options, params), callback);
  }

  /**
   * Perform live validation of an `access_token` against the Keycloak server.
   *
   * @param token The token to validate.
   * @param  callback Callback function if not using promises.
   *
   * @return `false` if the token is invalid, or the same token if valid.
   */
  async validateAccessToken (token: Token | string, callback: Function): Promise<boolean> {
    let t = token;
    if (typeof token === 'object') {
      t = token.token;
    }
    const params = {
      token: t,
      client_secret: this.secret,
      client_id: this.clientId,
    };
    const options = postOptions(this, '/protocol/openid-connect/token/introspect');
    const handler = validationHandler(token);

    return nodeify(fetch(handler, options, params), callback);
  }

  /**
   * Get the user info from the server.
   *
   * @param token The token to validate.
   * @param callback Callback function if not using promises.
   *
   * @return `false` if the token is invalid, or the same token if valid.
   */
  userInfo (token: Token | string, callback: Function) {
    const url = this.realmUrl + '/protocol/openid-connect/userinfo';
    const options: RequestOptions = parse(url); // eslint-disable-line
    options.method = 'GET';

    let t = token;
    if (typeof token === 'object') t = token.token;

    options.headers = {
      Authorization: 'Bearer ' + t,
      Accept: 'application/json',
      'X-Client': 'keycloak-nodejs-connect',
    };

    const promise = new Promise((resolve, reject) => {
      const req = getProtocol(options).request(options, (response) => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          return reject(new Error('Error fetching account'));
        }
        let json = '';
        response.on('data', (d) => (json += d.toString()));
        response.on('end', () => {
          const data = JSON.parse(json);
          if (data.error) reject(data);
          else resolve(data);
        });
      });
      req.on('error', reject);
      req.end();
    });

    return nodeify(promise, callback);
  }

  isGrantRefreshable (grant: Grant) {
    return !this.bearerOnly && (grant && grant.refresh_token);
  }

  /**
   * Create a `Grant` object from a string of JSON data.
   *
   * This method creates the `Grant` object, including
   * the `access_token`, `refresh_token` and `id_token`
   * if available, and validates each for expiration and
   * against the known public-key of the server.
   *
   * @param {String} rawData The raw JSON string received from the Keycloak server or from a client.
   * @return {Promise} A promise reoslving a grant.
   */
  async createGrant (rawData: string | any): Promise<any> {
    let grantData = rawData;
    if (typeof rawData !== 'object') grantData = JSON.parse(grantData);

    const grant = new Grant({
      access_token: (grantData.access_token ? new Token(grantData.access_token, this.clientId) : undefined),
      refresh_token: (grantData.refresh_token ? new Token(grantData.refresh_token) : undefined),
      id_token: (grantData.id_token ? new Token(grantData.id_token) : undefined),
      expires_in: grantData.expires_in,
      token_type: grantData.token_type,
      __raw: rawData,
    });
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    // const manager = this;
    if (this.isGrantRefreshable(grant)) {
      return new Promise((resolve, reject) => {
        this.ensureFreshness(grant)
          .then(g => this.validateGrant(g))
          .then(g => resolve(g))
          .catch(err => reject(err));
      });
    } else {
      return this.validateGrant(grant);
    }
  }
  /**
   * Validate the grant and all tokens contained therein.
   *
   * This method examines a grant (in place) and rejects
   * if any of the tokens are invalid. After this method
   * resolves, the passed grant is guaranteed to have
   * valid tokens.
   *
   * @param grant: The grant to validate.
   *
   * @return That resolves to a validated grant or
   * rejects with an error if any of the tokens are invalid.
   */
  validateGrant (grant: Grant) {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    // const self = this;
    const validateGrantToken = (grant: Grant, tokenName: string, expectedType: string) => {
      return new Promise((resolve, reject) => {
      // check the access token
        this.validateToken(grant[tokenName], expectedType).then(token => {
          grant[tokenName] = token;
          resolve(null);
        }).catch((err) => {
          reject(new Error('Grant validation failed. Reason: ' + err.message));
        });
      });
    };
    return new Promise((resolve, reject) => {
      const promises = [];
      promises.push(validateGrantToken(grant, 'access_token', 'Bearer'));
      if (!this.bearerOnly) {
        if (grant.id_token) {
          promises.push(validateGrantToken(grant, 'id_token', 'ID'));
        }
      }
      Promise.all(promises).then(() => {
        resolve(grant);
      }).catch((err) => {
        reject(new Error(err.message));
      });
    });
  }

  /**
   * Validate a token.
   *
   * This method accepts a token, and returns a promise
   *
   * If the token is valid the promise will be resolved with the token
   *
   * If the token is undefined or fails validation an applicable error is returned
   *
   * @return That resolve a token
   */
  validateToken (token: Token, expectedType: string) {
    return new Promise((resolve, reject) => {
      if (!token) {
        reject(new Error('invalid token (missing)'));
      } else if (token.isExpired()) {
        reject(new Error('invalid token (expired)'));
      } else if (!token.signed) {
        reject(new Error('invalid token (not signed)'));
      } else if (token.content.typ !== expectedType) {
        reject(new Error('invalid token (wrong type)'));
      } else if (token.content.iat < this.notBefore) {
        reject(new Error('invalid token (stale token)'));
      } else if (token.content.iss !== this.realmUrl) {
        reject(new Error('invalid token (wrong ISS)'));
      } else {
        const audienceData = Array.isArray(token.content.aud) ? token.content.aud : [token.content.aud];
        if (expectedType === 'ID') {
          if (!audienceData.includes(this.clientId)) {
            reject(new Error('invalid token (wrong audience)'));
          }
          if (token.content.azp && token.content.azp !== this.clientId) {
            reject(new Error('invalid token (authorized party should match client id)'));
          }
        } else if (this.verifyTokenAudience) {
          if (!audienceData.includes(this.clientId)) {
            reject(new Error('invalid token (wrong audience)'));
          }
        }
        const verify = createVerify('RSA-SHA256');
        // if public key has been supplied use it to validate token
        if (this.publicKey) {
          try {
            verify.update(token.signed);
            if (!verify.verify(this.publicKey, token.signature.toString(), 'base64')) {
              reject(new Error('invalid token (signature)'));
            } else {
              resolve(token);
            }
          } catch (err) {
            reject(new Error('Misconfigured parameters while validating token. Check your keycloak.json file!'));
          }
        } else {
          // retrieve public KEY and use it to validate token
          this.rotation.getJWK(token.header.kid).then((key: string) => {
            verify.update(token.signed);
            if (!verify.verify(key, token.signature)) {
              reject(new Error('invalid token (public key signature)'));
            } else {
              resolve(token);
            }
          }).catch((err) => {
            reject(new Error('failed to load public key to verify token. Reason: ' + err.message));
          });
        }
      }
    });
  }
}

const getProtocol = (opts: RequestOptions) => {
  return opts.protocol === 'https:' ? https : http;
};

const nodeify = async (promise: Promise<any>, cb?: Function) => {
  if (typeof cb !== 'function') return promise;
  return promise.then((res) => cb(null, res)).catch((err) => cb(err));
};

const createHandler = (manager: GrantManager) => (resolve, reject, json) => {
  try {
    resolve(manager.createGrant(json));
  } catch (err) {
    reject(err);
  }
};

const refreshHandler = (manager) => (resolve, reject, json) => {
  manager.createGrant(json)
    .then((grant) => resolve(grant))
    .catch((err) => reject(err));
};

const validationHandler = (token) => (resolve, reject, json) => {
  const data = JSON.parse(json);
  if (!data.active) resolve(false);
  else resolve(token);
};

const postOptions = (manager: GrantManager, path = '/protocol/openid-connect/token') => {
  const realPath = path;
  const opts: RequestOptions = parse(manager.realmUrl + realPath);
  opts.headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Client': 'keycloak-nodejs-connect',
  };
  if (!manager.public) {
    opts.headers.Authorization = 'Basic ' + Buffer.from(manager.clientId + ':' + manager.secret).toString('base64');
  }
  opts.method = 'POST';
  return opts;
};

const fetch = (handler, options, params) => {
  return new Promise((resolve, reject) => {
    const data = (typeof params === 'string' ? params : new URLSearchParams(params).toString());
    options.headers['Content-Length'] = data.length;

    const req = getProtocol(options).request(options, (response) => {
      if (response.statusCode < 200 || response.statusCode > 299) {
        return reject(new Error(response.statusCode + ':' + http.STATUS_CODES[response.statusCode]));
      }
      let json = '';
      response.on('data', (d) => (json += d.toString()));
      response.on('end', () => {
        handler(resolve, reject, json);
      });
    });

    req.write(data);
    req.on('error', reject);
    req.end();
  });
};
