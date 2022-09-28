import { parse, UrlWithStringQuery } from 'url';
import http from 'http';
import https from 'https';

import jwkToPem from 'jwk-to-pem';

import { Config } from '@Lib/Config';

export class Rotation {
  realmUrl: string;
  minTimeBetweenJwksRequests: number;
  jwks: any[];
  lastTimeRequestTime: number;

  constructor(config: Config) {
    this.realmUrl = config.realmUrl;
    this.minTimeBetweenJwksRequests = config.minTimeBetweenJwksRequests;
    this.jwks = [];
    this.lastTimeRequestTime = 0;
  }
  retrieveJWKs (callback?: Function) {
    const url = this.realmUrl + '/protocol/openid-connect/certs';
    const options: UrlWithStringQuery & { method?: string } = parse(url);
    options.method = 'GET';
    const promise = new Promise((resolve, reject) => {
      const req = this.getProtocol(options).request(options, (response) => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          return reject(new Error('Error fetching JWK Keys'));
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
    return this.nodeify(promise, callback);
  }

  async getJWK (kid: string) {
    const key = this.jwks.find((key) => { return key.kid === kid; });
    if (key) {
      return new Promise((resolve, reject) => {
        resolve(jwkToPem(key));
      });
    }
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    // const self = this;

    // check if we are allowed to send request
    const currentTime = new Date().getTime() / 1000;
    if (currentTime > this.lastTimeRequestTime + this.minTimeBetweenJwksRequests) {
      return this.retrieveJWKs()
        .then(publicKeys => {
          this.lastTimeRequestTime = currentTime;
          this.jwks = publicKeys.keys;
          const convertedKey = jwkToPem(this.jwks.find((key) => { return key.kid === kid; }));
          return convertedKey;
        });
    } else {
      console.error('Not enough time elapsed since the last request, blocking the request');
    }
  }

  clearCache () {
    this.jwks.length = 0;
  }

  getProtocol(opts: UrlWithStringQuery & { method?: string }){
    return opts.protocol === 'https:' ? https : http;
  }

  async nodeify(promise: Promise<any>, cb: Function) {
    if (typeof cb !== 'function') return promise;
    return promise.then((res) => cb(null, res)).catch((err) => cb(err));
  }
}
