import { Request, Response } from 'express';

import { Token } from '@Lib/Token';

export interface GrantProperties {
  access_token?: Token;
  refresh_token?: Token;
  id_token?: Token;
  expires_in?: string;
  token_type?: string;
  __raw: string;
}

export class Grant {
  access_token: Token;
  refresh_token: Token;
  id_token: Token;
  expires_in: string;
  token_type: string;
  __raw: string;

  store: (req: Request, res: Response) => void;
  unstore: (req: Request, res: Response) => void;
  constructor(grant: GrantProperties) {
    this.update(grant);
  }

  /**
   * Update this grant in-place given data in another grant.
   *
   * This is used to avoid making client perform extra-bookkeeping
   * to maintain the up-to-date/refreshed grant-set.
   */
  update(grant: GrantProperties) {
    this.access_token = grant.access_token;
    this.refresh_token = grant.refresh_token;
    this.id_token = grant.id_token;
    this.token_type = grant.token_type;
    this.expires_in = grant.expires_in;
    this.__raw = grant.__raw;
  }

  /**
   * Returns the raw String of the grant, if available.
   *
   * If the raw string is unavailable (due to programatic construction)
   * then `undefined` is returned.
   */
  toString(): string {
    return this.__raw;
  }

  /**
   * Determine if this grant is expired/out-of-date.
   *
   * Determination is made based upon the expiration status of the `access_token`.
   *
   * An expired grant *may* be possible to refresh, if a valid
   * `refresh_token` is available.
   *
   * @return `true` if expired, otherwise `false`.
   */
  isExpired(): boolean {
    if (!this.access_token) {
      return true;
    }
    return this.access_token.isExpired();
  }
}
