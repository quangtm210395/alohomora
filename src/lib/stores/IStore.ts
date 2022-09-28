import { Request } from 'express';

import { Grant } from '@Lib/Grant';

export interface IStore {
  get(request: Request): any;
  wrap(grant: Grant): any;
}
