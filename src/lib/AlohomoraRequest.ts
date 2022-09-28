import { Request } from 'express';

import { ResponsePermission } from '@Lib/ResponsePermission';
import { Grant } from '@Lib/Grant';

export type AlohomoraRequest = Request & {
  kauth?: {
    grant?: Grant;
  };
  permissions?: ResponsePermission[];
}
