import { Permission } from '@Lib/Permission';

export interface AuthZRequest {
  audience?: string;
  response_mode?: string;
  claim_token?: string;
  claim_token_format?: string;
  permissions?: Permission[];
}
