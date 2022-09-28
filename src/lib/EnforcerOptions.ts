
export interface EnforcerOptions {
  response_mode?: string;
  resource_server_id?: string;
  claims?: (...args: any[]) => any;
}
