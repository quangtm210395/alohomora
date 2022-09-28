import { UrlWithStringQuery } from 'url';

export type RequestOptions = UrlWithStringQuery & {
  method?: string;
  headers?: { [key: string]: string};
}
