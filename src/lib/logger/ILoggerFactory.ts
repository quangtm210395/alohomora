
export interface ILoggerFactory {
  create(thisModule: NodeModule): ILogger;
}

type LogCallback = (error?: any, level?: string, message?: string, meta?: any) => void;

interface LeveledLogMethod {
  (message: string, callback: LogCallback): ILogger | void;
  (message: string, meta: any, callback: LogCallback): ILogger | void;
  (message: string, ...meta: any[]): ILogger | void;
  (message: any): ILogger | void;
  (infoObject: object): ILogger | void;
}

export interface ILogger {
  debug: LeveledLogMethod;
  info: LeveledLogMethod;
  warn: LeveledLogMethod;
  error: LeveledLogMethod;
}
