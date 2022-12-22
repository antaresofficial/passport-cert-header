import { Request } from 'express';

import passport from 'passport';
import { PeerCertificate } from 'tls';

export interface StrategyOptions {
  passReqToCallback?: false;
  header: string;
}

export interface StrategyOptionsWithRequest {
  passReqToCallback: true;
  header: string;
}

export interface VerifyOptions {
  message: string;
}

export interface VerifyCallback {
  (error: any, user?: any, options?: VerifyOptions): void;
}

export interface VerifyFunctionWithRequest {
  (payload: { cert: PeerCertificate }, req: Request, done: VerifyCallback): void;
}

export interface VerifyFunction {
  (payload: { cert: PeerCertificate }, done: VerifyCallback): void;
}

declare class Strategy implements passport.Strategy {
  constructor(options: StrategyOptionsWithRequest, verify: VerifyFunctionWithRequest);
  constructor(options: StrategyOptions, verify: VerifyFunction);
  constructor(verify: VerifyFunction);

  name: string;
  authenticate: (req: Request, options?: Object) => void;
}
