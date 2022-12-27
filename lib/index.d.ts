import { Strategy as PassportStrategy } from "passport-strategy";
import express = require("express");
import { PeerCertificate } from 'tls';

interface IStrategyOptions {
    header: string;
    passReqToCallback?: false | undefined;
}

interface IStrategyOptionsWithRequest {
    header: string;
    passReqToCallback: true;
}

interface IVerifyOptions {
    message: string;
}

interface VerifyFunctionWithRequest {
    (
        req: express.Request,
        { cert }: PeerCertificate,
        done: (error: any, user?: any, options?: IVerifyOptions) => void
    ): void;
}

interface VerifyFunction {
    (
        { cert }: PeerCertificate,
        done: (error: any, user?: any, options?: IVerifyOptions) => void
    ): void;
}

declare class Strategy extends PassportStrategy {
    constructor(
        options: IStrategyOptionsWithRequest,
        verify: VerifyFunctionWithRequest
    );
    constructor(options: IStrategyOptions, verify: VerifyFunction);
    constructor(verify: VerifyFunction);

    name: string;
}
