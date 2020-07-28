declare enum RequestType {
    LOGIN = "LOGIN",
    RENEW_TOKEN = "RENEW_TOKEN",
    UNKNOWN = "UNKNOWN"
}
declare type RequestInfo = {
    parameters: {
        [key: string]: any;
    };
    requestType: RequestType;
    stateMatch: boolean;
    stateResponse: string;
    valid: boolean;
};
export declare type Config = any;
export declare type User = any;
export interface AuthenticationContext {
    config: Config;
    login(): void;
    logout(): void;
    loginInProgress(): boolean;
    getUser(): User | undefined;
    registerCallback(expectedState: any, resource: string, callback: any): void;
    acquireToken(resource: string, callback: any): void;
    acquireTokenPopup(resource: string, extraQueryParameters: string, claims: string | undefined, callback: any): void;
    getRequestInfo(hash: string): RequestInfo;
    saveTokenFromHash(requestInfo: RequestInfo): void;
    handleWindowCallback(hash?: string): void;
    _callBackMappedToRenewStates: any;
    _callBacksMappedToRenewStates: any;
}
export declare function AuthenticationContext(config: Config): AuthenticationContext;
export declare let clearCacheForResource: (resource: string) => void;
export {};
