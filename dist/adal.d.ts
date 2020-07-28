declare type Config = any;
declare type User = any;
/**
 * Request info object created from the response received from AAD.
 *  @class RequestInfo
 *  @property {object} parameters - object comprising of fields such as id_token/error, session_state, state, e.t.c.
 *  @property {REQUEST_TYPE} requestType - either LOGIN, RENEW_TOKEN or UNKNOWN.
 *  @property {boolean} stateMatch - true if state is valid, false otherwise.
 *  @property {string} stateResponse - unique guid used to match the response with the request.
 *  @property {boolean} valid - true if requestType contains id_token, access_token or error, false otherwise.
 */
declare type RequestInfo = {
    parameters: {
        [key: string]: any;
    };
    requestType: "LOGIN" | "RENEW_TOKEN" | "UNKNOWN";
    stateMatch: boolean;
    stateResponse: string;
    valid: boolean;
};
interface Adal {
    config: Config;
    login(): void;
    logOut(): void;
    loginInProgress(): boolean;
    getUser(): User | undefined;
    getCachedUser(): User | undefined;
    getCachedToken(resource: string): string | undefined;
    registerCallback(expectedState: any, resource: string, callback: any): void;
    acquireToken(resource: string, callback: any): void;
    acquireTokenPopup(resource: string, extraQueryParameters: string, claims: string | undefined, callback: any): void;
    getRequestInfo(hash: string): RequestInfo;
    saveTokenFromHash(requestInfo: RequestInfo): void;
    _callBackMappedToRenewStates: any;
    _callBacksMappedToRenewStates: any;
}
export declare function AuthenticationContext(config: Config): Adal;
export declare let clearCacheForResource: (resource: string) => void;
export {};
