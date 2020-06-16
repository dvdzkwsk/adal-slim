import { Logger } from "./logger";
declare enum RequestType {
    LOGIN = "LOGIN",
    RENEW_TOKEN = "RENEW_TOKEN",
    UNKNOWN = "UNKNOWN"
}
declare type Config = any;
declare type Options = any;
export declare class Adal {
    config: Config;
    logger: Logger;
    _user: any;
    _idTokenNonce: any;
    _activeRenewals: any;
    _loginInProgress: boolean;
    _acquireTokenInProgress: boolean;
    _renewStates: any[];
    _openedWindows: any[];
    _callBackMappedToRenewStates: any;
    _callBacksMappedToRenewStates: any;
    _requestType: RequestType;
    constructor(options: Options);
    /**
     * Initiates the login process by redirecting the user to Azure AD authorization endpoint.
     */
    login(): void;
    /**
     * Configures popup window for login.
     * @ignore
     */
    _openPopup(urlNavigate: string, title: string, popUpWidth: number, popUpHeight: number): Window | null;
    _handlePopupError(loginCallback: any, resource: string | undefined | null, error: string, errorDesc: string, loginError: string): void;
    /**
     * After authorization, the user will be sent to your specified redirect_uri with the user's bearer token
     * attached to the URI fragment as an id_token field. It closes popup window after redirection.
     * @ignore
     */
    _loginPopup(urlNavigate: string, resource?: string, callback?: any): void;
    loginInProgress(): boolean;
    /**
     * Checks for the resource in the cache. By default, cache location is Session Storage
     * @ignore
     * @returns {Boolean} 'true' if login is in progress, else returns 'false'.
     */
    _hasResource(key: any): boolean;
    /**
     * Gets token for the specified resource from the cache.
     * @param {string}   resource A URI that identifies the resource for which the token is requested.
     * @returns {string} token if if it exists and not expired, otherwise null.
     */
    getCachedToken(resource: string): any;
    /**
     * User information from idtoken.
     *  @class User
     *  @property {string} userName - username assigned from upn or email.
     *  @property {object} profile - properties parsed from idtoken.
     */
    /**
     * If user object exists, returns it. Else creates a new user object by decoding id_token from the cache.
     * @returns {User} user object
     */
    getCachedUser(): any;
    /**
     * Adds the passed callback to the array of callbacks for the specified resource and puts the array on the window object.
     * @param {string}   resource A URI that identifies the resource for which the token is requested.
     * @param {string}   expectedState A unique identifier (guid).
     * @param {tokenCallback} callback - The callback provided by the caller. It will be called with token or error.
     */
    registerCallback(expectedState: any, resource: string, callback: any): void;
    /**
     * Acquires access token with hidden iframe
     * @ignore
     */
    _renewToken(resource: any, callback: any, responseType?: string): void;
    /**
     * Renews idtoken for app's own backend when resource is clientId and calls the callback with token/error
     * @ignore
     */
    _renewIdToken(callback: any, responseType?: string): void;
    /**
     * Checks if the authorization endpoint URL contains query string parameters
     * @ignore
     */
    _urlContainsQueryStringParameter: (name: any, url: any) => boolean;
    /**
     * Removes the query string parameter from the authorization endpoint URL if it exists
     * @ignore
     */
    _urlRemoveQueryStringParameter: (url: any, name: any) => any;
    /**
     * @ignore
     */
    _loadFrameTimeout: (urlNavigation: any, frameName: any, resource: any) => void;
    /**
     * Loads iframe with authorization endpoint URL
     * @ignore
     */
    _loadFrame(urlNavigate: any, frameName: any): void;
    /**
     * @callback tokenCallback
     * @param {string} error_description error description returned from AAD if token request fails.
     * @param {string} token token returned from AAD if token request is successful.
     * @param {string} error error message returned from AAD if token request fails.
     */
    /**
     * Acquires token from the cache if it is not expired. Otherwise sends request to AAD to obtain a new token.
     * @param {string}   resource  ResourceUri identifying the target resource
     * @param {tokenCallback} callback -  The callback provided by the caller. It will be called with token or error.
     */
    acquireToken(resource: any, callback: any): void;
    /**
     * Acquires token (interactive flow using a popUp window) by sending request to AAD to obtain a new token.
     * @param {string}   resource  ResourceUri identifying the target resource
     * @param {string}   extraQueryParameters  extraQueryParameters to add to the authentication request
     * @param {tokenCallback} callback -  The callback provided by the caller. It will be called with token or error.
     */
    acquireTokenPopup(resource: any, extraQueryParameters: any, claims: any, callback: any): void;
    /**
     * Acquires token (interactive flow using a redirect) by sending request to AAD to obtain a new token. In this case the callback passed in the Authentication
     * request constructor will be called.
     * @param {string}   resource  ResourceUri identifying the target resource
     * @param {string}   extraQueryParameters  extraQueryParameters to add to the authentication request
     */
    acquireTokenRedirect(resource: any, extraQueryParameters: any, claims: any): void;
    ensureCanAcquireToken(resource: string): boolean;
    /**
     * Redirects the browser to Azure AD authorization endpoint.
     * @param {string}   urlNavigate  Url of the authorization endpoint.
     */
    promptUser(urlNavigate: string): void;
    /**
     * Clears cache items.
     */
    clearCache(): void;
    /**
     * Clears cache items for a given resource.
     * @param {string}  resource a URI that identifies the resource.
     */
    clearCacheForResource(resource: string): void;
    /**
     * Redirects user to logout endpoint.
     * After logout, it will redirect to postLogoutRedirectUri if added as a property on the config object.
     */
    logOut(): void;
    getUser(): any;
    /**
     * Adds login_hint to authorization URL which is used to pre-fill the username field of sign in page for the user if known ahead of time.
     * domain_hint can be one of users/organisations which when added skips the email based discovery process of the user.
     * @ignore
     */
    _addHintParameters: (urlNavigate: any) => any;
    /**
     * Creates a user object by decoding the id_token
     * @ignore
     */
    _createUser(idToken: any): {
        userName: any;
        profile: any;
    } | undefined;
    /**
     * Gets login error
     * @returns {string} error message related to login.
     */
    getLoginError(): any;
    /**
     * Request info object created from the response received from AAD.
     *  @class RequestInfo
     *  @property {object} parameters - object comprising of fields such as id_token/error, session_state, state, e.t.c.
     *  @property {REQUEST_TYPE} requestType - either LOGIN, RENEW_TOKEN or UNKNOWN.
     *  @property {boolean} stateMatch - true if state is valid, false otherwise.
     *  @property {string} stateResponse - unique guid used to match the response with the request.
     *  @property {boolean} valid - true if requestType contains id_token, access_token or error, false otherwise.
     */
    /**
     * Creates a requestInfo object from the URL fragment and returns it.
     * @returns {RequestInfo} an object created from the redirect response from AAD comprising of the keys - parameters, requestType, stateMatch, stateResponse and valid.
     */
    getRequestInfo(hash: any): {
        valid: boolean;
        parameters: {};
        stateMatch: boolean;
        stateResponse: string;
        requestType: RequestType;
    };
    /**
     * Matches nonce from the request with the response.
     * @ignore
     */
    _matchNonce(user: any): boolean;
    /**
     * Matches state from the request with the response.
     * @ignore
     */
    _matchState(requestInfo: any): boolean;
    /**
     * Saves token or error received in the response from AAD in the cache. In case of id_token, it also creates the user object.
     */
    saveTokenFromHash(requestInfo: any): void;
    /**
     * Gets resource for given endpoint if mapping is provided with config.
     * @param {string} endpoint  -  The URI for which the resource Id is requested.
     * @returns {string} resource for this API endpoint.
     */
    getResourceForEndpoint(endpoint: string): any;
    /**
     * Strips the protocol part of the URL and returns it.
     * @ignore
     */
    _getHostFromUri(uri: string): string;
    /**
     * This method must be called for processing the response received from AAD. It extracts the hash, processes the token or error, saves it in the cache and calls the registered callbacks with the result.
     * @param {string} [hash=window.location.hash] - Hash fragment of Url.
     */
    handleWindowCallback(hash: string): void;
    /**
     * Constructs the authorization endpoint URL and returns it.
     * @ignore
     */
    _getNavigateUrl(responseType: string, resource?: string): string;
    /**
     * Returns the decoded id_token.
     * @ignore
     */
    _extractIdToken(encodedIdToken: string): any;
    /**
     * Decodes a string of data which has been encoded using base-64 encoding.
     * @ignore
     */
    _base64DecodeStringUrlSafe(base64IdToken: string): string;
    /**
     * Decodes an id token into an object with header, payload and signature fields.
     * @ignore
     */
    _decodeJwt(jwtToken: string): {
        header: string;
        JWSPayload: string;
        JWSSig: string;
    } | null;
    /**
     * Converts string to represent binary data in ASCII string format by translating it into a radix-64 representation and returns it
     * @ignore
     */
    _convertUrlSafeToRegularBase64EncodedString(str: string): string;
    /**
     * Serializes the parameters for the authorization endpoint URL and returns the serialized uri string.
     * @ignore
     */
    _serialize(responseType: string, obj: any, resource?: string): string;
    /**
     * Calculates the expires in value in milliseconds for the acquired token
     * @ignore
     */
    _expiresIn(expires: any): number;
    /**
     * Adds the hidden iframe for silent token renewal
     * @ignore
     */
    _addAdalFrame(iframeId: string): HTMLElement | null | undefined;
}
export {};
