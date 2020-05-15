// AdalJS v1.0.17
//----------------------------------------------------------------------
// @preserve Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//id
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//----------------------------------------------------------------------
import {Storage, StorageKey} from "./storage"
import {Logger} from "./logger"
import {VERSION} from "./version"

enum RequestType {
    LOGIN = "LOGIN",
    RENEW_TOKEN = "RENEW_TOKEN",
    UNKNOWN = "UNKNOWN",
}
enum ResponseType {
    ID_TOKEN = "id_token token",
    TOKEN = "token",
}

enum TokenRenewStatus {
    Canceled = "Canceled",
    Completed = "Completed",
    InProgress = "In Progress",
}

const ACCESS_TOKEN = "access_token",
    EXPIRES_IN = "expires_in",
    ID_TOKEN = "id_token",
    ERROR = "error",
    ERROR_DESCRIPTION = "error_description",
    SESSION_STATE = "session_state",
    RESOURCE_DELIMETER = "|",
    CACHE_DELIMETER = "||"

type Config = any
type Options = any
export class Adal {
    config: Config
    logger = new Logger()

    // TODO: move off of instance for smaller property names
    _user: any
    _idTokenNonce: any
    _activeRenewals: any = {}
    _loginInProgress = false
    _acquireTokenInProgress = false
    _renewStates: any[] = []
    _openedWindows: any[] = []
    _callBackMappedToRenewStates: any = {}
    _callBacksMappedToRenewStates: any = {}
    _requestType = RequestType.LOGIN

    constructor(options: Options) {
        if ((window as any)._adalInstance) {
            return (window as any)._adalInstance
        }
        this.config = {
            popUp: false,
            instance: "https://login.microsoftonline.com/",
            loginResource: options.clientId,
            laodFrameTimeout: 6000,
            anonymousEndpoints: [],
            navigateToLoginRequestUrl: true,
            tenant: "common",
            redirectUri: window.location.href.split("?")[0].split("#")[0],
            callback: () => {},
            ...options,
        }
        this.logger.correlationId = options.correlationId
        ;(window as any)._adalInstance = this
    }

    /**
     * Initiates the login process by redirecting the user to Azure AD authorization endpoint.
     */
    login() {
        if (this._loginInProgress) {
            this.logger.info("Login in progress")
            return
        }

        this._loginInProgress = true

        // Token is not present and user needs to login
        var expectedState = guid()
        this.config.state = expectedState
        this._idTokenNonce = guid()
        var loginStartPage = getItem(StorageKey.ANGULAR_LOGIN_REQUEST)

        if (!loginStartPage || loginStartPage === "") {
            loginStartPage = window.location.href
        } else {
            saveItem(StorageKey.ANGULAR_LOGIN_REQUEST, "")
        }

        this.logger.verbose(
            "Expected state: " + expectedState + " startPage:" + loginStartPage,
        )
        saveItem(StorageKey.LOGIN_REQUEST, loginStartPage)
        saveItem(StorageKey.LOGIN_ERROR, "")
        saveItem(StorageKey.STATE_LOGIN, expectedState, true)
        saveItem(StorageKey.NONCE_IDTOKEN, this._idTokenNonce, true)
        saveItem(StorageKey.ERROR, "")
        saveItem(StorageKey.ERROR_DESCRIPTION, "")
        var urlNavigate =
            this._getNavigateUrl("id_token") +
            "&nonce=" +
            encodeURIComponent(this._idTokenNonce)

        if (this.config.displayCall) {
            // User defined way of handling the navigation
            this.config.displayCall(urlNavigate)
        } else if (this.config.popUp) {
            saveItem(StorageKey.STATE_LOGIN, "") // so requestInfo does not match redirect case
            this._renewStates.push(expectedState)
            this.registerCallback(
                expectedState,
                this.config.clientId,
                this.config.callback,
            )
            this._loginPopup(urlNavigate)
        } else {
            this.promptUser(urlNavigate)
        }
    }

    /**
     * Configures popup window for login.
     * @ignore
     */
    _openPopup(
        urlNavigate: string,
        title: string,
        popUpWidth: number,
        popUpHeight: number,
    ) {
        try {
            const left = window.innerWidth / 2 - popUpWidth / 2 + window.screenX
            const top =
                window.innerHeight / 2 - popUpHeight / 2 + window.screenY
            const popupWindow = window.open(
                urlNavigate,
                title,
                "width=" +
                    popUpWidth +
                    ", height=" +
                    popUpHeight +
                    ", top=" +
                    top +
                    ", left=" +
                    left,
            )!

            if (popupWindow.focus) {
                popupWindow.focus()
            }

            return popupWindow
        } catch (e) {
            this.logger.warn("Error opening popup, " + e.message)
            this._loginInProgress = false
            this._acquireTokenInProgress = false
            return null
        }
    }

    _handlePopupError(
        loginCallback: any,
        resource: string | undefined | null,
        error: string,
        errorDesc: string,
        loginError: string,
    ) {
        this.logger.warn(errorDesc)
        saveItem(StorageKey.ERROR, error)
        saveItem(StorageKey.ERROR_DESCRIPTION, errorDesc)
        saveItem(StorageKey.LOGIN_ERROR, loginError)

        if (resource && this._activeRenewals[resource]) {
            this._activeRenewals[resource] = null
        }

        this._loginInProgress = false
        this._acquireTokenInProgress = false

        if (loginCallback) {
            loginCallback(errorDesc, null, error)
        }
    }

    /**
     * After authorization, the user will be sent to your specified redirect_uri with the user's bearer token
     * attached to the URI fragment as an id_token field. It closes popup window after redirection.
     * @ignore
     */
    _loginPopup(urlNavigate: string, resource?: string, callback?: any) {
        var popupWindow = this._openPopup(urlNavigate, "login", 483, 600)
        var loginCallback = callback || this.config.callback

        if (popupWindow == null) {
            var error = "Error opening popup"
            var errorDesc =
                "Popup Window is null. This can happen if you are using IE"
            this._handlePopupError(
                loginCallback,
                resource,
                error,
                errorDesc,
                errorDesc,
            )
            return
        }

        this._openedWindows.push(popupWindow)

        if (this.config.redirectUri.indexOf("#") != -1) {
            var registeredRedirectUri = this.config.redirectUri.split("#")[0]
        } else {
            var registeredRedirectUri = this.config.redirectUri
        }

        var pollTimer = window.setInterval(() => {
            if (
                !popupWindow ||
                popupWindow.closed ||
                popupWindow.closed === undefined
            ) {
                var error = "Popup Window closed"
                var errorDesc =
                    "Popup Window closed by UI action/ Popup Window handle destroyed due to cross zone navigation in IE/Edge"

                this._handlePopupError(
                    loginCallback,
                    resource,
                    error,
                    errorDesc,
                    errorDesc,
                )
                window.clearInterval(pollTimer)
                return
            }
            try {
                var popUpWindowLocation = popupWindow.location
                if (
                    encodeURI(popUpWindowLocation.href).indexOf(
                        encodeURI(registeredRedirectUri),
                    ) != -1
                ) {
                    this.handleWindowCallback(popUpWindowLocation.hash)

                    window.clearInterval(pollTimer)
                    this._loginInProgress = false
                    this._acquireTokenInProgress = false
                    this.logger.info("Closing popup window")
                    this._openedWindows = []
                    popupWindow.close()
                    return
                }
            } catch (e) {}
        }, 1)
    }

    loginInProgress() {
        return this._loginInProgress
    }

    /**
     * Checks for the resource in the cache. By default, cache location is Session Storage
     * @ignore
     * @returns {Boolean} 'true' if login is in progress, else returns 'false'.
     */
    _hasResource(key) {
        var keys = getItem(StorageKey.TOKEN_KEYS)
        return !isEmpty(keys) && keys.indexOf(key + RESOURCE_DELIMETER) > -1
    }

    /**
     * Gets token for the specified resource from the cache.
     * @param {string}   resource A URI that identifies the resource for which the token is requested.
     * @returns {string} token if if it exists and not expired, otherwise null.
     */
    getCachedToken(resource: string) {
        if (!this._hasResource(resource)) {
            return null
        }

        var token = getItem(StorageKey.ACCESS_TOKEN_KEY + resource)
        var expiry = getItem(StorageKey.EXPIRATION_KEY + resource)

        // If expiration is within offset, it will force renew
        var offset = this.config.expireOffsetSeconds || 300

        if (expiry && expiry > now() + offset) {
            return token
        } else {
            saveItem(StorageKey.ACCESS_TOKEN_KEY + resource, "")
            saveItem(StorageKey.EXPIRATION_KEY + resource, 0)
            return null
        }
    }

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
    getCachedUser() {
        if (this._user) {
            return this._user
        }

        var idtoken = getItem(StorageKey.IDTOKEN)
        this._user = this._createUser(idtoken)
        return this._user
    }

    /**
     * Adds the passed callback to the array of callbacks for the specified resource and puts the array on the window object.
     * @param {string}   resource A URI that identifies the resource for which the token is requested.
     * @param {string}   expectedState A unique identifier (guid).
     * @param {tokenCallback} callback - The callback provided by the caller. It will be called with token or error.
     */
    registerCallback(expectedState: any, resource: string, callback: any) {
        this._activeRenewals[resource] = expectedState

        if (!this._callBacksMappedToRenewStates[expectedState]) {
            this._callBacksMappedToRenewStates[expectedState] = []
        }

        this._callBacksMappedToRenewStates[expectedState].push(callback)

        if (!this._callBackMappedToRenewStates[expectedState]) {
            this._callBackMappedToRenewStates[expectedState] = (
                errorDesc,
                token,
                error,
                tokenType,
            ) => {
                this._activeRenewals[resource] = null

                for (
                    var i = 0;
                    i <
                    this._callBacksMappedToRenewStates[expectedState].length;
                    ++i
                ) {
                    try {
                        this._callBacksMappedToRenewStates[expectedState][i](
                            errorDesc,
                            token,
                            error,
                            tokenType,
                        )
                    } catch (error) {
                        this.logger.warn(error)
                    }
                }

                this._callBacksMappedToRenewStates[expectedState] = null
                this._callBackMappedToRenewStates[expectedState] = null
            }
        }
    }

    // var errorResponse = {error:'', error_description:''};
    // var token = 'string token';
    // callback(errorResponse, token)
    // with callback
    /**
     * Acquires access token with hidden iframe
     * @ignore
     */
    _renewToken(resource, callback, responseType = "token") {
        // use iframe to try to renew token
        // use given resource to create new authz url
        this.logger.info("renewToken is called for resource:" + resource)
        var frameHandle = this._addAdalFrame("adalRenewFrame" + resource)
        var expectedState = guid() + "|" + resource
        this.config.state = expectedState
        // renew happens in iframe, so it keeps javascript context
        this._renewStates.push(expectedState)
        this.logger.verbose("Renew token Expected state: " + expectedState)
        // remove the existing prompt=... query parameter and add prompt=none
        var urlNavigate = this._urlRemoveQueryStringParameter(
            this._getNavigateUrl(responseType, resource),
            "prompt",
        )

        if (responseType === ResponseType.ID_TOKEN) {
            this._idTokenNonce = guid()
            saveItem(StorageKey.NONCE_IDTOKEN, this._idTokenNonce, true)
            urlNavigate += "&nonce=" + encodeURIComponent(this._idTokenNonce)
        }

        urlNavigate = urlNavigate + "&prompt=none"
        urlNavigate = this._addHintParameters(urlNavigate)
        this.registerCallback(expectedState, resource, callback)
        this.logger.verbosePii("Navigate to:" + urlNavigate)
        // @ts-expect-error
        frameHandle.src = "about:blank"
        this._loadFrameTimeout(
            urlNavigate,
            "adalRenewFrame" + resource,
            resource,
        )
    }

    /**
     * Renews idtoken for app's own backend when resource is clientId and calls the callback with token/error
     * @ignore
     */
    _renewIdToken(callback, responseType?: string) {
        // use iframe to try to renew token
        this.logger.info("renewIdToken is called")
        let frameHandle = this._addAdalFrame("adalIdTokenFrame")
        let expectedState = guid() + "|" + this.config.clientId
        this._idTokenNonce = guid()
        saveItem(StorageKey.NONCE_IDTOKEN, this._idTokenNonce, true)
        this.config.state = expectedState
        // renew happens in iframe, so it keeps javascript context
        this._renewStates.push(expectedState)
        this.logger.verbose("Renew Idtoken Expected state: " + expectedState)
        // remove the existing prompt=... query parameter and add prompt=none
        let resource = responseType || this.config.clientId
        responseType = responseType || "id_token"
        let urlNavigate = this._urlRemoveQueryStringParameter(
            this._getNavigateUrl(responseType, resource),
            "prompt",
        )
        urlNavigate = urlNavigate + "&prompt=none"
        urlNavigate = this._addHintParameters(urlNavigate)
        urlNavigate += "&nonce=" + encodeURIComponent(this._idTokenNonce)
        this.registerCallback(expectedState, this.config.clientId, callback)
        this.logger.verbosePii("Navigate to:" + urlNavigate)
        // @ts-expect-error
        frameHandle.src = "about:blank"
        this._loadFrameTimeout(
            urlNavigate,
            "adalIdTokenFrame",
            this.config.clientId,
        )
    }

    /**
     * Checks if the authorization endpoint URL contains query string parameters
     * @ignore
     */
    _urlContainsQueryStringParameter = function (name, url) {
        // regex to detect pattern of a ? or & followed by the name parameter and an equals character
        var regex = new RegExp("[\\?&]" + name + "=")
        return regex.test(url)
    }

    /**
     * Removes the query string parameter from the authorization endpoint URL if it exists
     * @ignore
     */
    _urlRemoveQueryStringParameter = function (url, name) {
        // we remove &name=value, name=value& and name=value
        // &name=value
        var regex = new RegExp("(\\&" + name + "=)[^&]+")
        url = url.replace(regex, "")
        // name=value&
        regex = new RegExp("(" + name + "=)[^&]+&")
        url = url.replace(regex, "")
        // name=value
        regex = new RegExp("(" + name + "=)[^&]+")
        url = url.replace(regex, "")
        return url
    }

    // Calling _loadFrame but with a timeout to signal failure in loadframeStatus. Callbacks are left
    // registered when network errors occur and subsequent token requests for same resource are registered to the pending request
    /**
     * @ignore
     */
    _loadFrameTimeout = function (urlNavigation, frameName, resource) {
        //set iframe session to pending
        this.verbose("Set loading state to pending for: " + resource)
        saveItem(
            StorageKey.RENEW_STATUS + resource,
            TokenRenewStatus.InProgress,
        )
        this._loadFrame(urlNavigation, frameName)

        setTimeout(() => {
            if (
                getItem(StorageKey.RENEW_STATUS + resource) ===
                TokenRenewStatus.InProgress
            ) {
                // fail the iframe session if it's in pending state
                this.verbose(
                    "Loading frame has timed out after: " +
                        this.config.loadFrameTimeout / 1000 +
                        " seconds for resource " +
                        resource,
                )
                var expectedState = this._activeRenewals[resource]

                if (
                    expectedState &&
                    this._callBackMappedToRenewStates[expectedState]
                ) {
                    this._callBackMappedToRenewStates[expectedState](
                        "Token renewal operation failed due to timeout",
                        null,
                        "Token Renewal Failed",
                    )
                }

                saveItem(
                    StorageKey.RENEW_STATUS + resource,
                    TokenRenewStatus.Canceled,
                )
            }
        }, this.config.loadFrameTimeout)
    }

    /**
     * Loads iframe with authorization endpoint URL
     * @ignore
     */
    _loadFrame(urlNavigate, frameName) {
        // This trick overcomes iframe navigation in IE
        // IE does not load the page consistently in iframe
        this.logger.info("LoadFrame: " + frameName)
        setTimeout(() => {
            var frameHandle = this._addAdalFrame(frameName) as any
            if (frameHandle.src === "" || frameHandle.src === "about:blank") {
                frameHandle.src = urlNavigate
                this._loadFrame(urlNavigate, frameName)
            }
        }, 500)
    }

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
    acquireToken(resource, callback) {
        if (isEmpty(resource)) {
            this.logger.warn("resource is required")
            callback("resource is required", null, "resource is required")
            return
        }

        var token = this.getCachedToken(resource)

        if (token) {
            this.logger.info(
                "Token is already in cache for resource:" + resource,
            )
            callback(null, token, null)
            return
        }

        if (
            !this._user &&
            !(
                this.config.extraQueryParameter &&
                this.config.extraQueryParameter.indexOf("login_hint") !== -1
            )
        ) {
            this.logger.warn("User login is required")
            callback("User login is required", null, "login required")
            return
        }

        // renew attempt with iframe
        // Already renewing for this resource, callback when we get the token.
        if (this._activeRenewals[resource]) {
            // Active renewals contains the state for each renewal.
            this.registerCallback(
                this._activeRenewals[resource],
                resource,
                callback,
            )
        } else {
            this._requestType = RequestType.RENEW_TOKEN
            if (resource === this.config.clientId) {
                // App uses idtoken to send to api endpoints
                // Default resource is tracked as clientid to store this token
                if (this._user) {
                    this.logger.verbose("renewing idtoken")
                    this._renewIdToken(callback)
                } else {
                    this.logger.verbose("renewing idtoken and access_token")
                    this._renewIdToken(callback, ResponseType.ID_TOKEN)
                }
            } else {
                if (this._user) {
                    this.logger.verbose("renewing access_token")
                    this._renewToken(resource, callback)
                } else {
                    this.logger.verbose("renewing idtoken and access_token")
                    this._renewToken(resource, callback, ResponseType.ID_TOKEN)
                }
            }
        }
    }

    /**
     * Acquires token (interactive flow using a popUp window) by sending request to AAD to obtain a new token.
     * @param {string}   resource  ResourceUri identifying the target resource
     * @param {string}   extraQueryParameters  extraQueryParameters to add to the authentication request
     * @param {tokenCallback} callback -  The callback provided by the caller. It will be called with token or error.
     */
    acquireTokenPopup(resource, extraQueryParameters, claims, callback) {
        if (isEmpty(resource)) {
            this.logger.warn("resource is required")
            callback("resource is required", null, "resource is required")
            return
        }

        if (!this._user) {
            this.logger.warn("User login is required")
            callback("User login is required", null, "login required")
            return
        }

        if (this._acquireTokenInProgress) {
            this.logger.warn("Acquire token interactive is already in progress")
            callback(
                "Acquire token interactive is already in progress",
                null,
                "Acquire token interactive is already in progress",
            )
            return
        }

        var expectedState = guid() + "|" + resource
        this.config.state = expectedState
        this._renewStates.push(expectedState)
        this._requestType = RequestType.RENEW_TOKEN
        this.logger.verbose("Renew token Expected state: " + expectedState)
        // remove the existing prompt=... query parameter and add prompt=select_account
        var urlNavigate = this._urlRemoveQueryStringParameter(
            this._getNavigateUrl("token", resource),
            "prompt",
        )
        urlNavigate = urlNavigate + "&prompt=select_account"

        if (extraQueryParameters) {
            urlNavigate += extraQueryParameters
        }

        if (claims && urlNavigate.indexOf("&claims") === -1) {
            urlNavigate += "&claims=" + encodeURIComponent(claims)
        } else if (claims && urlNavigate.indexOf("&claims") !== -1) {
            throw new Error("Claims cannot be passed as an extraQueryParameter")
        }

        urlNavigate = this._addHintParameters(urlNavigate)
        this._acquireTokenInProgress = true
        this.logger.info(
            "acquireToken interactive is called for the resource " + resource,
        )
        this.registerCallback(expectedState, resource, callback)
        this._loginPopup(urlNavigate, resource, callback)
    }

    /**
     * Acquires token (interactive flow using a redirect) by sending request to AAD to obtain a new token. In this case the callback passed in the Authentication
     * request constructor will be called.
     * @param {string}   resource  ResourceUri identifying the target resource
     * @param {string}   extraQueryParameters  extraQueryParameters to add to the authentication request
     */
    acquireTokenRedirect(resource, extraQueryParameters, claims) {
        const {callback} = this.config

        if (isEmpty(resource)) {
            this.logger.warn("resource is required")
            callback("resource is required", null, "resource is required")
            return
        }

        if (!this._user) {
            this.logger.warn("User login is required")
            callback("User login is required", null, "login required")
            return
        }

        if (this._acquireTokenInProgress) {
            this.logger.warn("Acquire token interactive is already in progress")
            callback(
                "Acquire token interactive is already in progress",
                null,
                "Acquire token interactive is already in progress",
            )
            return
        }

        var expectedState = guid() + "|" + resource
        this.config.state = expectedState
        this.logger.verbose("Renew token Expected state: " + expectedState)

        // remove the existing prompt=... query parameter and add prompt=select_account
        var urlNavigate = this._urlRemoveQueryStringParameter(
            this._getNavigateUrl("token", resource),
            "prompt",
        )
        urlNavigate = urlNavigate + "&prompt=select_account"
        if (extraQueryParameters) {
            urlNavigate += extraQueryParameters
        }

        if (claims && urlNavigate.indexOf("&claims") === -1) {
            urlNavigate += "&claims=" + encodeURIComponent(claims)
        } else if (claims && urlNavigate.indexOf("&claims") !== -1) {
            throw new Error("Claims cannot be passed as an extraQueryParameter")
        }

        urlNavigate = this._addHintParameters(urlNavigate)
        this._acquireTokenInProgress = true
        this.logger.info(
            "acquireToken interactive is called for the resource " + resource,
        )
        saveItem(StorageKey.LOGIN_REQUEST, window.location.href)
        saveItem(StorageKey.STATE_RENEW, expectedState, true)
        this.promptUser(urlNavigate)
    }

    /**
     * Redirects the browser to Azure AD authorization endpoint.
     * @param {string}   urlNavigate  Url of the authorization endpoint.
     */
    promptUser(urlNavigate: string) {
        if (urlNavigate) {
            this.logger.infoPii("Navigate to:" + urlNavigate)
            window.location.replace(urlNavigate)
        } else {
            this.logger.info("Navigate url is empty")
        }
    }

    /**
     * Clears cache items.
     */
    clearCache() {
        saveItem(StorageKey.LOGIN_REQUEST, "")
        saveItem(StorageKey.ANGULAR_LOGIN_REQUEST, "")
        saveItem(StorageKey.SESSION_STATE, "")
        saveItem(StorageKey.STATE_LOGIN, "")
        saveItem(StorageKey.STATE_RENEW, "")
        this._renewStates = []
        saveItem(StorageKey.NONCE_IDTOKEN, "")
        saveItem(StorageKey.IDTOKEN, "")
        saveItem(StorageKey.ERROR, "")
        saveItem(StorageKey.ERROR_DESCRIPTION, "")
        saveItem(StorageKey.LOGIN_ERROR, "")
        saveItem(StorageKey.LOGIN_ERROR, "")
        var keys = getItem(StorageKey.TOKEN_KEYS) as any

        if (!isEmpty(keys)) {
            keys = keys.split(RESOURCE_DELIMETER)
            for (var i = 0; i < keys.length && keys[i] !== ""; i++) {
                saveItem(StorageKey.ACCESS_TOKEN_KEY + keys[i], "")
                saveItem(StorageKey.EXPIRATION_KEY + keys[i], 0)
            }
        }

        saveItem(StorageKey.TOKEN_KEYS, "")
    }

    /**
     * Clears cache items for a given resource.
     * @param {string}  resource a URI that identifies the resource.
     */
    clearCacheForResource(resource: string) {
        saveItem(StorageKey.STATE_RENEW, "")
        saveItem(StorageKey.ERROR, "")
        saveItem(StorageKey.ERROR_DESCRIPTION, "")

        if (this._hasResource(resource)) {
            saveItem(StorageKey.ACCESS_TOKEN_KEY + resource, "")
            saveItem(StorageKey.EXPIRATION_KEY + resource, 0)
        }
    }

    /**
     * Redirects user to logout endpoint.
     * After logout, it will redirect to postLogoutRedirectUri if added as a property on the config object.
     */
    logOut() {
        this.clearCache()
        this._user = null
        let urlNavigate: string

        if (this.config.logOutUri) {
            urlNavigate = this.config.logOutUri
        } else {
            let logout = ""
            if (this.config.postLogoutRedirectUri) {
                logout =
                    "post_logout_redirect_uri=" +
                    encodeURIComponent(this.config.postLogoutRedirectUri)
            }

            urlNavigate =
                this.config.instance +
                this.config.tenant +
                "/oauth2/logout?" +
                logout
        }

        this.logger.infoPii("Logout navigate to: " + urlNavigate)
        this.promptUser(urlNavigate)
    }

    /**
     * @callback userCallback
     * @param {string} error error message if user info is not available.
     * @param {User} user user object retrieved from the cache.
     */

    /**
     * Calls the passed in callback with the user object or error message related to the user.
     * @param {userCallback} callback - The callback provided by the caller. It will be called with user or error.
     */
    getUser(callback) {
        // user in memory
        if (this._user) {
            callback(null, this._user)
            return
        }

        // frame is used to get idtoken
        const idtoken = getItem(StorageKey.IDTOKEN)
        if (!isEmpty(idtoken)) {
            this._user = this._createUser(idtoken)
            callback(null, this._user)
        } else {
            this.logger.warn("User information is not available")
            callback("User information is not available", null)
        }
    }

    /**
     * Adds login_hint to authorization URL which is used to pre-fill the username field of sign in page for the user if known ahead of time.
     * domain_hint can be one of users/organisations which when added skips the email based discovery process of the user.
     * @ignore
     */
    _addHintParameters = function (urlNavigate) {
        //If you dont use prompt=none, then if the session does not exist, there will be a failure.
        //If sid is sent alongside domain or login hints, there will be a failure since request is ambiguous.
        //If sid is sent with a prompt value other than none or attempt_none, there will be a failure since the request is ambiguous.

        if (this._user && this._user.profile) {
            if (
                this._user.profile.sid &&
                urlNavigate.indexOf("&prompt=none") !== -1
            ) {
                // don't add sid twice if user provided it in the extraQueryParameter value
                if (
                    !this._urlContainsQueryStringParameter("sid", urlNavigate)
                ) {
                    // add sid
                    urlNavigate +=
                        "&sid=" + encodeURIComponent(this._user.profile.sid)
                }
            } else if (this._user.profile.upn) {
                // don't add login_hint twice if user provided it in the extraQueryParameter value
                if (
                    !this._urlContainsQueryStringParameter(
                        "login_hint",
                        urlNavigate,
                    )
                ) {
                    // add login_hint
                    urlNavigate +=
                        "&login_hint=" +
                        encodeURIComponent(this._user.profile.upn)
                }
                // don't add domain_hint twice if user provided it in the extraQueryParameter value
                if (
                    !this._urlContainsQueryStringParameter(
                        "domain_hint",
                        urlNavigate,
                    ) &&
                    this._user.profile.upn.indexOf("@") > -1
                ) {
                    var parts = this._user.profile.upn.split("@")
                    // local part can include @ in quotes. Sending last part handles that.
                    urlNavigate +=
                        "&domain_hint=" +
                        encodeURIComponent(parts[parts.length - 1])
                }
            }
        }

        return urlNavigate
    }

    /**
     * Creates a user object by decoding the id_token
     * @ignore
     */
    _createUser(idToken) {
        const json = this._extractIdToken(idToken)
        if (!has(json, "aud")) {
            return
        }

        if (json.aud.toLowerCase() !== this.config.clientId.toLowerCase()) {
            this.logger.warn("IdToken has invalid aud field")
        } else {
            return {
                userName: json.upn || json.email,
                profile: json,
            }
        }
    }

    /**
     * Gets login error
     * @returns {string} error message related to login.
     */
    getLoginError() {
        return getItem(StorageKey.LOGIN_ERROR)
    }

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
    getRequestInfo(hash) {
        const parameters = deserialize(getHash(hash)) as any
        const requestInfo = {
            valid: false,
            parameters: {},
            stateMatch: false,
            stateResponse: "",
            requestType: RequestType.UNKNOWN,
        }

        if (!parameters) {
            return requestInfo
        }

        requestInfo.parameters = parameters
        if (
            has(parameters, ERROR_DESCRIPTION) ||
            has(parameters, ACCESS_TOKEN) ||
            has(parameters, ID_TOKEN)
        ) {
            requestInfo.valid = true

            // which call
            if (parameters.hasOwnProperty("state")) {
                this.logger.verbose("State: " + parameters.state)
                requestInfo.stateResponse = parameters.state
            } else {
                this.logger.warn("No state returned")
                return requestInfo
            }

            // async calls can fire iframe and login request at the same time if developer does not use the API as expected
            // incoming callback needs to be looked up to find the request type
            if (this._matchState(requestInfo)) {
                // loginRedirect or acquireTokenRedirect
                return requestInfo
            }

            // external api requests may have many renewtoken requests for different resource
            if (!requestInfo.stateMatch && window.parent) {
                requestInfo.requestType = this._requestType
                for (const state of this._renewStates) {
                    if (state === requestInfo.stateResponse) {
                        requestInfo.stateMatch = true
                        break
                    }
                }
            }
        }
    }

    /**
     * Matches nonce from the request with the response.
     * @ignore
     */
    _matchNonce(user) {
        const requestNonce = getItem(StorageKey.NONCE_IDTOKEN)
        if (requestNonce) {
            for (const nonce of requestNonce.split(CACHE_DELIMETER)) {
                if (nonce === user.profile.nonce) {
                    return true
                }
            }
        }
        return false
    }

    /**
     * Matches state from the request with the response.
     * @ignore
     */
    _matchState(requestInfo) {
        const loginStates = getItem(StorageKey.STATE_LOGIN)
        if (loginStates) {
            for (const state of loginStates.split(CACHE_DELIMETER)) {
                if (state === requestInfo.stateResponse) {
                    requestInfo.requestType = RequestType.LOGIN
                    requestInfo.stateMatch = true
                    return true
                }
            }
        }

        const acquireTokenStates = getItem(StorageKey.STATE_RENEW)
        if (acquireTokenStates) {
            for (const state of acquireTokenStates.split(CACHE_DELIMETER)) {
                if (state === requestInfo.stateResponse) {
                    requestInfo.requestType = RequestType.RENEW_TOKEN
                    requestInfo.stateMatch = true
                    return true
                }
            }
        }

        return false
    }

    /**
     * Saves token or error received in the response from AAD in the cache. In case of id_token, it also creates the user object.
     */
    saveTokenFromHash(requestInfo) {
        this.logger.info(
            "State status:" +
                requestInfo.stateMatch +
                "; Request type:" +
                requestInfo.requestType,
        )
        saveItem(StorageKey.ERROR, "")
        saveItem(StorageKey.ERROR_DESCRIPTION, "")

        var resource = getResourceFromState(requestInfo.stateResponse)

        // Record error
        if (requestInfo.parameters.hasOwnProperty(ERROR_DESCRIPTION)) {
            this.logger.infoPii(
                "Error :" +
                    requestInfo.parameters.error +
                    "; Error description:" +
                    requestInfo.parameters[ERROR_DESCRIPTION],
            )
            saveItem(StorageKey.ERROR, requestInfo.parameters.error)
            saveItem(
                StorageKey.ERROR_DESCRIPTION,
                requestInfo.parameters[ERROR_DESCRIPTION],
            )

            if (requestInfo.requestType === RequestType.LOGIN) {
                this._loginInProgress = false
                saveItem(
                    StorageKey.LOGIN_ERROR,
                    requestInfo.parameters.error_description,
                )
            }
        } else {
            // It must verify the state from redirect
            if (requestInfo.stateMatch) {
                // record tokens to storage if exists
                this.logger.info("State is right")
                if (requestInfo.parameters.hasOwnProperty(SESSION_STATE)) {
                    saveItem(
                        StorageKey.SESSION_STATE,
                        requestInfo.parameters[SESSION_STATE],
                    )
                }

                var keys

                if (requestInfo.parameters.hasOwnProperty(ACCESS_TOKEN)) {
                    this.logger.info("Fragment has access token")

                    if (!this._hasResource(resource)) {
                        keys = getItem(StorageKey.TOKEN_KEYS) || ""
                        saveItem(
                            StorageKey.TOKEN_KEYS,
                            keys + resource + RESOURCE_DELIMETER,
                        )
                    }

                    // save token with related resource
                    saveItem(
                        StorageKey.ACCESS_TOKEN_KEY + resource,
                        requestInfo.parameters[ACCESS_TOKEN],
                    )
                    saveItem(
                        StorageKey.EXPIRATION_KEY + resource,
                        this._expiresIn(requestInfo.parameters[EXPIRES_IN]),
                    )
                }

                if (requestInfo.parameters.hasOwnProperty(ID_TOKEN)) {
                    // this.info("Fragment has id token")
                    this._loginInProgress = false
                    this._user = this._createUser(
                        requestInfo.parameters[ID_TOKEN],
                    )
                    if (this._user && this._user.profile) {
                        if (!this._matchNonce(this._user)) {
                            saveItem(
                                StorageKey.LOGIN_ERROR,
                                "Nonce received: " +
                                    this._user.profile.nonce +
                                    " is not same as requested: " +
                                    getItem(StorageKey.NONCE_IDTOKEN),
                            )
                            this._user = null
                        } else {
                            saveItem(
                                StorageKey.IDTOKEN,
                                requestInfo.parameters[ID_TOKEN],
                            )

                            // Save idtoken as access token for app itself
                            resource = this.config.loginResource
                                ? this.config.loginResource
                                : this.config.clientId

                            if (!this._hasResource(resource)) {
                                keys = getItem(StorageKey.TOKEN_KEYS) || ""
                                saveItem(
                                    StorageKey.TOKEN_KEYS,
                                    keys + resource + RESOURCE_DELIMETER,
                                )
                            }

                            saveItem(
                                StorageKey.ACCESS_TOKEN_KEY + resource,
                                requestInfo.parameters[ID_TOKEN],
                            )
                            saveItem(
                                StorageKey.EXPIRATION_KEY + resource,
                                this._user.profile.exp,
                            )
                        }
                    } else {
                        requestInfo.parameters["error"] = "invalid id_token"
                        requestInfo.parameters["error_description"] =
                            "Invalid id_token. id_token: " +
                            requestInfo.parameters[ID_TOKEN]
                        saveItem(StorageKey.ERROR, "invalid id_token")
                        saveItem(
                            StorageKey.ERROR_DESCRIPTION,
                            "Invalid id_token. id_token: " +
                                requestInfo.parameters[ID_TOKEN],
                        )
                    }
                }
            } else {
                requestInfo.parameters["error"] = "Invalid_state"
                requestInfo.parameters["error_description"] =
                    "Invalid_state. state: " + requestInfo.stateResponse
                saveItem(StorageKey.ERROR, "Invalid_state")
                saveItem(
                    StorageKey.ERROR_DESCRIPTION,
                    "Invalid_state. state: " + requestInfo.stateResponse,
                )
            }
        }

        saveItem(StorageKey.RENEW_STATUS + resource, TokenRenewStatus.Completed)
    }

    /**
     * Gets resource for given endpoint if mapping is provided with config.
     * @param {string} endpoint  -  The URI for which the resource Id is requested.
     * @returns {string} resource for this API endpoint.
     */
    getResourceForEndpoint(endpoint: string) {
        // if user specified list of anonymous endpoints, no need to send token to these endpoints, return null.
        if (this.config && this.config.anonymousEndpoints) {
            for (var i = 0; i < this.config.anonymousEndpoints.length; i++) {
                if (endpoint.indexOf(this.config.anonymousEndpoints[i]) > -1) {
                    return null
                }
            }
        }

        if (this.config && this.config.endpoints) {
            for (var configEndpoint in this.config.endpoints) {
                // configEndpoint is like /api/Todo requested endpoint can be /api/Todo/1
                if (endpoint.indexOf(configEndpoint) > -1) {
                    return this.config.endpoints[configEndpoint]
                }
            }
        }

        // default resource will be clientid if nothing specified
        // App will use idtoken for calls to itself
        // check if it's staring from http or https, needs to match with app host
        if (
            endpoint.indexOf("http://") > -1 ||
            endpoint.indexOf("https://") > -1
        ) {
            if (
                this._getHostFromUri(endpoint) ===
                this._getHostFromUri(this.config.redirectUri)
            ) {
                return this.config.loginResource
            }
        } else {
            // in angular level, the url for $http interceptor call could be relative url,
            // if it's relative call, we'll treat it as app backend call.
            return this.config.loginResource
        }

        // if not the app's own backend or not a domain listed in the endpoints structure
        return null
    }

    /**
     * Strips the protocol part of the URL and returns it.
     * @ignore
     */
    _getHostFromUri(uri: string) {
        // remove http:// or https:// from uri
        var extractedUri = String(uri).replace(/^(https?:)\/\//, "")
        extractedUri = extractedUri.split("/")[0]
        return extractedUri
    }

    /**
     * This method must be called for processing the response received from AAD. It extracts the hash, processes the token or error, saves it in the cache and calls the registered callbacks with the result.
     * @param {string} [hash=window.location.hash] - Hash fragment of Url.
     */
    handleWindowCallback(hash: string) {
        // This is for regular javascript usage for redirect handling
        // need to make sure this is for callback
        if (hash == null) {
            hash = window.location.hash
        }

        if (isCallback(hash)) {
            var self: Adal = null as any
            var isPopup = false

            if (
                this._openedWindows.length > 0 &&
                this._openedWindows[this._openedWindows.length - 1].opener &&
                this._openedWindows[this._openedWindows.length - 1].opener
                    ._adalInstance
            ) {
                self = this._openedWindows[this._openedWindows.length - 1]
                    .opener._adalInstance
                isPopup = true
            }
            // @ts-ignore
            else if (window.parent && window.parent._adalInstance) {
                // @ts-ignore
                self = window.parent._adalInstance
            }

            let requestInfo = self.getRequestInfo(hash) as any
            let tokenReceivedCallback: any

            if (isPopup || window.parent !== window) {
                tokenReceivedCallback =
                    self._callBackMappedToRenewStates[requestInfo.stateResponse]
            } else {
                tokenReceivedCallback = self.config.callback
            }

            // self.info("Returned from redirect url")
            self.saveTokenFromHash(requestInfo)

            let token: any
            let tokenType: any
            if (
                requestInfo.requestType === RequestType.RENEW_TOKEN &&
                window.parent
            ) {
                if (window.parent !== window) {
                    self.logger.verbose(
                        "Window is in iframe, acquiring token silently",
                    )
                } else {
                    self.logger.verbose(
                        "acquiring token interactive in progress",
                    )
                }

                token =
                    requestInfo.parameters[ACCESS_TOKEN] ||
                    requestInfo.parameters[ID_TOKEN]
                tokenType = ACCESS_TOKEN
            } else if (requestInfo.requestType === RequestType.LOGIN) {
                token = requestInfo.parameters[ID_TOKEN]
                tokenType = ID_TOKEN
            }

            var errorDesc = requestInfo.parameters[ERROR_DESCRIPTION]
            var error = requestInfo.parameters[ERROR]
            try {
                if (tokenReceivedCallback) {
                    tokenReceivedCallback(errorDesc, token, error, tokenType)
                }
            } catch (err) {
                self.logger.error(
                    "Error occurred in user defined callback function: " + err,
                )
            }

            if (window.parent === window && !isPopup) {
                if (self.config.navigateToLoginRequestUrl) {
                    window.location.href = getItem(StorageKey.LOGIN_REQUEST)
                } else {
                    window.location.hash = ""
                }
            }
        }
    }

    /**
     * Constructs the authorization endpoint URL and returns it.
     * @ignore
     */
    _getNavigateUrl(responseType: string, resource?: string) {
        const urlNavigate =
            this.config.instance +
            this.config.tenant +
            "/oauth2/authorize" +
            this._serialize(responseType, this.config, resource) +
            "&x-client-SKU=Js&x-client-Ver=" +
            VERSION
        this.logger.info("Navigate url:" + urlNavigate)
        return urlNavigate
    }

    /**
     * Returns the decoded id_token.
     * @ignore
     */
    _extractIdToken(encodedIdToken: string) {
        // id token will be decoded to get the username
        var decodedToken = this._decodeJwt(encodedIdToken)

        if (!decodedToken) {
            return
        }

        try {
            var base64IdToken = decodedToken.JWSPayload
            var base64Decoded = this._base64DecodeStringUrlSafe(base64IdToken)

            if (!base64Decoded) {
                this.logger.info(
                    "The returned id_token could not be base64 url safe decoded.",
                )
                return
            }

            // ECMA script has JSON built-in support
            return JSON.parse(base64Decoded)
        } catch (err) {
            this.logger.error("The returned id_token could not be decoded", err)
        }
    }

    /**
     * Decodes a string of data which has been encoded using base-64 encoding.
     * @ignore
     */
    _base64DecodeStringUrlSafe(base64IdToken: string) {
        base64IdToken = base64IdToken.replace(/-/g, "+").replace(/_/g, "/")
        return decodeURIComponent(escape(window.atob(base64IdToken)))
    }

    /**
     * Decodes an id token into an object with header, payload and signature fields.
     * @ignore
     */
    // Adal.node js crack function
    _decodeJwt(jwtToken: string) {
        if (isEmpty(jwtToken)) {
            return null
        }

        var idTokenPartsRegex = /^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/

        var matches = idTokenPartsRegex.exec(jwtToken)

        if (!matches || matches.length < 4) {
            this.logger.warn("The returned id_token is not parseable.")
            return null
        }

        var crackedToken = {
            header: matches[1],
            JWSPayload: matches[2],
            JWSSig: matches[3],
        }

        return crackedToken
    }

    /**
     * Converts string to represent binary data in ASCII string format by translating it into a radix-64 representation and returns it
     * @ignore
     */
    _convertUrlSafeToRegularBase64EncodedString(str: string) {
        return str.replace("-", "+").replace("_", "/")
    }

    /**
     * Serializes the parameters for the authorization endpoint URL and returns the serialized uri string.
     * @ignore
     */
    _serialize(responseType: string, obj: any, resource?: string) {
        var str: string[] = []

        if (obj !== null) {
            str.push("?response_type=" + responseType)
            str.push("client_id=" + encodeURIComponent(obj.clientId))
            if (resource) {
                str.push("resource=" + encodeURIComponent(resource))
            }

            str.push("redirect_uri=" + encodeURIComponent(obj.redirectUri))
            str.push("state=" + encodeURIComponent(obj.state))

            if (obj.hasOwnProperty("slice")) {
                str.push("slice=" + encodeURIComponent(obj.slice))
            }

            if (obj.hasOwnProperty("extraQueryParameter")) {
                str.push(obj.extraQueryParameter)
            }

            var correlationId = obj.correlationId ? obj.correlationId : guid()
            str.push("client-request-id=" + encodeURIComponent(correlationId))
        }

        return str.join("&")
    }

    /**
     * Calculates the expires in value in milliseconds for the acquired token
     * @ignore
     */
    _expiresIn(expires: any) {
        // if AAD did not send "expires_in" property, use default expiration of 3599 seconds, for some reason AAD sends 3599 as "expires_in" value instead of 3600
        if (!expires) expires = 3599
        return now() + parseInt(expires, 10)
    }

    /**
     * Adds the hidden iframe for silent token renewal
     * @ignore
     */
    _addAdalFrame(iframeId: string) {
        if (!iframeId) {
            return
        }

        this.logger.info("Add adal frame to document:" + iframeId)
        var adalFrame = document.getElementById(iframeId)

        if (!adalFrame) {
            if (
                document.createElement &&
                document.documentElement &&
                (window["opera"] ||
                    window.navigator.userAgent.indexOf("MSIE 5.0") === -1)
            ) {
                var ifr = document.createElement("iframe") as any
                ifr.setAttribute("id", iframeId)
                ifr.setAttribute("aria-hidden", "true")
                ifr.style.visibility = "hidden"
                ifr.style.position = "absolute"
                ifr.style.width = ifr.style.height = ifr.borderWidth = "0px"

                adalFrame = document
                    .getElementsByTagName("body")[0]
                    .appendChild(ifr)
            } else if (document.body && document.body.insertAdjacentHTML) {
                document.body.insertAdjacentHTML(
                    "beforeEnd" as any,
                    '<iframe name="' +
                        iframeId +
                        '" id="' +
                        iframeId +
                        '" style="display:none"></iframe>',
                )
            }
            if (window.frames && window.frames[iframeId]) {
                adalFrame = window.frames[iframeId]
            }
        }

        return adalFrame
    }
}

/**
 * Saves the key-value pair in the cache
 * @ignore
 */
function saveItem(key: string, value: any, preserve = false) {
    if (preserve) {
        const old = getItem(key) || ""
        Storage.setItem(key, old + value + CACHE_DELIMETER)
    } else {
        Storage.setItem(key, value)
    }
}

/**
 * Searches the value for the given key in the cache
 * @ignore
 */
function getItem(key: string): any {
    return Storage.getItem(key)
}

/**
 * Returns the anchor part(#) of the URL
 * @ignore
 */
function getHash(hash: string) {
    if (hash.indexOf("#/") > -1) {
        hash = hash.substring(hash.indexOf("#/") + 2)
    } else if (hash.indexOf("#") > -1) {
        hash = hash.substring(1)
    }
    return hash
}

/**
 * Checks if the URL fragment contains access token, id token or error_description.
 * @param {string} hash  -  Hash passed from redirect page
 * @returns {Boolean} true if response contains id_token, access_token or error, false otherwise.
 */
function isCallback(hash: string) {
    const parameters = deserialize(getHash(hash))
    return (
        has(parameters, ERROR_DESCRIPTION) ||
        has(parameters, ACCESS_TOKEN) ||
        has(parameters, ID_TOKEN)
    )
}

/**
 * Parses the query string parameters into a key-value pair object.
 * @ignore
 */
function deserialize(query: string) {
    var match,
        pl = /\+/g, // Regex for replacing addition symbol with a space
        search = /([^&=]+)=([^&]*)/g,
        decode = (s: string) => decodeURIComponent(s.replace(pl, " ")),
        obj = {}
    match = search.exec(query)

    while (match) {
        obj[decode(match[1])] = decode(match[2])
        match = search.exec(query)
    }

    return obj
}

/**
 * Extracts resource value from state.
 * @ignore
 */
function getResourceFromState(state) {
    if (state) {
        var splitIndex = state.indexOf("|")

        if (splitIndex > -1 && splitIndex + 1 < state.length) {
            return state.substring(splitIndex + 1)
        }
    }

    return ""
}

function isEmpty(str: string): boolean {
    return typeof str === "undefined" || !str || 0 === str.length
}

function has(obj: any, key: string): boolean {
    return !!obj && Object.hasOwnProperty.call(obj, key)
}

function now() {
    return Math.round(Date.now() / 1000)
}

/**
 * Generates RFC4122 version 4 guid (128 bits)
 * @ignore
 */
function guid(): string {
    // RFC4122: The version 4 UUID is meant for generating UUIDs from truly-random or
    // pseudo-random numbers.
    // The algorithm is as follows:
    //     Set the two most significant bits (bits 6 and 7) of the
    //        clock_seq_hi_and_reserved to zero and one, respectively.
    //     Set the four most significant bits (bits 12 through 15) of the
    //        time_hi_and_version field to the 4-bit version number from
    //        Section 4.1.3. Version4
    //     Set all the other bits to randomly (or pseudo-randomly) chosen
    //     values.
    // UUID                   = time-low "-" time-mid "-"time-high-and-version "-"clock-seq-reserved and low(2hexOctet)"-" node
    // time-low               = 4hexOctet
    // time-mid               = 2hexOctet
    // time-high-and-version  = 2hexOctet
    // clock-seq-and-reserved = hexOctet:
    // clock-seq-low          = hexOctet
    // node                   = 6hexOctet
    // Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    // y could be 1000, 1001, 1010, 1011 since most significant two bits needs to be 10
    // y values are 8, 9, A, B
    // @ts-expect-error
    var cryptoObj = window.crypto || window.msCrypto // for IE 11
    var buffer = new Uint8Array(16)
    cryptoObj.getRandomValues(buffer)
    //buffer[6] and buffer[7] represents the time_hi_and_version field. We will set the four most significant bits (4 through 7) of buffer[6] to represent decimal number 4 (UUID version number).
    buffer[6] |= 0x40 //buffer[6] | 01000000 will set the 6 bit to 1.
    buffer[6] &= 0x4f //buffer[6] & 01001111 will set the 4, 5, and 7 bit to 0 such that bits 4-7 == 0100 = "4".
    //buffer[8] represents the clock_seq_hi_and_reserved field. We will set the two most significant bits (6 and 7) of the clock_seq_hi_and_reserved to zero and one, respectively.
    buffer[8] |= 0x80 //buffer[8] | 10000000 will set the 7 bit to 1.
    buffer[8] &= 0xbf //buffer[8] & 10111111 will set the 6 bit to 0.
    buffer = buffer.map((n: any) => {
        let hex = n.toString(16)
        while (hex.length < 2) {
            hex = "0" + hex
        }
        return hex
    })
    return (
        buffer[0] +
        buffer[1] +
        buffer[2] +
        buffer[3] +
        "-" +
        buffer[4] +
        buffer[5] +
        "-" +
        buffer[6] +
        buffer[7] +
        "-" +
        buffer[8] +
        buffer[9] +
        "-" +
        buffer[10] +
        buffer[11] +
        buffer[12] +
        buffer[13] +
        buffer[14] +
        buffer[15]
    )
}
