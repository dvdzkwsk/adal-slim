export enum StorageKey {
    TOKEN_KEYS = "adal.token.keys",
    ACCESS_TOKEN_KEY = "adal.access.token.key",
    EXPIRATION_KEY = "adal.expiration.key",
    STATE_LOGIN = "adal.state.login",
    STATE_RENEW = "adal.state.renew",
    NONCE_IDTOKEN = "adal.nonce.idtoken",
    SESSION_STATE = "adal.session.state",
    USERNAME = "adal.username",
    IDTOKEN = "adal.idtoken",
    ERROR = "adal.error",
    ERROR_DESCRIPTION = "adal.error.description",
    LOGIN_REQUEST = "adal.login.request",
    LOGIN_ERROR = "adal.login.error",
    RENEW_STATUS = "adal.token.renew.status",
}

interface IStorage {
    getItem(key: string): any
    setItem(key: string, value: any, preserve?: boolean): void
}

export const Storage: IStorage = (() => {
    function supportsStorage(type: string) {
        const storage = window[type]
        if (!storage) {
            return false
        }
        const testKey = "__test__"
        storage.setItem(testKey, testKey)
        if (storage.getItem(testKey) !== testKey) {
            return false
        }
        storage.removeItem(testKey)
        if (storage.getItem(testKey)) {
            return false
        }
        return true
    }

    if (supportsStorage("localStorage")) return localStorage
    if (supportsStorage("sessionStorage")) return sessionStorage
    return {getItem() {}, setItem() {}} as IStorage
})()
