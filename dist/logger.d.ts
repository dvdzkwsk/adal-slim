export declare enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Verbose = 3
}
export declare const Logger: {
    pii: boolean;
    correlationId: undefined;
    level: LogLevel;
    /**
     * Checks the Logging Level, constructs the Log message and logs it. Users need to implement/override this method to turn on Logging.
     * @param {number} level  -  Level can be set 0,1,2 and 3 which turns on 'error', 'warning', 'info' or 'verbose' level logging respectively.
     * @param {string} message  -  Message to log.
     * @param {string} error  -  Error to log.
     */
    log(level: LogLevel, message: string, error: Error | string | undefined | null, containsPii?: boolean): void;
    /**
     * Logs messages when Logging Level is set to 0.
     * @param {string} message  -  Message to log.
     * @param {string} error  -  Error to log.
     */
    error(message: string, error?: Error | undefined): void;
    /**
     * Logs messages when Logging Level is set to 1.
     * @param {string} message  -  Message to log.
     */
    warn(message: string): void;
    /**
     * Logs messages when Logging Level is set to 2.
     * @param {string} message  -  Message to log.
     */
    info(message: string): void;
    /**
     * Logs messages when Logging Level is set to 3.
     * @param {string} message  -  Message to log.
     */
    verbose(message: string): void;
    /**
     * Logs Pii messages when Logging Level is set to 0 and window.piiLoggingEnabled is set to true.
     * @param {string} message  -  Message to log.
     * @param {string} error  -  Error to log.
     */
    errorPii(message: string, error: string): void;
    /**
     * Logs  Pii messages when Logging Level is set to 1 and window.piiLoggingEnabled is set to true.
     * @param {string} message  -  Message to log.
     */
    warnPii(message: string): void;
    /**
     * Logs messages when Logging Level is set to 2 and window.piiLoggingEnabled is set to true.
     * @param {string} message  -  Message to log.
     */
    infoPii(message: string): void;
    /**
     * Logs messages when Logging Level is set to 3 and window.piiLoggingEnabled is set to true.
     * @param {string} message  -  Message to log.
     */
    verbosePii(message: string): void;
};
