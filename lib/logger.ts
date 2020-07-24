export enum LogLevel {
    Error = 0,
    Warn,
    Info,
    Verbose,
}

const LOG_LEVEL_LABELS = {
    [LogLevel.Error]: "ERROR",
    [LogLevel.Warn]: "WARNING",
    [LogLevel.Info]: "INFO",
    [LogLevel.Verbose]: "VERBOSE",
}

export const Logger = {
    pii: false,
    correlationId: undefined,
    level: LogLevel.Error,

    /**
     * Checks the Logging Level, constructs the Log message and logs it. Users need to implement/override this method to turn on Logging.
     * @param {number} level  -  Level can be set 0,1,2 and 3 which turns on 'error', 'warning', 'info' or 'verbose' level logging respectively.
     * @param {string} message  -  Message to log.
     * @param {string} error  -  Error to log.
     */
    log(
        level: LogLevel,
        message: string,
        error: Error | string | undefined | null,
        containsPii = false,
    ) {
        if (containsPii && !this.pii) return

        if (level <= this.level) {
            let timestamp = new Date().toUTCString()
            let formattedMessage =
                timestamp +
                ":" +
                (this.correlationId ? this.correlationId + "-" : "") +
                LOG_LEVEL_LABELS[level] +
                ": " +
                message

            if (error) {
                // @ts-expect-error
                formattedMessage += "\nstack:\n" + error.stack
            }

            console.log(formattedMessage)
        }
    },

    /**
     * Logs messages when Logging Level is set to 0.
     * @param {string} message  -  Message to log.
     * @param {string} error  -  Error to log.
     */
    error(message: string, error?: Error) {
        this.log(LogLevel.Error, message, error)
    },

    /**
     * Logs messages when Logging Level is set to 1.
     * @param {string} message  -  Message to log.
     */
    warn(message: string) {
        this.log(LogLevel.Warn, message, null)
    },

    /**
     * Logs messages when Logging Level is set to 2.
     * @param {string} message  -  Message to log.
     */
    info(message: string) {
        this.log(LogLevel.Info, message, null)
    },

    /**
     * Logs messages when Logging Level is set to 3.
     * @param {string} message  -  Message to log.
     */
    verbose(message: string) {
        this.log(LogLevel.Verbose, message, null)
    },

    /**
     * Logs Pii messages when Logging Level is set to 0 and window.piiLoggingEnabled is set to true.
     * @param {string} message  -  Message to log.
     * @param {string} error  -  Error to log.
     */
    errorPii(message: string, error: string) {
        this.log(LogLevel.Error, message, error, true)
    },

    /**
     * Logs  Pii messages when Logging Level is set to 1 and window.piiLoggingEnabled is set to true.
     * @param {string} message  -  Message to log.
     */
    warnPii(message: string) {
        this.log(LogLevel.Warn, message, null, true)
    },

    /**
     * Logs messages when Logging Level is set to 2 and window.piiLoggingEnabled is set to true.
     * @param {string} message  -  Message to log.
     */
    infoPii(message: string) {
        this.log(LogLevel.Info, message, null, true)
    },

    /**
     * Logs messages when Logging Level is set to 3 and window.piiLoggingEnabled is set to true.
     * @param {string} message  -  Message to log.
     */
    verbosePii(message: string) {
        this.log(LogLevel.Verbose, message, null, true)
    },
}
