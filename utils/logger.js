const { createLogger, format, transports } = require("winston");
const path = require("path");

// Define the log format
const logFormat = format.combine(
  format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
  format.errors({ stack: true }),
  format.splat(),
  format.json()
);

// Initialize Winston Logger
const logger = createLogger({
  level: "info", // Minimum level of messages to log
  format: logFormat,
  transports: [
    // - Write all logs with level `error` and below to `error.log`
    new transports.File({
      filename: path.join("logs", "error.log"),
      level: "error",
    }),

    // - Write all logs with level `info` and below to `combined.log`
    new transports.File({ filename: path.join("logs", "combined.log") }),
  ],
});

// If not in production, also log to the console with colorized output
if (process.env.NODE_ENV !== "production") {
  logger.add(
    new transports.Console({
      format: format.combine(format.colorize(), format.simple()),
    })
  );
}

module.exports = logger;
