"use strict";

const request = require("request");
const _ = require("lodash");
const config = require("./config/config");
const async = require("async");
const fs = require("fs");

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;

const IGNORED_IPS = new Set(["127.0.0.1", "255.255.255.255", "0.0.0.0"]);

const NodeCache = require("node-cache");
const tokenCache = new NodeCache({
  stdTTL: 1000 * 1000
});

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function startup(logger) {
  let defaults = {};
  Logger = logger;

  if (typeof config.request.cert === "string" && config.request.cert.length > 0)
    defaults.cert = fs.readFileSync(config.request.cert);

  if (typeof config.request.key === "string" && config.request.key.length > 0)
    defaults.key = fs.readFileSync(config.request.key);

  if (
    typeof config.request.passphrase === "string" &&
    config.request.passphrase.length > 0
  )
    defaults.passphrase = config.request.passphrase;

  if (typeof config.request.ca === "string" && config.request.ca.length > 0)
    defaults.ca = fs.readFileSync(config.request.ca);

  if (typeof config.request.proxy === "string" && config.request.proxy.length > 0)
    defaults.proxy = config.request.proxy;

  if (typeof config.request.rejectUnauthorized === "boolean")
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;

  requestWithDefaults = request.defaults(defaults);
}

function getAuthToken(options, callback) {
  const cacheKey = options.url + options.apiKey + options.apiSecret;
  let token = tokenCache.get(cacheKey);
  if (token) return callback(null, token);

  requestWithDefaults(
    {
      method: "POST",
      uri: `${options.url}/iroh/oauth2/token`,
      auth: {
        user: options.clientId,
        pass: options.clientPassword
      },
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json"
      },
      form: {
        grant_type: "client_credentials"
      },
      json: true
    },
    (err, resp, body) => {
      if (err) return callback(err);

      Logger.trace({ body }, "Result of token lookup");

      if (resp.statusCode != 200)
        return callback({ err: new Error("status code was not 200"), body });

      tokenCache.set(cacheKey, body.access_token);

      Logger.trace({ tokenCache }, "Checking TokenCache");

      callback(null, body.access_token);
    }
  );
}

function doLookup(entities, { url, ..._options }, cb) {
  let lookupResults = [];
  let tasks = [];
  let options = { ..._options, url: url.endsWith("/") ? url.slice(0, -1) : url };
  Logger.debug(entities);

  getAuthToken(options, (err, token) => {
    if (err) {
      Logger.error({ err }, "get token errored");
      return cb({ 
        err: "Error getting Auth Token",
        detail: `Auth Error: Verify your URL, Client ID, and Client password are correct ${err}`
      });
    }

    Logger.trace({ token }, "Token in doLookup");

    entities
      .filter(({ isIP, value }) => !isIP || (isIP && !IGNORED_IPS.has(value)))
      .forEach((entity) => {
        let requestOptions = {
          method: "POST",
          uri: `${options.url}/iroh/iroh-enrich/observe/observables`,
          headers: {
            Authorization: "Bearer " + token,
            "Content-Type": "application/json",
            Accept: "application/json",
            "Client-Type": "API"
          },
          json: true
        };

        if (entity.isIPv4) {
          requestOptions.body = [{ value: entity.value.toLowerCase(), type: "ip" }];
        } else if (entity.isMD5) {
          requestOptions.body = [{ value: entity.value.toLowerCase(), type: "md5" }];
        } else if (entity.isSHA1) {
          requestOptions.body = [{ value: entity.value.toLowerCase(), type: "sha1" }];
        } else if (entity.isSHA256) {
          requestOptions.body = [{ value: entity.value.toLowerCase(), type: "sha256" }];
        } else if (entity.isDomain) {
          requestOptions.body = [{ value: entity.value.toLowerCase(), type: "domain" }];
        } else if (entity.isEmail) {
          requestOptions.body = [{ value: entity.value.toLowerCase(), type: "email" }];
        } else {
          return;
        }

        Logger.trace({ uri: requestOptions }, "Request URI");

        tasks.push(function(done) {
          requestWithDefaults(requestOptions, function(error, res, body) {
            if (error) return done(error);

            Logger.trace(
              { body, statusCode: res ? res.statusCode : "N/A" },
              "Result of Lookup"
            );

            let result = {};

            if (res.statusCode === 200) {
              result = { entity, body };
            } else if (res.statusCode === 404) {
              result = {
                entity,
                body: null
              };
            } else if (res.statusCode === 202) {
              result = {
                entity,
                body: null
              };
            } else if (res.statusCode === 403) {
              error = {
                err: "Non-Existent Device",
                detail:
                  "A warning will result if an investigation is performed with a non-existent device."
              };
            } else if (res.statusCode === 429) {
              error = {
                err: "API Limit Exceeded",
                detail:
                  "You may have exceeded the rate limits for your organization or package"
              };
            } else if (Math.round(res.statusCode / 10) * 10 === 500) {
              error = {
                err: "Server Error",
                detail: "Unexpected Server Error"
              };
            }

            done(null, result);
          });
        });
      });

    async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
      if (err) {
        Logger.error({ err }, "Error");
        return cb({ err, detail: "Error Requesting Observables" });
      }
      
      Logger.trace({ results }, "Results")
      results.forEach((result) => {
        if (
          result.body === null ||
          _isMiss(result.body.data) ||
          _.isEmpty(result.body.data)
        ) {
          lookupResults.push({
            entity: result.entity,
            data: null
          });
        } else {
          lookupResults.push({
            entity: result.entity,
            data: {
              summary: [],
              details: result.body
            }
          });
        }
      });

      Logger.debug({ lookupResults }, "Results");
      cb(null, lookupResults);
    });
  });
}

function _isMiss(body) {
  return !body || (body && Array.isArray(body) && body.length === 0);
}

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== "string" ||
    (typeof options[optionName].value === "string" &&
      options[optionName].value.length === 0)
  )
    errors.push({
      key: optionName,
      message: errMessage
    });
}

const validateUrlOption = ({ value: url }, otherErrors = []) =>
  url && url.endsWith("//") && 
    otherErrors.push({
      key: "url",
      message: "Your Url must not end with a //"
    });

function validateOptions(options, callback) {
  let errors = [];

  validateUrlOption(options.url, errors);
  validateStringOption(errors, options, "url", "You must provide a valid API URL");
  validateStringOption(errors, options, "clientId", "You must provide a valid Client ID");
  validateStringOption(
    errors,
    options,
    "clientPassword",
    "You must provide a valid Client Password"
  );
  callback(null, errors);
}

module.exports = {
  doLookup,
  startup,
  validateOptions
};
