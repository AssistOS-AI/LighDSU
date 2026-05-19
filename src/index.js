"use strict";

const { LightDSUEngine } = require("./engine");
const { DefaultDidStrategy } = require("./defaultDidStrategy");
const { PERMISSIONS, EVENT_TYPES, SSI_TYPES } = require("./constants");
const { ERROR_CODES, LightDSUError } = require("./errors");

module.exports = {
  LightDSUEngine,
  DefaultDidStrategy,
  PERMISSIONS,
  EVENT_TYPES,
  SSI_TYPES,
  ERROR_CODES,
  LightDSUError
};
