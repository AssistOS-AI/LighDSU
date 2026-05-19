"use strict";

const { canonicalJSONStringify } = require("./utils");

function encodeActorMessage(event) {
  const message = {
    eventType: event.eventType,
    seq: event.seq,
    timestampMs: event.timestampMs
  };
  const fields = ["brickMapHash", "payloadHash", "subjectHash", "resourceHash", "permissions", "policyWord", "keyEpoch", "grantId"];
  for (const field of fields) {
    if (event[field] === undefined) continue;
    message[field] = Buffer.isBuffer(event[field]) ? event[field].toString("hex") : event[field];
  }
  return Buffer.from(canonicalJSONStringify(message));
}

module.exports = { encodeActorMessage };
