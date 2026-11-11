#!/usr/bin/env node
// Supported build-time bridge to the SDK's canonical key/configuration identities.
import { readFileSync } from "node:fs";
import {
  parseVerificationKey,
  prepareRuntimeKey,
} from "../../dist/index.js";
import { fixedConfigurationHash } from "../../dist/fixed.js";
import {
  parseProfile,
  profileHash,
} from "../../dist/current.js";
try {
  const request = JSON.parse(readFileSync(0, "utf8"));
  let result;
  if (request.operation === "key") {
    const key = parseVerificationKey(request.verificationKey);
    result = { verificationKey: key, keyHash: prepareRuntimeKey(key).keyHash };
  } else if (request.operation === "fixed") {
    result = {
      configurationHash: fixedConfigurationHash({
        schema: "groth16-fixed-global66-v1",
        verificationKey: request.verificationKey,
        tPreimage: request.tPreimage,
      }),
    };
  } else if (request.operation === "profile") {
    result = {
      profile: parseProfile(request.profile),
      profileSha256: profileHash(request.profile),
    };
  } else throw new Error("Unknown generator identity operation");
  process.stdout.write(
    JSON.stringify(result, (_, value) =>
      typeof value === "bigint" ? value.toString() : value,
    ),
  );
} catch (error) {
  console.error(`Groth16 generation: ${error.message}`);
  process.exitCode = 1;
}
