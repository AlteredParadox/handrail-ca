// ESLint flat config for the embedded front end (internal/web/static/*.js)
// and its Node test, run by `make jscheck`. Correctness rules only. The
// page script is plain script code in one function, so every browser
// global it uses is listed here, and anything else that is referenced but
// never declared is an error: that would be a ReferenceError at the moment
// a button is pressed, which no Go test sees.
const rules = { "no-undef": "error", "no-unreachable": "error", "no-dupe-keys": "error", "no-unused-vars": "error" };

export default [{
  files: ["**/*.js"],
  languageOptions: {
    ecmaVersion: 2019,
    sourceType: "script",
    globals: { window: "readonly", document: "readonly", URL: "readonly", Blob: "readonly", Uint8Array: "readonly", setTimeout: "readonly" },
  },
  rules,
}, {
  files: ["**/*_test.mjs"],
  languageOptions: {
    ecmaVersion: 2022,
    sourceType: "module",
    globals: { URL: "readonly", Buffer: "readonly", Uint8Array: "readonly", Map: "readonly", Object: "readonly" },
  },
  rules,
}];
