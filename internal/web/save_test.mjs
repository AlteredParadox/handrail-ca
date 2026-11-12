// Runs static/save.js against a stand-in for the page, with `node --test`
// (make jscheck): the buttons appear, a press saves the file's own bytes
// under a blob: address with the file's name, and no file is ever its own
// address.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("./static/save.js", import.meta.url), "utf8");

// page is a stand-in document with the given buttons and the two notes
// that say whether the buttons work.
function page(buttons, capable = true) {
  const element = (attributes) => ({
    hidden: attributes.hidden === true,
    listeners: {},
    getAttribute(name) { return name in attributes ? attributes[name] : null; },
    addEventListener(kind, act) { this.listeners[kind] = act; },
  });
  const made = buttons.map((b) => element({ hidden: true, "data-save-name": b.name, "data-save-type": b.type, "data-save-body": b.body }));
  const on = element({ hidden: true });
  const off = element({});
  const saved = [];
  const blobs = new Map();
  const revoked = [];
  const timers = [];
  const document = {
    body: {
      children: [],
      appendChild(child) { this.children.push(child); },
      removeChild(child) { this.children.splice(this.children.indexOf(child), 1); },
    },
    createElement(tag) {
      assert.equal(tag, "a");
      const link = { tag, click() { saved.push({ href: this.href, download: this.download, attached: document.body.children.includes(this) }); } };
      if (capable) {
        link.download = "";
      }
      return link;
    },
    querySelectorAll(selector) {
      return { "button[data-save-body]": made, "[data-save-on]": [on], "[data-save-off]": [off] }[selector] || [];
    },
  };
  class Blob {
    constructor(parts, options) { this.parts = parts; this.type = options.type; }
  }
  const URL = {
    createObjectURL(blob) { const address = `blob:http://handrail.test/${blobs.size + 1}`; blobs.set(address, blob); return address; },
    revokeObjectURL(address) { revoked.push(address); },
  };
  const window = { Blob, URL, Uint8Array, atob: (text) => Buffer.from(text, "base64").toString("latin1") };
  vm.runInNewContext(source, { window, document, URL, Blob, Uint8Array, setTimeout: (act, after) => timers.push({ act, after }) });
  return { made, on, off, saved, blobs, revoked, timers, document };
}

const key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n";
const pfx = Buffer.from([0x30, 0x82, 0x00, 0xff, 0x80, 0x00, 0x7f, 0xfe]);
const files = [
  { name: "git.internal.example.key", type: "application/x-pem-file", body: Buffer.from(key).toString("base64") },
  { name: "git.internal.example.pfx", type: "application/x-pkcs12", body: pfx.toString("base64") },
];

test("the buttons are shown and the page stops saying they do not work", () => {
  const p = page(files);
  assert.deepEqual(p.made.map((b) => b.hidden), [false, false]);
  assert.equal(p.on.hidden, false);
  assert.equal(p.off.hidden, true);
  assert.equal(p.saved.length, 0, "nothing is saved before a button is pressed");
});

test("a press saves the file's own bytes, under its name, from a blob: address", () => {
  const p = page(files);
  p.made.forEach((button) => button.listeners.click({ currentTarget: button }));
  assert.equal(p.saved.length, 2);
  p.saved.forEach((save, i) => {
    assert.equal(save.download, files[i].name);
    assert.match(save.href, /^blob:/);
    assert.ok(save.attached, "the link is in the page when it is pressed");
    const blob = p.blobs.get(save.href);
    assert.equal(blob.type, files[i].type);
    assert.deepEqual(Buffer.from(blob.parts[0]), Buffer.from(files[i].body, "base64"));
  });
  assert.deepEqual(Buffer.from(p.blobs.get(p.saved[1].href).parts[0]), pfx, "bytes above 127 come through as they are");
  assert.equal(p.document.body.children.length, 0, "the links are taken out of the page again");
});

test("no file is its own address, and the address is given up afterwards", () => {
  const p = page(files);
  p.made.forEach((button) => button.listeners.click({ currentTarget: button }));
  for (const save of p.saved) {
    assert.ok(!save.href.startsWith("data:"));
    for (const file of files) {
      assert.ok(!save.href.includes(file.body.slice(0, 16)), "the address holds none of the file");
    }
  }
  assert.equal(p.revoked.length, 0);
  p.timers.forEach((timer) => timer.act());
  assert.deepEqual(p.revoked, p.saved.map((save) => save.href));
});

test("a browser that cannot save this way keeps the buttons hidden and the note shown", () => {
  const p = page(files, false);
  assert.deepEqual(p.made.map((b) => b.hidden), [true, true]);
  assert.equal(p.on.hidden, true);
  assert.equal(p.off.hidden, false);
  assert.deepEqual(p.made.map((b) => Object.keys(b.listeners).length), [0, 0]);
});
