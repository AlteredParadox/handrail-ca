// handrail-ca — a lightweight web UI for step-ca.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

/* Saves the files that the page with a generated key carries.

   The files are in the page, as base64 in attributes of the buttons, and
   are saved from there: a button makes the file in the browser's memory
   and saves it under a blob: address, which is a random name and nothing
   more. The file must never be the address itself (a data: link). A
   browser keeps the address of what it downloads in its history, and that
   would keep the private key there.

   Without this script the buttons stay hidden and the page says how to
   take the files from its text instead. */
(function () {
  "use strict";

  var probe = document.createElement("a");
  if (!window.Blob || !window.URL || !URL.createObjectURL || !window.atob || !window.Uint8Array || !("download" in probe)) {
    return;
  }

  function each(selector, act) {
    var found = document.querySelectorAll(selector);
    for (var i = 0; i < found.length; i++) {
      act(found[i]);
    }
  }

  function save(event) {
    var button = event.currentTarget;
    var text = window.atob(button.getAttribute("data-save-body"));
    var bytes = new Uint8Array(text.length);
    for (var i = 0; i < text.length; i++) {
      bytes[i] = text.charCodeAt(i);
    }
    var address = URL.createObjectURL(new Blob([bytes], { type: button.getAttribute("data-save-type") }));
    var link = document.createElement("a");
    link.href = address;
    link.download = button.getAttribute("data-save-name");
    link.hidden = true;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    // The save has begun by now; the name is of no more use.
    setTimeout(function () { URL.revokeObjectURL(address); }, 60000);
  }

  each("button[data-save-body]", function (button) {
    button.addEventListener("click", save);
    button.hidden = false;
  });
  each("[data-save-on]", function (shown) { shown.hidden = false; });
  each("[data-save-off]", function (hidden) { hidden.hidden = true; });
})();
