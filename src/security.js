'use strict';

// VULNERABLE revision of src/security.js — used on the `vulnerable` branch.
// It has no Cache-Control input guard, which is the precondition of
// CVE-2022-25881 in this project.

const HTML_ESCAPES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;'
};

function escapeHtml(value) {
  return String(value).replace(/[&<>"'`]/g, (ch) => HTML_ESCAPES[ch]);
}

function escapeLike(value) {
  return String(value).replace(/[\\%_]/g, (ch) => '\\' + ch);
}

module.exports = { escapeHtml, escapeLike };