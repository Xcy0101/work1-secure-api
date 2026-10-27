'use strict';

// Fixed revision of src/security.js.
// Added by the fix commit: a linear, allow-list based guard that runs before
// the Cache-Control value is handed to http-cache-semantics.

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

const MAX_CACHE_CONTROL_LENGTH = 1024;
const MAX_DIRECTIVES = 32;

// Bounds the input size, so a super-linear parser can never be fed a long run
// of characters; the pattern is a single character class and is linear itself.
function checkCacheControl(value) {
  if (value === undefined) return { ok: true, value: '' };
  if (typeof value !== 'string') return { ok: false, reason: 'not_a_string' };
  if (value.length > MAX_CACHE_CONTROL_LENGTH) return { ok: false, reason: 'too_long' };
  if (!/^[\t\x20-\x7E]*$/.test(value)) return { ok: false, reason: 'illegal_characters' };
  if (value.split(',').length > MAX_DIRECTIVES) {
    return { ok: false, reason: 'too_many_directives' };
  }
  return { ok: true, value };
}

module.exports = {
  escapeHtml,
  escapeLike,
  checkCacheControl,
  MAX_CACHE_CONTROL_LENGTH
};