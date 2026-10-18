function replayFields(event, fields) {
  const input = {}, errors = [], encoder = new TextEncoder();
  const size = value => encoder.encode(value).length;
  const credential = value => /tunn_(?:mcp|ep|gr|sk|app|inv)_/.test(value);
  const fail = message => { throw new Error(message); };
  const check = (field, label, validate) => {
    try { validate(); } catch (error) { errors.push({field, message:label + ': ' + error.message + ' Request not sent.'}); }
  };
  // Decode form values as bytes, like net/url, without rewriting the input.
  const unquery = value => {
    const bytes = encoder.encode(value.replace(/\+/g, ' ')); let decoded = '';
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] === 37) {
        const hex = String.fromCharCode(...bytes.slice(i + 1, i + 3));
        if (!/^[\da-f]{2}$/i.test(hex)) fail('Use valid percent escapes.');
        decoded += String.fromCharCode(parseInt(hex, 16)); i += 2;
      } else decoded += String.fromCharCode(bytes[i]);
    }
    return decoded;
  };
  const query = (raw, captured = false) => {
    const values = new Map();
    for (const pair of raw.split('&')) {
      if (!pair) continue;
      if (pair.includes(';')) fail('Use a valid query.');
      const index = pair.indexOf('='), key = unquery(index < 0 ? pair : pair.slice(0, index));
      const value = unquery(index < 0 ? '' : pair.slice(index + 1));
      if (key.length > 128 || credential(key)) fail('Use the original query fields.');
      if ((!captured && value.includes('[redacted]')) || credential(value)) fail('Restore every hidden value.');
      values.set(key, (values.get(key) || 0) + 1);
    }
    return values;
  };
  if (event.query_redacted) check('path', 'Path and query', () => {
    const path = fields.path;
    if (typeof path !== 'string' || !path) fail('Restore the original path and query.');
    if (size(path) > 2048) fail('Use at most 2048 bytes.');
    if (!path.startsWith('/') || path.startsWith('//') || /[\x00-\x1f\x7f]/.test(path) || /%(?![\da-f]{2})/i.test(path)) fail('Use a valid original path and query.');
    if (path.includes('[redacted]') || credential(path)) fail('Restore every hidden value.');
    const index = path.indexOf('?'), oldIndex = event.path.indexOf('?');
    if (index < 0) fail('Keep every original query field.');
    const rawPath = path.slice(0, index);
    let escapedPath = '';
    const bytes = encoder.encode(rawPath);
    for (let i = 0; i < bytes.length; i++) {
      const ch = String.fromCharCode(bytes[i]);
      if (ch === '%') { escapedPath += String.fromCharCode(...bytes.slice(i, i + 3)); i += 2; }
      else escapedPath += /[A-Za-z0-9\-_.~$&+,/:;=@]/.test(ch) ? ch : '%' + bytes[i].toString(16).toUpperCase().padStart(2, '0');
    }
    if (escapedPath !== event.path.slice(0, oldIndex) || credential(unquery(rawPath))) fail('Keep the original path.');
    const restored = query(path.slice(index + 1));
    // Original query values are markers; only their keys and counts matter.
    const original = query(event.path.slice(oldIndex + 1), true);
    if (restored.size !== original.size || [...original].some(([key, count]) => restored.get(key) !== count)) fail('Keep every original query field.');
    input.path = path;
  });
  if ((event.redacted_headers || []).length) check('headers', 'Headers', () => {
    let headers;
    try { headers = JSON.parse(fields.headers); } catch { fail('Enter a JSON object of header names and text values.'); }
    if (!headers || Array.isArray(headers) || typeof headers !== 'object') fail('Enter a JSON object of header names and text values.');
    const canonical = key => key.toLowerCase().replace(/(^|-)[a-z]/g, part => part.toUpperCase());
    const seen = new Set();
    for (const [key, value] of Object.entries(headers)) {
      const name = canonical(key);
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(key) || size(key) > 128 || !Object.hasOwn(event.headers, name)) fail('Keep only the original header names.');
      if (seen.has(name)) fail('Remove the duplicate ' + name + ' header.');
      seen.add(name);
      if (typeof value !== 'string') fail(name + ' must be text.');
      if (value.includes('[redacted]')) fail('Restore ' + name + '.');
      if (/[\r\n\x00]/.test(value)) fail(name + ' cannot contain line breaks or NUL.');
      if (/[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) fail(name + ' cannot contain control characters.');
      if (credential(value)) fail('Restore ' + name + ' without platform credentials.');
      if (size(value) > 1024) fail(name + ' exceeds 1024 bytes.');
      if (['Accept','Accept-Encoding','Content-Type','Content-Length','Host'].includes(name) && value !== event.headers[name]) fail('Keep the captured ' + name + ' value.');
    }
    const missing = Object.keys(event.headers).filter(key => !seen.has(key));
    if (missing.length) fail('Restore ' + missing.join(', ') + '.');
    input.headers = headers;
  });
  if (!event.body_captured && event.request_bytes > 0) check('body', 'Body', () => {
    if (!fields.body) fail('Restore the original body.');
    let encoded = fields.body, binary;
    if (fields.bodyFormat === 'text') {
      const bytes = encoder.encode(fields.body);
      if (bytes.length > 65536) fail('Use at most 64 KiB.');
      binary = Array.from(bytes, byte => String.fromCharCode(byte)).join(''); encoded = btoa(binary);
    } else {
      const compact = encoded.replace(/[\r\n]/g, '');
      if (compact.length > 87384) fail('Use at most 64 KiB.');
      if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(compact)) fail('Enter valid Base64.');
      binary = atob(compact);
    }
    if (binary.length > 65536) fail('Use at most 64 KiB.');
    if (binary.length !== event.request_bytes) fail('Restore exactly ' + event.request_bytes + ' bytes.');
    if (credential(binary)) fail('Remove platform credentials.');
    input.body = encoded;
  });
  if (size(JSON.stringify(input)) > 128 * 1024) errors.push({field:'headers', message:'Replay fields exceed 128 KiB. Request not sent.'});
  return {input, errors};
}
