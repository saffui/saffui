// OpenID Connect Session Management 1.0 §4.1. A relying party loads this in a
// frame and posts it `client_id + " " + session_state`; the answer says whether
// the login behind that value is still the one this browser holds.
//
// The comparison happens here rather than at the server on purpose: §4 exists
// so a relying party can ask without a request reaching anybody, which is what
// makes it cheap enough to ask often.
//
// The digest is computed here rather than through WebCrypto, which is offered
// only in a secure context and rejects everywhere else. A frame that answered
// `error` wherever the browser judged its parent untrustworthy would be one
// that fails exactly where somebody is looking into why.
(function () {
  "use strict";

  // FIPS 180-4 §4.2.2.
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function rotr(value, by) {
    return (value >>> by) | (value << (32 - by));
  }

  // The message as UTF-8 bytes. What reaches here is an identifier, an origin
  // and two base64url values, so ASCII in practice; done properly anyway,
  // because a client identifier is whatever a registration put in it.
  function bytesOf(text) {
    var out = [];
    for (var i = 0; i < text.length; i += 1) {
      var point = text.charCodeAt(i);
      // A pair of halves is one character above the basic plane. A lone half
      // is not a character at all and becomes the replacement, which is what
      // every other encoder does with it.
      if (point >= 0xd800 && point <= 0xdbff && i + 1 < text.length) {
        var low = text.charCodeAt(i + 1);
        if (low >= 0xdc00 && low <= 0xdfff) {
          point = 0x10000 + ((point - 0xd800) << 10) + (low - 0xdc00);
          i += 1;
        } else {
          point = 0xfffd;
        }
      } else if (point >= 0xd800 && point <= 0xdfff) {
        point = 0xfffd;
      }

      if (point < 0x80) {
        out.push(point);
      } else if (point < 0x800) {
        out.push(0xc0 | (point >> 6), 0x80 | (point & 0x3f));
      } else if (point < 0x10000) {
        out.push(
          0xe0 | (point >> 12),
          0x80 | ((point >> 6) & 0x3f),
          0x80 | (point & 0x3f)
        );
      } else {
        out.push(
          0xf0 | (point >> 18),
          0x80 | ((point >> 12) & 0x3f),
          0x80 | ((point >> 6) & 0x3f),
          0x80 | (point & 0x3f)
        );
      }
    }
    return out;
  }

  function sha256(text) {
    var bytes = bytesOf(text);
    var bits = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) {
      bytes.push(0);
    }
    // The length as 64 bits. The high half is zero for anything this frame is
    // ever handed, and written rather than assumed.
    for (var shift = 56; shift >= 0; shift -= 8) {
      bytes.push(shift >= 32 ? 0 : (bits >>> shift) & 0xff);
    }

    var h = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    var w = new Array(64);
    for (var at = 0; at < bytes.length; at += 64) {
      var i;
      for (i = 0; i < 16; i += 1) {
        w[i] =
          (bytes[at + i * 4] << 24) |
          (bytes[at + i * 4 + 1] << 16) |
          (bytes[at + i * 4 + 2] << 8) |
          bytes[at + i * 4 + 3];
      }
      for (i = 16; i < 64; i += 1) {
        var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }

      var a = h[0], b = h[1], c = h[2], d = h[3];
      var e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i += 1) {
        var big1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var choose = (e & f) ^ (~e & g);
        var one = (hh + big1 + choose + K[i] + w[i]) | 0;
        var big0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var most = (a & b) ^ (a & c) ^ (b & c);
        var two = (big0 + most) | 0;
        hh = g; g = f; f = e;
        e = (d + one) | 0;
        d = c; c = b; b = a;
        a = (one + two) | 0;
      }
      var held = [a, b, c, d, e, f, g, hh];
      for (i = 0; i < 8; i += 1) {
        h[i] = (h[i] + held[i]) | 0;
      }
    }

    var out = "";
    for (var n = 0; n < 8; n += 1) {
      out += ("00000000" + (h[n] >>> 0).toString(16)).slice(-8);
    }
    return out;
  }

  // The cookie the provider set for this realm, which says which login this
  // browser is holding. Absent means none, which is a change from any state a
  // client was told.
  function held() {
    var wanted = "saffui_op_state=";
    var all = document.cookie ? document.cookie.split("; ") : [];
    for (var i = 0; i < all.length; i += 1) {
      if (all[i].indexOf(wanted) === 0) {
        return all[i].slice(wanted.length);
      }
    }
    return "";
  }

  window.addEventListener("message", function (event) {
    if (!event.source) {
      return;
    }
    var told = "error";
    // The message is `client_id + " " + session_state`, and the state is the
    // digest and the salt it was made with.
    if (typeof event.data === "string") {
      var space = event.data.indexOf(" ");
      var state = space < 1 ? "" : event.data.slice(space + 1);
      var dot = state.lastIndexOf(".");
      if (space >= 1 && dot >= 1) {
        var salt = state.slice(dot + 1);
        // The origin is the frame's parent, which is the relying party asking.
        // Taken from the message and never from its contents: a page that
        // could name its own origin could ask about somebody else's session.
        var over =
          event.data.slice(0, space) +
          " " +
          event.origin +
          " " +
          held() +
          " " +
          salt;
        told = sha256(over) + "." + salt === state ? "unchanged" : "changed";
      }
    }
    event.source.postMessage(told, event.origin);
  });
})();
