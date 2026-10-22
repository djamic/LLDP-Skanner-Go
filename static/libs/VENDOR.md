# Vendored libraries

The UI runs offline, so its libraries are served from this directory and never
from a CDN. The files below are byte-for-byte copies of the upstream releases;
do not edit them. Each library keeps its license next to it, and every
minified JavaScript file starts with the upstream license header.

The older files in this directory (d3, mermaid, xterm, chart.js) were added
before this record was started and are not listed here.

## jQuery 3.7.1

- License: MIT (`jquery/LICENSE.txt`, header `/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */`)
- Source: <https://code.jquery.com/jquery-3.7.1.min.js>
- Same bytes as `package/dist/jquery.min.js` of the npm tarball
  <https://registry.npmjs.org/jquery/-/jquery-3.7.1.tgz>
  (registry sha512 `m4avr8yL8kmFN8psrbFFFmB/If14iN5o9nw/NgnnM+kybDJpRsAynV2BsfpTYrTRysYUdADVD7CkUUizgkpLfg==`,
  verified), and its sha256 is the official subresource-integrity value
  `sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=`.
- `jquery/LICENSE.txt` is `package/LICENSE.txt` of that tarball.
- Used by: jsTree (the Tree tab, `static/tree.js`).

## jsTree 3.3.16

- License: MIT (`jstree/LICENSE-MIT`, header `/*! jsTree - v3.3.16 - 2023-09-19 - (MIT) */`)
- Source: the npm tarball <https://registry.npmjs.org/jstree/-/jstree-3.3.16.tgz>
  (registry sha1 `43e3a8a1ee270ddff514317250d5e85b95d63c52` and sha512
  `yeeIJffi2WAqyMeHufXj/Ozy7GqgKdDkxfN8L8lwbG0h1cw/TgDafWmyhroH4AKgDSk9yW1W6jiJZu4zXAqzXw==`,
  both verified), files `package/dist/jstree.min.js`,
  `package/dist/themes/default/*` and `package/LICENSE-MIT`.
- `jstree.min.js` and `themes/default/style.min.css` are also identical to
  `dist/` of the git tag 3.3.16 of <https://github.com/vakata/jstree>.
- Only the default theme is vendored; `static/style.css` adapts its colours to
  the dark UI (`#topologyTree` rules).

## Checksums

Run `sha256sum -c` in `static/libs/` with these lines:

```
fc9a93dd241f6b045cbff0481cf4e1901becd0e12fb45166a8f17f95823f0b1a  jquery/jquery-3.7.1.min.js
d4db9ebe6f29f5168eac45ad713f055623ac5d0dcd5ba92da23d650ae012020d  jquery/LICENSE.txt
6cb77a3aa483e057f7b9ec8ab3572fbbf987865169b3fed22743faeb4930b84e  jstree/jstree.min.js
31211520f079a45fbe812303d02e864ce4465359715b7a10cb92852a6f8927a6  jstree/LICENSE-MIT
a0e940031a2893b30c999476073c0ccb774fdb08614171b7f2b721f4ce0a7a10  jstree/themes/default/style.min.css
3a5c5ca760a324913b14af3e9c0f496b50d5c09d17dcf09786261881c8200f8d  jstree/themes/default/32px.png
a83492a1563137335ce3d41d82552c17104ebea9bb80c3dbe7673201b92197d7  jstree/themes/default/40px.png
28e3fcaacae52189201f54a20576ee63c7450be82a0ee55398ac2f51bed98fac  jstree/themes/default/throbber.gif
```
