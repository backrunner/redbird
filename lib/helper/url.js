const { URL } = require('url');

/** @type {(url: string) => URL} */
const parseUrl = (url) => new URL(url);

module.exports = {
  parseUrl,
};
