/*eslint-env node */
'use strict';
const http2 = require('http2');
const http = require('http');
const h2Proxy = require('http2-proxy');
const httpProxy = require('http-proxy');
const validUrl = require('valid-url');
const path = require('path');
const fs = require('fs');
const _ = require('lodash');
const cluster = require('cluster');
const hash = require('object-hash');
const LRUCache = require('lru-cache');
const letsencrypt = require('./letsencrypt.js');
const tls = require('tls');
const { parseUrl } = require('./helper/url');

const routeCache = new LRUCache({
  max: 1000,
  maxAge: 300,
  updateAgeOnGet: true,
});

const secureContext = {};

function ReverseProxy(opts) {
  if (!(this instanceof ReverseProxy)) {
    return new ReverseProxy(opts);
  }

  this.opts = opts = opts || {};

  if (this.opts.httpProxy == undefined) {
    this.opts.httpProxy = {};
  }

  let log;
  if (opts.logger && typeof opts.logger === 'object') {
    log = this.log = opts.logger;
  }

  if ((opts.cluster && typeof opts.cluster !== 'number') || opts.cluster > 32) {
    throw Error('cluster setting must be an integer less than 32');
  }

  if (opts.cluster && cluster.isMaster) {
    for (let i = 0; i < opts.cluster; i++) {
      cluster.fork();
    }

    cluster.on('exit', function (worker, code, signal) {
      // Fork if a worker dies.
      log &&
        log.error(
          {
            code: code,
            signal: signal,
          },
          'worker died un-expectedly... restarting it.'
        );
      cluster.fork();
    });
  } else {
    this.resolvers = [this._defaultResolver];

    opts.port = opts.port || 8080;

    if (opts.letsencrypt) {
      this.setupLetsencrypt(log, opts);
    }

    if (opts.resolvers) {
      this.addResolver(opts.resolvers);
    }

    //
    // Routing table.
    //
    this.routing = {};

    //
    // Create a proxy server with custom application logic
    //
    const proxyParams = {
      xfwd: opts.xfwd != false,
      prependPath: false,
      secure: true,
      timeout: opts.timeout,
      proxyTimeout: opts.proxyTimeout,
    };
    const proxy = (this.proxy = httpProxy.createProxyServer(proxyParams));

    // Rewrite host of req
    proxy.on('proxyReq', (p, req) => {
      if (req.host != null) {
        p.setHeader('host', req.host);
      }
    });

    //
    // Support NTLM auth
    //
    if (opts.ntlm) {
      proxy.on('proxyRes', function (proxyRes) {
        const key = 'www-authenticate';
        proxyRes.headers[key] = proxyRes.headers[key] && proxyRes.headers[key].split(',');
      });
    }

    //
    // Optionally create an https proxy server.
    //
    if (opts.ssl) {
      this.setupHttpsProxy(proxyParams, websocketsUpgrade, log, opts.ssl);
    }

    //
    // Plain HTTP Proxy
    //
    const server = this.setupHttpProxy(proxy, websocketsUpgrade, log, opts);

    server.listen(opts.port, opts.host);

    if (opts.errorHandler && _.isFunction(opts.errorHandler)) {
      proxy.on('error', opts.errorHandler);
    } else {
      proxy.on('error', handleProxyError);
    }

    log?.info(`Started a Redbird reverse proxy server on port ${opts.port}`);
  }

  function websocketsUpgrade(req, socket, head) {
    socket.on('error', (err) => {
      log?.error(err, 'WebSockets error');
    });
    const src = this._getSource(req);
    this._getTarget(src, req).then((target) => {
      log?.info({ headers: req.headers, target: target }, 'upgrade to websockets');
      if (target) {
        if (target.useTargetHostHeader === true) {
          req.headers.host = target.host;
        }
        h2Proxy.ws(req, socket, head, {
          host: target.host,
          port: target.port,
          path: req.url,
          proxyTimeout: 10 * 1000,
        });
      } else {
        respondNotFound(req, socket);
      }
    });
  }

  function handleProxyError(err, req, res) {
    //
    // Send a 500 http status if headers have been sent
    //

    if (err.code === 'ECONNREFUSED') {
      res.writeHead && res.writeHead(502);
    } else if (!res.headersSent) {
      res.writeHead && res.writeHead(500);
    }

    //
    // Do not log this common error
    //
    if (!err?.message.includes('socket hang up')) {
      log && log.error(err, 'Proxy Error');
    }

    //
    // for this route, try another one.
    //
    res.end(err.code);
  }
}

ReverseProxy.prototype.setupHttpProxy = function (proxy, websocketsUpgrade, log, opts) {
  const httpServerModule = opts.serverModule || http;
  const server = (this.server = httpServerModule.createServer((req, res) => {
    const src = this._getSource(req);
    this._getTarget(src, req, res).then((target) => {
      if (target) {
        if (shouldRedirectToHttps(secureContext, src, target, this)) {
          redirectToHttps(req, res, target, opts.ssl, log);
        } else {
          proxy.web(req, res, {
            target,
            secure: false,
          });
        }
      } else {
        respondNotFound(req, res);
      }
    });
  }));

  //
  // Listen to the `upgrade` event and proxy the
  // WebSocket requests as well.
  //
  server.on('upgrade', websocketsUpgrade);

  server.on('error', function (err) {
    log && log.error(err, 'Server Error');
  });

  return server;
};

function shouldRedirectToHttps(certs, src, target, proxy) {
  return Object.keys(certs).includes(src) && target.sslRedirect && target.host !== proxy.letsencryptHost;
}

ReverseProxy.prototype.setupLetsencrypt = function (log, opts) {
  if (!opts.letsencrypt.path) {
    throw Error('Missing certificate path for Lets Encrypt');
  }
  const letsencryptPort = opts.letsencrypt.port || 3000;
  letsencrypt.init(opts.letsencrypt.path, letsencryptPort, log);

  opts.resolvers = opts.resolvers || [];
  this.letsencryptHost = `127.0.0.1:${letsencryptPort}`;
  const targetHost = `http://${this.letsencryptHost}`;
  const challengeResolver = (host, url) => {
    if (/^\/\.well-known\/acme-challenge/.test(url)) {
      return targetHost + '/' + host;
    }
  };
  challengeResolver.priority = 10000;
  this.addResolver(challengeResolver);
  log && log.info('Chanllenge resolver added.');
};

ReverseProxy.prototype.setupHttpsProxy = function (proxyParams, websocketsUpgrade, log, sslOpts) {
  const ssl = {
    SNICallback: function (hostname, cb) {
      if (cb) {
        cb(null, secureContext?.[hostname]);
      } else {
        return secureContext?.[hostname];
      }
    },
    honorCipherOrder: true,
  };

  if (sslOpts.ca) {
    ssl.ca = getCertData(sslOpts.ca, true);
  }

  if (sslOpts.cert && sslOpts.key) {
    //
    // Default certs for clients that do not support SNI.
    //
    Object.assign(ssl, {
      key: getCertData(sslOpts.key),
      cert: getCertData(sslOpts.cert),
    });
  }

  if (sslOpts.opts) {
    ssl = _.defaults(ssl, sslOpts.opts);
  }

  const httpsServer = (this.httpsServer = http2.createSecureServer({
    ...ssl,
    allowHTTP1: true,
    keepAlive: true,
    noDelay: true,
    maxSessionMemory: 16,
    handshakeTimeout: 60000,
  }, (req, res) => {
    const src = this._getSource(req);

    // set timeout of req
    req.setTimeout(sslOpts.reqTimeout || 120 * 1000);
    res.setTimeout(sslOpts.reqTimeout || 120 * 1000);

    this._getTarget(src, req, res).then((target) => {
      if (target) {
        h2Proxy.web(req, res, {
          host: target.host,
          port: target.port,
          path: req.url,
          proxyTimeout: sslOpts.proxyTimeout || 30 * 1000,
        });
      } else {
        respondNotFound(req, res);
      }
    });
  }));

  httpsServer.on('upgrade', websocketsUpgrade);

  httpsServer.on('error', (err) => {
    log && log.error(err, 'HTTPS Server Error');
  });

  httpsServer.on('clientError', (err) => {
    log && log.error(err, 'HTTPS Client Error');
  });

  log && log.info(`Listening to HTTPS requests on port ${sslOpts.port}.`);
  httpsServer.listen(sslOpts.port, sslOpts.ip);
};

ReverseProxy.prototype.addResolver = function (resolver) {
  if (this.opts.cluster && cluster.isMaster) return this;

  if (!_.isArray(resolver)) {
    resolver = [resolver];
  }

  resolver.forEach((resolveObj) => {
    if (!_.isFunction(resolveObj)) {
      throw new Error('Resolver must be an invokable function.');
    }

    if (!resolveObj.hasOwnProperty('priority')) {
      resolveObj.priority = 0;
    }

    this.resolvers.push(resolveObj);
  });

  this.resolvers = _.sortBy(_.uniq(this.resolvers), ['priority']).reverse();
};

ReverseProxy.prototype.removeResolver = function (resolver) {
  if (this.opts.cluster && cluster.isMaster) return this;
  // since unique resolvers are not checked for performance,
  // just remove every existence.
  this.resolvers = this.resolvers.filter(function (resolverFn) {
    return resolverFn !== resolver;
  });
};

ReverseProxy.buildTarget = function (target, opts = {}) {
  target = prepareUrl(target);
  target.sslRedirect = opts.ssl?.redirect !== false;
  target.useTargetHostHeader = opts.useTargetHostHeader === true;
  return target;
};

/**
 * Register a new route.
 *
 * @param {string | URL} src A string or a url parsed by node url module.
 * Note that port is ignored, since the proxy just listens to one port.
 * @param {string} target A string or a url parsed by node url module.
 * @param {*} opts Route options.
 */
ReverseProxy.prototype.register = function (src, target, opts) {
  if (this.opts.cluster && cluster.isMaster) return this;

  // allow registering with src or target as an object to pass in
  // options specific to each one.
  if (src?.src) {
    target = src.target;
    opts = src;
    src = src.src;
  } else if (target?.target) {
    opts = target;
    target = target.target;
  }

  if (!src || !target) {
    throw Error('Cannot register a new route with unspecified src or target');
  }

  const routing = this.routing;

  src = prepareUrl(src);

  if (opts) {
    const ssl = opts.ssl;
    if (ssl) {
      if (!this.httpsServer) {
        throw Error('Cannot register https routes without defining a ssl port');
      }

      if (!secureContext) {
        secureContext = {};
      }

      if (!secureContext[src.hostname]) {
        if (ssl.key || ssl.cert || ssl.ca) {
          secureContext[src.hostname] = createCredentialContext(ssl.key, ssl.cert, ssl.ca);
        } else if (ssl.letsencrypt) {
          if (!this.opts.letsencrypt || !this.opts.letsencrypt.path) {
            console.error('Missing certificate path for Lets Encrypt');
            return;
          }
          this.log && this.log.info(`Getting Lets Encrypt certificates for ${src.hostname}`);
          this.updateCertificates(
            src.hostname,
            ssl.letsencrypt.email,
            ssl.letsencrypt.production,
            ssl.letsencrypt.greenlockOpts || {}
          );
        } else {
          // Trigger the use of the default certificates.
          secureContext[src.hostname] = void 0;
        }
      }
    }
  }

  target = ReverseProxy.buildTarget(target, opts);

  const host = (routing[src.hostname] = routing[src.hostname] || []);
  const pathname = src.pathname || '/';
  let route = _.find(host, { path: pathname });

  if (!route) {
    route = { path: pathname, rr: 0, urls: [], opts: Object.assign({}, opts) };
    host.push(route);

    //
    // Sort routes
    //
    routing[src.hostname] = _.sortBy(host, function (_route) {
      return -_route.path.length;
    });
  }

  route.urls.push(target);

  this.log && this.log.info(`Registered a new route - ${src} -> ${target}`);
  return this;
};

/**
 *
 * @param {string} domain
 * @param {string} email
 * @param {boolean} production
 * @param {number} renewWithin Deprecated
 * @param {boolean} renew Deprecated
 */
ReverseProxy.prototype.updateCertificates = async function (
  domain,
  email,
  production,
  greenlockOpts = {}
) {
  const siteCallback = (err, site) => {
    if (err) {
      if (typeof err?.message === 'string' && err?.message.includes('ENOENT: no such file or directory')) {
        this.log?.warn(err, err.message);
      } else {
        this.log?.error(err, "Error getting Let's Encrypt certificates");
        return;
      }
    }
    if (!site?.pems?.privkey || !site?.pems?.fullchain) {
      this.log?.info(`Could not get any certs for ${domain}.`);
      return;
    }
    const opts = {
      key: site.pems.privkey,
      cert: site.pems.fullchain,
      ca: site.pems.chain,
    };
    if (!secureContext) {
      secureContext = {};
    }
    secureContext[domain] = tls.createSecureContext(opts);
    this.log?.info(`${domain} secure context added.`);
  };

  letsencrypt.getCertificates(domain, email, production, this.log, siteCallback, greenlockOpts);
};

ReverseProxy.prototype.unregister = function (src, target) {
  if (this.opts.cluster && cluster.isMaster) return this;

  if (!src) {
    return this;
  }

  src = prepareUrl(src);
  const routes = this.routing[src.hostname] || [];
  const pathname = src.pathname || '/';
  let i = 0;

  for (i = 0; i < routes.length; i++) {
    if (routes[i].path === pathname) {
      break;
    }
  }

  if (i < routes.length) {
    const route = routes[i];

    if (target) {
      target = prepareUrl(target);
      _.remove(route.urls, function (url) {
        return url.href === target.href;
      });
    } else {
      route.urls = [];
    }

    if (route.urls.length === 0) {
      routes.splice(i, 1);
      const certs = secureContext;
      if (certs) {
        delete certs[src.hostname];
      }
    }

    this.log && this.log.info(`Unregistered a route - ${src} -> ${target}`);
  }
  return this;
};

ReverseProxy.prototype._defaultResolver = function (host, url) {
  // Given a src resolve it to a target route if any available.
  if (!host) {
    return;
  }

  url = url || '/';

  const routes = this.routing[host];
  let i = 0;

  if (routes) {
    const len = routes.length;

    //
    // Find path that matches the start of req.url
    //
    for (i = 0; i < len; i++) {
      const route = routes[i];

      if (route.path === '/' || startsWith(url, route.path)) {
        return route;
      }
    }
  }
};

ReverseProxy.prototype._defaultResolver.priority = 0;

/**
 * Resolves to route
 * @param host
 * @param url
 * @returns {*}
 */
ReverseProxy.prototype.resolve = function (_host, url, req) {
  const promiseArray = [];

  const host = _host?.toLowerCase();
  for (let i = 0; i < this.resolvers.length; i++) {
    promiseArray.push(this.resolvers[i].call(this, host, url, req));
  }

  return Promise.all(promiseArray)
    .then((resolverResults) => {
      for (let i = 0; i < resolverResults.length; i++) {
        let route = resolverResults[i];

        if (route && (route = ReverseProxy.buildRoute(route))) {
          // ensure resolved route has path that prefixes URL
          // no need to check for native routes.
          if (!route.isResolved || route.path === '/' || startsWith(url, route.path)) {
            return route;
          }
        }
      }
    })
    .catch(function (error) {
      console.error('Resolvers error:', error);
    });
};

ReverseProxy.buildRoute = function (_route) {
  if (!_.isString(_route) && !_.isObject(_route)) {
    return null;
  }

  if (_.isObject(_route) && _route.hasOwnProperty('urls') && _route.hasOwnProperty('path')) {
    // default route type matched.
    return _route;
  }

  const route = _.cloneDeep(_route);

  if (route.rewriteTo) {
    route.url = route.rewriteTo;
  }

  const cacheKey = _.isString(route) ? route : hash(route);
  const entry = routeCache.get(cacheKey);
  if (entry) {
    return entry;
  }

  const routeObject = { rr: 0, isResolved: true };
  if (_.isString(route)) {
    routeObject.urls = [ReverseProxy.buildTarget(route)];
    routeObject.path = '/';
  } else {
    if (!route.hasOwnProperty('url')) {
      return null;
    }

    routeObject.urls = (_.isArray(route.url) ? route.url : [route.url]).map(function (url) {
      return ReverseProxy.buildTarget(url, route.opts || {});
    });

    routeObject.path = route.path || '/';

    if (route.rewriteTo) {
      routeObject.isRewrite = true;
    }
  }

  routeCache.set(cacheKey, routeObject);
  return routeObject;
};

ReverseProxy.prototype._getTarget = function (src, req, res) {
  const { url } = req;

  return this.resolve(src, url, req).then((route) => {
    if (!route) {
      this.log?.warn(`No valid route found for given source - ${src} -> ${url}`);
      return;
    }

    const pathname = route.path;
    if (pathname.length > 1) {
      //
      // remove prefix from src
      //
      req.originalUrl = url.substr(pathname.length) || ''; // save original url
      req.url = url.substr(pathname.length) || '';
    } else {
      req.originalUrl = url;
    }

    //
    // Perform Round-Robin on the available targets
    // TODO: if target errors with EHOSTUNREACH we should skip this
    // target and try with another.
    //
    const urls = route.urls;
    const j = route.rr;
    route.rr = (j + 1) % urls.length; // get and update Round-robin index.
    const target = route.urls[j];

    //
    // Fix request url if target name specified.
    //
    if (target.pathname) {
      if (req.url && !route.isRewrite) {
        req.url = path.posix.join(target.pathname, req.url);
      } else {
        req.url = target.pathname;
      }
    }

    //
    // Host headers are passed through from the source by default
    // Often we want to use the host header of the target instead
    //
    if (target.useTargetHostHeader === true) {
      req.host = target.host;
    }

    if (route.opts?.onRequest) {
      const resultFromRequestHandler = route.opts.onRequest(req, res, target);
      if (resultFromRequestHandler !== undefined) {
        this.log &&
          this.log.info(`Proxying ${src + url} received result from onRequest handler, returning.`);
        return resultFromRequestHandler;
      }
    }

    this.log && this.log.info(`Proxying ${src + url} to ${path.posix.join(target.host, req.url)}`);

    return target;
  });
};

ReverseProxy.prototype._getSource = function (req) {
  if (this.opts.preferForwardedHost === true && req.headers['x-forwarded-host']) {
    return req.headers['x-forwarded-host'].split(':')[0];
  }
  if (req.headers.host) {
    return req.headers.host.split(':')[0];
  } else if (req.headers[':authority']) {
    return req.headers[':authority'];
  }
};

ReverseProxy.prototype.close = function () {
  try {
    return Promise.all(
      [this.server, this.httpsServer]
        .filter((s) => s)
        .map((server) => new Promise((resolve) => server.close(resolve)))
    );
  } catch (err) {
    // Ignore for now...
  }
};

//
// Helpers
//
/**
  Routing table structure. An object with hostname as key, and an array as value.
  The array has one element per path associated to the given hostname.
  Every path has a Round-Robin value (rr) and urls array, with all the urls available
  for this target route.

  {
    hostA :
      [
        {
          path: '/',
          rr: 3,
          urls: []
        }
      ]
  }
*/

const respondNotFound = function (req, res) {
  res.statusCode = 404;
  res.write('Not Found');
  res.end();
};

ReverseProxy.prototype.notFound = function (callback) {
  if (typeof callback == 'function') respondNotFound = callback;
  else throw Error('notFound callback is not a function');
};

//
// Redirect to the HTTPS proxy
//
function redirectToHttps(req, res, target, ssl, log) {
  const redirectUrl = req.originalUrl || req.url; // Get the original url since we are going to redirect.

  const targetPort = Number(ssl.redirectPort || ssl.port);
  const hostname =
    req.headers.host.split(':')[0] + (targetPort && targetPort !== 443 ? ':' + targetPort : '');
  const url = 'https://' + path.posix.join(hostname, redirectUrl);
  log && log.info(`Redirecting ${path.posix.join(req.headers.host, redirectUrl)} to ${url}.`);
  //
  // We can use 301 for permanent redirect, but its bad for debugging, we may have it as
  // a configurable option.
  //
  res.writeHead(302, { Location: url });
  res.end();
}

function startsWith(input, str) {
  return (
    input.slice(0, str.length) === str && (input.length === str.length || input[str.length] === '/')
  );
}

function prepareUrl(_url) {
  let url = _.clone(_url);
  if (_.isString(url)) {
    url = setHttp(url);

    if (!validUrl.isHttpUri(url) && !validUrl.isHttpsUri(url)) {
      throw Error('uri is not a valid http uri ' + url);
    }

    url = parseUrl(url);
  }
  return url;
}

function getCertData(source, unbundle) {
  let data;

  if (source) {
    if (_.isArray(source)) {
      const sources = source;
      return _.flatten(
        _.map(sources, function (_source) {
          return getCertData(_source, unbundle);
        })
      );
    } else if (Buffer.isBuffer(source)) {
      data = source.toString('utf8');
    } else if (fs.existsSync(source)) {
      data = fs.readFileSync(source, 'utf8');
    }
  }

  if (!data) {
    return undefined;
  }

  return unbundle ? unbundleCert(data) : data;
}

/**
 Unbundles a file composed of several certificates.
 http://www.benjiegillam.com/2012/06/node-dot-js-ssl-certificate-chain/
 */
function unbundleCert(bundle) {
  const chain = bundle.trim().split('\n');

  const ca = [];
  let cert = [];

  for (let i = 0, len = chain.length; i < len; i++) {
    const line = chain[i].trim();
    if (!(line.length !== 0)) {
      continue;
    }
    cert.push(line);
    if (line.match(/-END CERTIFICATE-/)) {
      const joined = cert.join('\n');
      ca.push(joined);
      cert = [];
    }
  }
  return ca;
}

function createCredentialContext(key, cert, ca) {
  const opts = {};

  opts.key = getCertData(key);
  opts.cert = getCertData(cert);

  if (ca) {
    opts.ca = getCertData(ca, true);
  }

  return tls.createSecureContext(opts);
}

//
// https://stackoverflow.com/questions/18052919/javascript-regular-expression-to-add-protocol-to-url-string/18053700#18053700
// Adds http protocol if non specified.
const setHttp = (link) => {
  if (link.search(/^http[s]?\:\/\//) === -1) {
    return `http://${link}`;
  }
  return link;
};

module.exports = ReverseProxy;
