"use strict";

import assert from "assert";
import http from "http";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import defaults from "../../../lib/defaults/index.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import httpAdapter from "../../../lib/adapters/http.js";

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.transport;
    delete Object.prototype.transformRequest;
    delete Object.prototype.transformResponse;
    delete Object.prototype.formSerializer;
    delete Object.prototype.env;
    delete Object.prototype.parseReviver;
    delete Object.prototype.url;
    delete Object.prototype.data;
    delete Object.prototype.headers;
    delete Object.prototype.responseType;
    delete Object.prototype.responseEncoding;
    delete Object.prototype.httpVersion;
    delete Object.prototype.transitional;
    delete Object.prototype.response;
    delete Object.prototype.validateStatus;
    delete Object.prototype.customProp;
  });

  describe("utils.merge", function () {
    it("should filter __proto__ key at top level", function () {
      const result = utils.merge(
        {},
        { __proto__: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key at top level", function () {
      const result = utils.merge(
        {},
        { constructor: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key at top level", function () {
      const result = utils.merge(
        {},
        { prototype: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter __proto__ key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            __proto__: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            constructor: { prototype: { polluted: "nested" } },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            prototype: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in deeply nested objects", function () {
      const result = utils.merge(
        {},
        {
          level1: {
            level2: {
              __proto__: { polluted: "deep" },
              prototype: { polluted: "deep" },
              safe: "value",
            },
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.level1.level2.safe, "value");
      assert.strictEqual(
        result.level1.level2.hasOwnProperty("__proto__"),
        false,
      );
    });

    it("should still merge regular properties correctly", function () {
      const result = utils.merge({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 });

      assert.strictEqual(result.a, 1);
      assert.strictEqual(result.b.c, 2);
      assert.strictEqual(result.b.d, 3);
      assert.strictEqual(result.e, 4);
    });

    it("should handle JSON.parse payloads safely", function () {
      const malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should handle nested JSON.parse payloads safely", function () {
      const malicious = JSON.parse(
        '{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}',
      );
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });
  });

  describe("mergeConfig", function () {
    it("should filter dangerous keys at top level", function () {
      const result = mergeConfig(
        {},
        {
          __proto__: { polluted: "yes" },
          constructor: { polluted: "yes" },
          prototype: { polluted: "yes" },
          url: "/api/test",
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, "/api/test");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in headers", function () {
      const result = mergeConfig(
        {},
        {
          headers: {
            __proto__: { polluted: "yes" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter dangerous keys in custom config properties", function () {
      const result = mergeConfig(
        {},
        {
          customProp: {
            __proto__: { polluted: "yes" },
            safe: "value",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.customProp.safe, "value");
      assert.strictEqual(result.customProp.hasOwnProperty("__proto__"), false);
    });

    it("should not inherit transport from Object.prototype", function () {
      Object.prototype.transport = { request: function () {} };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(result.hasOwnProperty("transport"), false);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false
      );
    });

    it("should not inherit transformRequest from Object.prototype", function () {
      Object.prototype.transformRequest = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformRequest"),
        false
      );
    });

    it("should not inherit transformResponse from Object.prototype", function () {
      Object.prototype.transformResponse = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformResponse"),
        false
      );
    });

    it("should not inherit arbitrary keys from Object.prototype", function () {
      Object.prototype.polluted = "yes";
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "polluted"),
        false
      );
    });

    // The four tests above only prove that a key which is visited by neither
    // config cannot leak. The real attack requires the key to be OWN on one
    // config (so it is visited) while the OTHER config resolves it through the
    // polluted prototype. The tests below encode that exploit.

    it("should not take a config2 value from Object.prototype (defaultToConfig2)", function () {
      Object.prototype.responseType = "blob";

      const result = mergeConfig({ responseType: "json" }, { url: "/a" });

      // unpatched: config2["responseType"] resolves to the polluted "blob"
      assert.strictEqual(result.responseType, "json");
    });

    it("should not take a config1 value from Object.prototype (headers)", function () {
      Object.prototype.headers = { "X-Injected": "evil" };

      const result = mergeConfig({ url: "/a" }, { headers: undefined });

      // unpatched: config1["headers"] resolves to the polluted object
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "headers"),
        false,
      );
    });

    it("should not resolve an own-undefined transport through Object.prototype", function () {
      const evilTransport = { request: function () {} };
      Object.prototype.transport = evilTransport;

      const result = mergeConfig({ transport: undefined }, { url: "/a" });

      // unpatched: config2["transport"] resolves to the polluted transport
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false,
      );
    });

    it("should not resolve an own-undefined url through Object.prototype (valueFromConfig2)", function () {
      Object.prototype.url = "http://evil.example.com/";

      const result = mergeConfig({ url: undefined }, { method: "get" });

      // unpatched: config2["url"] resolves to the attacker controlled URL
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "url"),
        false,
      );
      assert.strictEqual(result.method, "get");
    });

    it("should not resolve an own-undefined custom key through Object.prototype (mergeDeepProperties)", function () {
      Object.prototype.customProp = { polluted: "yes" };

      const result = mergeConfig({ customProp: undefined }, { url: "/a" });

      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "customProp"),
        false,
      );
      assert.strictEqual(result.url, "/a");
    });

    it("should not resolve an own-undefined validateStatus through Object.prototype (mergeDirectKeys)", function () {
      const evilValidateStatus = function () {
        return true;
      };
      Object.prototype.validateStatus = evilValidateStatus;

      const result = mergeConfig({ validateStatus: undefined }, { url: "/a" });

      // unpatched: config2["validateStatus"] resolves to the polluted function
      assert.notStrictEqual(result.validateStatus, evilValidateStatus);
      assert.strictEqual(result.validateStatus, undefined);
    });

    it("should not resolve an own-undefined transformResponse through Object.prototype", function () {
      const evilTransform = function () {
        return "hijacked";
      };
      Object.prototype.transformResponse = [evilTransform];

      const result = mergeConfig(
        { transformResponse: undefined },
        { url: "/a" },
      );

      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformResponse"),
        false,
      );
    });

    it("should still merge configs correctly", function () {
      const config1 = {
        baseURL: "https://api.example.com",
        timeout: 1000,
        headers: {
          common: {
            Accept: "application/json",
          },
        },
      };

      const config2 = {
        url: "/users",
        timeout: 5000,
        headers: {
          common: {
            "Content-Type": "application/json",
          },
        },
      };

      const result = mergeConfig(config1, config2);

      assert.strictEqual(result.baseURL, "https://api.example.com");
      assert.strictEqual(result.url, "/users");
      assert.strictEqual(result.timeout, 5000);
      assert.strictEqual(result.headers.common.Accept, "application/json");
      assert.strictEqual(
        result.headers.common["Content-Type"],
        "application/json",
      );
    });
  });

  describe("defaults.transformRequest", function () {
    it("should not read formSerializer from Object.prototype", function () {
      let evilVisitorCalled = false;

      Object.prototype.formSerializer = {
        visitor: function () {
          evilVisitorCalled = true;
          return false;
        },
      };

      const headers = new AxiosHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
      });

      // `this` is a plain object without an own `formSerializer`
      const result = defaults.transformRequest[0].call({}, { a: "1" }, headers);

      assert.strictEqual(evilVisitorCalled, false);
      assert.strictEqual(typeof result, "string");
      // the default visitor must still have serialized the payload
      assert.ok(result.length > 0, "payload should not be empty");
      assert.ok(result.indexOf("a") > -1);
    });

    it("should not read env from Object.prototype", function () {
      let evilFormDataConstructed = false;

      function EvilFormData() {
        evilFormDataConstructed = true;
        this.append = function () {};
      }

      Object.prototype.env = { FormData: EvilFormData };

      const headers = new AxiosHeaders({
        "Content-Type": "multipart/form-data",
      });

      const result = defaults.transformRequest[0].call({}, { a: "1" }, headers);

      assert.strictEqual(evilFormDataConstructed, false);
      assert.ok(result && typeof result === "object");
    });
  });

  describe("defaults.transformResponse", function () {
    it("should not read transitional from Object.prototype", function () {
      Object.prototype.transitional = { forcedJSONParsing: false };

      // unpatched: this.transitional resolves to the polluted object and
      // disables JSON parsing, so the raw string is handed to the caller
      const result = defaults.transformResponse[0].call({}, '{"a":1}');

      assert.strictEqual(typeof result, "object");
      assert.strictEqual(result.a, 1);
    });

    it("should not read responseType from Object.prototype", function () {
      Object.prototype.responseType = "text";

      // unpatched: this.responseType resolves to "text" and suppresses parsing
      const result = defaults.transformResponse[0].call({}, '{"a":1}');

      assert.strictEqual(typeof result, "object");
      assert.strictEqual(result.a, 1);
    });

    it("should not read parseReviver from Object.prototype", function () {
      let evilReviverCalled = false;

      Object.prototype.parseReviver = function (key, value) {
        evilReviverCalled = true;
        return typeof value === "number" ? "hijacked" : value;
      };

      const result = defaults.transformResponse[0].call({}, '{"a":1}');

      assert.strictEqual(evilReviverCalled, false);
      assert.strictEqual(result.a, 1);
    });

    it("should not read response from Object.prototype", function () {
      Object.prototype.response = { status: 500, data: "evil" };

      const context = {
        responseType: "json",
        transitional: { forcedJSONParsing: true, silentJSONParsing: false },
      };

      let thrown = null;

      try {
        defaults.transformResponse[0].call(context, "{not json");
      } catch (e) {
        thrown = e;
      }

      assert.ok(thrown, "a parsing error should have been thrown");
      // unpatched: this.response resolves to the polluted object and is
      // attached to the AxiosError as a forged response
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(thrown, "response"),
        false,
      );
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(thrown, "status"),
        false,
      );
    });
  });

  describe("http adapter", function () {
    let server = null;

    function startServer(handler) {
      return new Promise(function (resolve, reject) {
        server = http.createServer(handler);
        server.on("error", reject);
        server.listen(0, "127.0.0.1", function () {
          resolve("http://127.0.0.1:" + server.address().port + "/");
        });
      });
    }

    function makeConfig(url, extra) {
      const config = {
        method: "get",
        url: url,
        headers: new AxiosHeaders(),
        maxRedirects: 0,
        maxContentLength: -1,
        maxBodyLength: -1,
        proxy: false,
        timeout: 8000,
      };

      if (extra) {
        Object.keys(extra).forEach(function (key) {
          config[key] = extra[key];
        });
      }

      return config;
    }

    afterEach(function (done) {
      if (!server) {
        done();
        return;
      }

      const current = server;
      server = null;
      current.close(function () {
        done();
      });
    });

    it("should not read transport from Object.prototype", async function () {
      this.timeout(10000);

      const url = await startServer(function (req, res) {
        res.end("ok");
      });

      let evilTransportUsed = false;

      Object.prototype.transport = {
        request: function () {
          evilTransportUsed = true;
          throw new Error("evil transport was used");
        },
      };

      const response = await httpAdapter(makeConfig(url));

      assert.strictEqual(evilTransportUsed, false);
      assert.strictEqual(response.data, "ok");
    });

    it("should not read data from Object.prototype", async function () {
      this.timeout(10000);

      let receivedBody = null;

      const url = await startServer(function (req, res) {
        let body = "";
        req.on("data", function (chunk) {
          body += chunk;
        });
        req.on("end", function () {
          receivedBody = body;
          res.end("ok");
        });
      });

      Object.prototype.data = "EVIL_BODY";

      const response = await httpAdapter(makeConfig(url, { method: "post" }));

      assert.strictEqual(receivedBody, "");
      assert.strictEqual(response.data, "ok");
    });

    it("should not read responseType from Object.prototype", async function () {
      this.timeout(10000);

      const url = await startServer(function (req, res) {
        res.end("ok");
      });

      Object.prototype.responseType = "stream";

      const response = await httpAdapter(makeConfig(url));

      assert.strictEqual(typeof response.data, "string");
      assert.strictEqual(response.data, "ok");
    });

    it("should not read responseEncoding from Object.prototype", async function () {
      this.timeout(10000);

      const url = await startServer(function (req, res) {
        res.end("ok");
      });

      Object.prototype.responseEncoding = "hex";

      const response = await httpAdapter(makeConfig(url));

      assert.strictEqual(response.data, "ok");
    });

    it("should not read httpVersion from Object.prototype", async function () {
      this.timeout(10000);

      const url = await startServer(function (req, res) {
        res.end("ok");
      });

      Object.prototype.httpVersion = "bogus";

      const response = await httpAdapter(makeConfig(url));

      assert.strictEqual(response.data, "ok");
    });

    it("should not read env from Object.prototype for data: URIs", async function () {
      this.timeout(10000);

      let evilBlobConstructed = false;

      function EvilBlob() {
        evilBlobConstructed = true;
      }

      Object.prototype.env = { Blob: EvilBlob };

      let response = null;
      let thrown = null;

      try {
        response = await httpAdapter(
          makeConfig("data:text/plain;base64,b2s=", { responseType: "blob" }),
        );
      } catch (e) {
        // Blob is unavailable as a global on older Node versions, in which
        // case the adapter rejects instead of building a Blob - either way
        // the polluted constructor must never be reached
        thrown = e;
      }

      assert.strictEqual(evilBlobConstructed, false);
      assert.ok(
        response || thrown,
        "the adapter should either resolve or reject",
      );

      if (response) {
        assert.strictEqual(response.status, 200);
        assert.ok(response.data);
      }
    });
  });
});
