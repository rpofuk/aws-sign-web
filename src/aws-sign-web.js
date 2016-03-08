//
// AWS Signature v4 Implementation for Web Browsers
//
// Copyright (c) 2016 Daniel Joos
//
// Distributed under MIT license. (See file LICENSE)
//

;(function (globals, factory) {
    globals.AwsSigner = factory();
})(this, function () {
    'use strict';

    var defaultConfig = {
        region: 'eu-west-1',
        service: 'execute-api',
        defaultContentType: 'application/json',
        defaultAcceptType: 'application/json',
        uriParserFactory: SimpleUriParser,
        hasherFactory: CryptoJSHasher
    };

    /**
     * Create a new signer object with the given configuration.
     * Configuration must specify the AWS credentials used for the signing operation.
     * It must contain the following properties:
     * `accessKeyId`: The AWS IAM access key ID.
     * `secretKey`: The AWS IAM secret key.
     * `sessionToken`: Optional session token, required for temporary credentials.
     * @param config The configuration object.
     * @constructor
     */
    var AwsSigner = function (config) {
        this.config = extend({}, defaultConfig, config);
        this.uriParser = this.config.uriParserFactory();
        this.hasher = this.config.hasherFactory();
        assertRequired(this.config.accessKeyId, 'Signer requires AWS AccessKeyID');
        assertRequired(this.config.secretKey, 'Signer requires AWS SecretKey');
    };

    /**
     * Create signature headers for the given request.
     * Request must be in the format, known from the `$http` service of Angular:
     * ```
     * request = {
     *      headers: { ... },
     *      method: 'GET',
     *      data: ...
     * };
     * ```
     * The resulting object contains the signature headers. For example, it can be merged into an
     * existing `$http` config when dealing with Angular JS.
     * @param request The request to create the signature for. Will not be modified!
     * @param signDate Optional signature date to use. Current date-time is used if not specified.
     * @returns Signed request headers.
     */
    AwsSigner.prototype.sign = function (request, signDate) {
        var workingSet = {
            request: extend({}, request),
            signDate: signDate || new Date(),
            uri: this.uriParser(request.url)
        };
        prepare(this, workingSet);
        buildCanonicalRequest(this, workingSet);    // Step1: build the canonical request
        buildStringToSign(this, workingSet);        // Step2: build the string to sign
        calculateSignature(this, workingSet);       // Step3: calculate the signature hash
        buildSignatureHeader(this, workingSet);     // Step4: build the authorization header
        return {
            'Accept': workingSet.request.headers['accept'],
            'Authorization': workingSet.authorization,
            'x-amz-date': workingSet.request.headers['x-amz-date'],
            'x-amz-security-token': this.config.sessionToken || undefined
        };
    };

    // Some preparations
    function prepare(self, ws) {
        var headers = {
            'host': ws.uri.host,
            'content-type': self.config.defaultContentType,
            'accept': self.config.defaultAcceptType,
            'x-amz-date': amzDate(ws.signDate)
        };
        if (!ws.request.data) {
            delete headers['content-type'];
        } else {
            ws.request.data = JSON.stringify(ws.request.data);
        }
        ws.request.headers = extend(
            headers,
            Object.keys(ws.request.headers).reduce(function (normalized, key) {
                normalized[key.toLowerCase()] = ws.request.headers[key];
            }, {})
        );
        ws.sortedHeaderKeys = Object.keys(ws.request.headers).sort();
    }

    // Convert the request to a canonical format.
    function buildCanonicalRequest(self, ws) {
        ws.signedHeaders = ws.sortedHeaderKeys.map(function (key) {
            return key.toLowerCase();
        }).join(';');
        ws.canonicalRequest = String(ws.request.method).toUpperCase() + '\n' +
                // Canonical URI:
            encodeURI(ws.uri.path) + '\n' +
                // Canonical Query String:
            Object.keys(ws.uri.queryParams).sort().map(function (key) {
                return encodeURIComponent(key) + '=' +
                    encodeURIComponent(ws.uri.queryParams[key]);
            }).join('&') + '\n' +
                // Canonical Headers:
            ws.sortedHeaderKeys.map(function (key) {
                return key.toLocaleLowerCase() + ':' + ws.request.headers[key];
            }).join('\n') + '\n\n' +
                // Signed Headers:
            ws.signedHeaders + '\n' +
                // Hashed Payload
            self.hasher.hash((ws.request.data) ? ws.request.data : '');
    }

    // Construct the string that will be signed.
    function buildStringToSign(self, ws) {
        ws.credentialScope = [amzDate(ws.signDate, true), self.config.region, self.config.service,
            'aws4_request'].join('/');
        ws.stringToSign = 'AWS4-HMAC-SHA256' + '\n' +
            amzDate(ws.signDate) + '\n' +
            ws.credentialScope + '\n' +
            self.hasher.hash(ws.canonicalRequest);
    }

    // Calculate the signature
    function calculateSignature(self, ws) {
        var hmac = self.hasher.hmac;
        var signKey = hmac(
            hmac(
                hmac(
                    hmac(
                        'AWS4' + self.config.secretKey,
                        amzDate(ws.signDate, true),
                        {hexOutput: false}
                    ),
                    self.config.region,
                    {hexOutput: false, textInput: false}
                ),
                self.config.service,
                {hexOutput: false, textInput: false}
            ),
            'aws4_request',
            {hexOutput: false, textInput: false}
        );
        ws.signature = hmac(signKey, ws.stringToSign, {textInput: false});
    }

    // Build the signature HTTP header using the data in the working set.
    function buildSignatureHeader(self, ws) {
        ws.authorization = 'AWS4-HMAC-SHA256 ' +
            'Credential=' + self.config.accessKeyId + '/' + ws.credentialScope + ', ' +
            'SignedHeaders=' + ws.signedHeaders + ', ' +
            'Signature=' + ws.signature;
    }

    // Format the given `Date` as AWS compliant date string.
    // Time part gets omitted if second argument is set to `true`.
    function amzDate(date, short) {
        var result = date.toISOString().replace(/[:\-]|\.\d{3}/g, '').substr(0, 17);
        if (short) {
            return result.substr(0, 8);
        }
        return result;
    }

    /**
     * Simple URI parser factory.
     * Uses an `a` document element for parsing given URIs.
     * Therefore it most likely will only work in a web browser.
     */
    function SimpleUriParser() {
        var parser = document.createElement('a');

        /**
         * Parse the given URI.
         * @param uri The URI to parse.
         * @returns JavaScript object with the parse results:
         * `protocol`: The URI protocol part.
         * `host`: Host part of the URI.
         * `path`: Path part of the URI, always starting with a `/`
         * `queryParams`: Query parameters as JavaScript object.
         */
        return function (uri) {
            parser.href = uri;
            return {
                protocol: parser.protocol,
                host: parser.host,
                path: ((parser.pathname.charAt(0) !== '/') ? '/' : '') + parser.pathname,
                queryParams: extractQueryParams(parser.search)
            };
        };

        function extractQueryParams(search) {
            return /^\??(.*)$/.exec(search)[1].split('&').reduce(function (result, arg) {
                arg = /^(.+)=(.*)$/.exec(arg);
                if (arg) {
                    result[arg[1]] = arg[2];
                }
                return result;
            }, {});
        }
    }

    /**
     * Hash factory implementation using the SHA-256 hash algorithm of CryptoJS.
     * Requires at least the CryptoJS rollups: `sha256.js` and `hmac-sha256.js`.
     */
    function CryptoJSHasher() {
        /* global CryptoJS */
        return {
            /**
             * Hash the given input using SHA-256 algorithm.
             * The options can be used to control the in-/output of the hash operation.
             * @param input Input data.
             * @param options Options object:
             * `hexOutput` -- Output the hash with hex encoding (default: `true`).
             * `textInput` -- Interpret the input data as text (default: `true`).
             * @returns The generated hash
             */
            hash: function (input, options) {
                options = extend({hexOutput: true, textInput: true}, options);
                var hash = CryptoJS.SHA256(input);
                if (options.hexOutput) {
                    return hash.toString(CryptoJS.enc.Hex);
                }
                return hash;
            },

            /**
             * Create the HMAC of the given input data with the given key using the SHA-256
             * hash algorithm.
             * The options can be used to control the in-/output of the hash operation.
             * @param key Secret key.
             * @param input Input data.
             * @param options Options object:
             * `hexOutput` -- Output the hash with hex encoding (default: `true`).
             * `textInput` -- Interpret the input data as text (default: `true`).
             * @returns The generated HMAC.
             */
            hmac: function (key, input, options) {
                options = extend({hexOutput: true, textInput: true}, options);
                var hmac = CryptoJS.HmacSHA256(input, key, {asBytes: true});
                if (options.hexOutput) {
                    return hmac.toString(CryptoJS.enc.Hex);
                }
                return hmac;
            }
        };
    }


    // Simple version of the `extend` function, known from Angular and Backbone.
    // It merges the second (and all succeeding) argument(s) into the object, given as first
    // argument. This is done recursively for all child objects, as well.
    function extend(dest) {
        var objs = [].slice.call(arguments, 1);
        objs.forEach(function (obj) {
            if (!obj || typeof(obj) !== 'object') {
                return;
            }
            Object.keys(obj).forEach(function (key) {
                var src = obj[key];
                if (typeof(src) === 'undefined') {
                    return;
                }
                if (typeof(src) === 'object') {
                    dest[key] = extend({}, src);
                } else {
                    dest[key] = src;
                }
            });
        });
        return dest;
    }

    // Throw an error if the given object is undefined.
    function assertRequired(obj, msg) {
        if (typeof(obj) === 'undefined' || !obj) {
            throw new Error(msg);
        }
    }


    return AwsSigner;
});
