# aws-sign-web
Plain JavaScript AWS Signature v4 for use within Web Browsers

## Example: AngularJS `$http` interceptor

The example assumes that the `aws-sign-web` is loaded inside the `index.html` such that it exposes the global variable `AwsSigner`.
The following code snippet shows how to create and configure an interceptor for Angular's `$http` provider.

```js
/* global AwsSigner */

angular
    .module('mymodule')
    .factory('AwsAuthInterceptor', function () {
        var defaultAuthConfig = {
            region: 'eu-west-1',
            service: 'execute-api'
        };
        return {
            request: onRequest
        };
        
        function onRequest(config) {
            if (angular.isUndefined(config.awsAuth) || !config.awsAuth) {
                return config;
            }
            var authConfig = angular.extend({}, defaultAuthConfig, config.awsAuth);
            delete config.awsAuth;
            if (angular.isUndefined(authConfig.accessKeyId) ||
                angular.isUndefined(authConfig.secretKey)) {
                return config;
            }
            // Re-use existing request transformers for generating the payload.
            if (config.transformRequest) {
                authConfig.payloadSerializer = function() {
                    return config.transformRequest.reduce(function(prev, transformer) {
                        return transformer(prev);
                    }, config.data);
                };
            }
            // Create the authentication headers and merge them into the existing ones
            var signer = new AwsSigner(authConfig);
            var signed = signer.sign(config);
            angular.merge(config.headers, signed);
            return config;
        }
    })
    .config(function ($httpProvider) {
        $httpProvider.interceptors.push('AwsAuthInterceptor');
    });
```

Use the above interceptor, e.g. in combination with _Restangular_:

```js
Restangular.all('users')
    .withHttpConfig({
        awsAuth: {
            accessKeyId: '...',
            secretKey: '...',
            sessionToken: '...'
        }
    })
    .get('johndoe')
    .then(...);
```

