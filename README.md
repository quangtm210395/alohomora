# Alohomora

[![Version](https://img.shields.io/npm/v/@hikariq/alohomora.svg)](https://www.npmjs.com/package/@hikariq/alohomora)
[![License](https://img.shields.io/npm/l/@hikariq/alohomora.svg)](https://github.com/quangtm210395/alohomora/blob/main/LICENSE)
[![Build Status](https://github.com/quangtm210395/alohomora/workflows/NPM%20publish/badge.svg?branch=main)](https://github.com/quangtm210395/alohomora/actions)

This repository is to create middleware for nodejs service (express) to connect with [Keycloak](https://github.com/keycloak/keycloak) Authorization service.
The idea is come from [keycloak-nodejs-connect](https://github.com/keycloak/keycloak-nodejs-connect), we extends the existing features of this project but currently only support the bearer-only option. We have added a fantastic feature is **policy enforcer by json configuration**. You can add the **policy-enforcer** attribute to the *keycloak.json* file and see the magic happen.

## Prerequisites

- Node 10 or higher

## Installation

```bash
# yarn
yarn add @hikariq/alohomora

# npm
npm install @hikariq/alohomora
```

## Usage

This library provide methods to connect and integrate with keycloak auth/authz service to use as a policy enforcer.

First, create keycloak.json file in the project root folder like this to config the policy enforcer.

```json
{
  "realm": "test-services",
  "bearer-only": true,
  "auth-server-url": "http://localhost:8080/auth",
  "json-enforcer-enabled": true,
  "client-id": "${env.KEYCLOAK_CLIENT_ID}",
  "secret": "${env.KEYCLOAK_CLIENT_SECRET}",
  "policy-enforcer": {
    "enforcement-mode": "ENFORCING",
    "paths": [
      {
        "name": "resource",
        "path": "/resource/:id",
        "methods": [
          {
            "method": "GET",
            "scopes": ["resource#scopes:get"]
          }
        ]
      }
    ]
  }
}
```

Then initialize and use the alohomora instance as a middleware.

```ts
import express from 'express';
import { Alohomora } from '@hikariq/alohomora';

const app = express();
const keycloak = new Alohomora();
app.use(keycloak.init());

app.get('/resource/:id', keycloak.enforce());

```

or just use the inline enforcer like this

```ts
app.get('/resource/:id', keycloak.enforce('resource#scopes:get'))
```

## Related Projects

- [keycloak-nodejs-connect](https://github.com/keycloak/keycloak-nodejs-connect): A Nodejs library to connect to keycloak developed by Keycloak team (Deprecated)
- [Keycloak](https://github.com/keycloak/keycloak): Opensource project for Identity and Access Management

## ❯ License

[MIT](/LICENSE)
