# Sample Express app that integrates with Google Identity Platform

This is a sample app that integrates with Google Identity Platform doing a
OAuth2 implicit authentication flow with the result being an Open Id Connected
Id Token. The token can then be validated against a service using an Express
authentication middleware.

## Setup

First register a OAuth2 client:

1. Go to https://console.cloud.google.com/apis/credentials
2. Click "Create credentials"->"OAuth Client ID"
3. Select "Web application"
4. Add "Authorised JavaScript origins", fx. http://localhost:3000 for
testing this app
5. Add "Authorised redirect URIs", fx. http://localhost:3000/index.html for
testing this app

## Links

* Scopes: https://developers.google.com/identity/protocols/googlescopes
