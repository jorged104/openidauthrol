
# Keycloak Authentication Middleware for Go

This Keycloak authentication plugin is a middleware designed for Go applications, providing a robust solution for managing user authentication via Keycloak, a comprehensive open-source identity and access management platform.

# Installation

To integrate this middleware into your application, enable plugin support in your Traefik configuration file (traefik.yml or traefik.toml):

```yaml
experimental:
  plugins:
    keycloakopenid:
      moduleName: "github.com/jorged104/openidauthrol"
      version: "v0.0.1"
```
Usage
Add the plugin's specific configuration to your Traefik routers:

```yaml
  middlewares:
    plugindemo:
      plugin:
        openidauthrol:
          keycloak: https://keycloakURL
          realms: phitec-test
```