# Caddy Resolve Host CNAME
Resolve host CNAME and put it into placeholder

## Usage
```
* {
    tls {
        on_demand
    }
    route {
        cname
    }
    reverse_proxy * http://127.0.0.1:8080 {
        header_up Host {http.request.host.cname}
        header_up X-Forwarded-Host {http.request.host}
    }
}
```
