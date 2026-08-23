from urllib.parse import urlparse
def resolve_base_url(spec: dict, openapi_url: str, override_url: str | None = None):
    if override_url:
        return override_url.rstrip("/")

    servers = spec.get("servers",[])
    if servers and isinstance(servers, list):
        server_url = servers[0].get("url", "").strip()
        if server_url.startswith("http"):
            return server_url.rstrip("/")

    parsed = urlparse(openapi_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def extract_endpoints(openapi_spec: dict, allowed_methods: list[str]):
    endpoints = []
    paths = openapi_spec.get("paths",{})
    allowed_methods = [m.lower() for m in allowed_methods]
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.lower() not in ['get','post','put', 'delete', 'patch']:
                continue

            if method.lower() not in allowed_methods:
                continue
            endpoint_info = {
                "path":path,
                "method":method.upper(),
                "summary":details.get("summary",""),
                "parameters":[],
                "has_body":"requestBody" in details
            }

            if "parameters" in details:
                for param in details['parameters']:
                    if isinstance(param, dict) and "name" in param:
                        endpoint_info["parameters"].append({
                            "name":param["name"],
                            "in": param.get("in", "query"),
                            "required": param.get("required", False)
                        })
            endpoints.append(endpoint_info)

    return endpoints