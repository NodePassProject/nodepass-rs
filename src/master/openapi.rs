pub fn generate_openapi_spec(prefix: &str) -> String {
    format!(r##"{{
  "openapi": "3.1.1",
  "info": {{
    "title": "NodePass API",
    "description": "API for managing NodePass server and client instances",
    "version": "v1"
  }},
  "servers": [{{"url": "{prefix}"}}],
  "security": [{{"ApiKeyAuth": []}}],
  "paths": {{
    "/instances": {{
      "get": {{
        "summary": "List all instances",
        "security": [{{"ApiKeyAuth": []}}],
        "responses": {{
          "200": {{"description": "Success", "content": {{"application/json": {{"schema": {{"type": "array", "items": {{"$ref": "#/components/schemas/Instance"}}}}}}}}}},
          "401": {{"description": "Unauthorized"}}
        }}
      }},
      "post": {{
        "summary": "Create a new instance",
        "security": [{{"ApiKeyAuth": []}}],
        "requestBody": {{"required": true, "content": {{"application/json": {{"schema": {{"$ref": "#/components/schemas/CreateInstanceRequest"}}}}}}}},
        "responses": {{
          "201": {{"description": "Created", "content": {{"application/json": {{"schema": {{"$ref": "#/components/schemas/Instance"}}}}}}}},
          "400": {{"description": "Invalid input"}},
          "401": {{"description": "Unauthorized"}}
        }}
      }}
    }},
    "/instances/{{id}}": {{
      "parameters": [{{"name": "id", "in": "path", "required": true, "schema": {{"type": "string"}}}}],
      "get": {{
        "summary": "Get instance details",
        "security": [{{"ApiKeyAuth": []}}],
        "responses": {{
          "200": {{"description": "Success"}},
          "404": {{"description": "Not found"}}
        }}
      }},
      "patch": {{
        "summary": "Update instance",
        "security": [{{"ApiKeyAuth": []}}],
        "requestBody": {{"required": true, "content": {{"application/json": {{"schema": {{"$ref": "#/components/schemas/UpdateInstanceRequest"}}}}}}}},
        "responses": {{
          "200": {{"description": "Success"}}
        }}
      }},
      "put": {{
        "summary": "Update instance URL",
        "security": [{{"ApiKeyAuth": []}}],
        "responses": {{
          "200": {{"description": "Success"}}
        }}
      }},
      "delete": {{
        "summary": "Delete instance",
        "security": [{{"ApiKeyAuth": []}}],
        "responses": {{
          "204": {{"description": "Deleted"}}
        }}
      }}
    }},
    "/events": {{
      "get": {{
        "summary": "Subscribe to instance events (SSE)",
        "security": [{{"ApiKeyAuth": []}}],
        "responses": {{
          "200": {{"description": "Success", "content": {{"text/event-stream": {{}}}}}}
        }}
      }}
    }},
    "/info": {{
      "get": {{
        "summary": "Get master information",
        "security": [{{"ApiKeyAuth": []}}],
        "responses": {{
          "200": {{"description": "Success"}}
        }}
      }},
      "post": {{
        "summary": "Update master alias",
        "security": [{{"ApiKeyAuth": []}}],
        "responses": {{
          "200": {{"description": "Success"}}
        }}
      }}
    }},
    "/tcping": {{
      "get": {{
        "summary": "TCP connectivity test",
        "security": [{{"ApiKeyAuth": []}}],
        "parameters": [{{"name": "target", "in": "query", "required": true, "schema": {{"type": "string"}}}}],
        "responses": {{
          "200": {{"description": "Success"}}
        }}
      }}
    }}
  }},
  "components": {{
    "securitySchemes": {{
      "ApiKeyAuth": {{
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key"
      }}
    }},
    "schemas": {{
      "Instance": {{
        "type": "object",
        "properties": {{
          "id": {{"type": "string"}},
          "alias": {{"type": "string"}},
          "type": {{"type": "string", "enum": ["client", "server"]}},
          "status": {{"type": "string", "enum": ["running", "stopped", "error"]}},
          "url": {{"type": "string"}},
          "config": {{"type": "string"}},
          "restart": {{"type": "boolean"}},
          "mode": {{"type": "integer"}},
          "ping": {{"type": "integer"}},
          "pool": {{"type": "integer"}},
          "tcps": {{"type": "integer"}},
          "udps": {{"type": "integer"}},
          "tcprx": {{"type": "integer"}},
          "tcptx": {{"type": "integer"}},
          "udprx": {{"type": "integer"}},
          "udptx": {{"type": "integer"}}
        }}
      }},
      "CreateInstanceRequest": {{
        "type": "object",
        "required": ["url"],
        "properties": {{
          "alias": {{"type": "string"}},
          "url": {{"type": "string"}}
        }}
      }},
      "UpdateInstanceRequest": {{
        "type": "object",
        "properties": {{
          "alias": {{"type": "string"}},
          "action": {{"type": "string", "enum": ["start", "stop", "restart", "reset"]}},
          "restart": {{"type": "boolean"}}
        }}
      }}
    }}
  }}
}}"##, prefix = prefix)
}

pub fn swagger_ui_html(spec: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html>
<head>
  <title>NodePass API</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => SwaggerUIBundle({{
      spec: {},
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: "BaseLayout"
    }});
  </script>
</body>
</html>"#, spec)
}
