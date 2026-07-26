"""Spike2: standalone Jac ASGI gateway with starlette middleware under uvicorn."""
import uvicorn;
import httpx;
import from typing { Any }
import from starlette.applications { Starlette }
import from starlette.routing { Route }
import from starlette.responses { JSONResponse }
import from starlette.middleware.base { BaseHTTPMiddleware }

class SpikeMiddleware(BaseHTTPMiddleware) {
    async def dispatch(self: SpikeMiddleware, request: Any, call_next: Any) -> Any {
        client_host = request.client.host if request.client else None;
        hdrs = dict(request.headers);
        cookies = dict(request.cookies);
        print(f"[gateway] client.host={client_host}");
        print(f"[gateway] headers={hdrs}");
        print(f"[gateway] cookies={cookies}");
        response = await call_next(request);
        response.headers["X-Spike"] = "ok";
        return response;
    }
}

async def ping(request: Any) -> Any {
    return JSONResponse({"status": "ok", "client": request.client.host if request.client else None});
}

async def proxy(request: Any) -> Any {
    async with httpx.AsyncClient() as client {
        resp = await client.get("http://127.0.0.1:8799/ping");
    }
    return JSONResponse({"proxied_status": resp.status_code, "proxied_body": resp.json()});
}

def build_app() -> Any {
    routes = [Route("/ping", ping), Route("/proxy", proxy, methods=["GET", "POST"])];
    app = Starlette(routes=routes);
    app.add_middleware(SpikeMiddleware);
    return app;
}

with entry:__main__ {
    app = build_app();
    uvicorn.run(app, host="127.0.0.1", port=8799);
}
