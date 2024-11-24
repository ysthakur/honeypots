from __future__ import annotations

from abc import ABC
from cgi import FieldStorage
from contextlib import suppress
import mimetypes
import os
from random import choice

from twisted.web.resource import Resource

from honeypots.base_server import BaseServer
from honeypots.helper import load_template, get_headers_and_ip_from_request, check_bytes


class BaseHttpServer(BaseServer, ABC):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.mocking_server = choice(
            [
                "Apache",
                "nginx",
                "Microsoft-IIS/7.5",
                "Microsoft-HTTPAPI/2.0",
                "Apache/2.2.15",
                "SmartXFilter",
                "Microsoft-IIS/8.5",
                "Apache/2.4.6",
                "Apache-Coyote/1.1",
                "Microsoft-IIS/7.0",
                "Apache/2.4.18",
                "AkamaiGHost",
                "Apache/2.2.25",
                "Microsoft-IIS/10.0",
                "Apache/2.2.3",
                "nginx/1.12.1",
                "Apache/2.4.29",
                "cloudflare",
                "Apache/2.2.22",
            ]
        )

    class MainResource(Resource):
        isLeaf = True  # noqa: N815
        home_file = load_template("home.html")
        login_file = load_template("login.html")

        def __init__(self, *args, hp_server: BaseHttpServer = None, **kwargs):
            super().__init__(*args, **kwargs)
            self.hp_server = hp_server
            self.files = {
                os.path.relpath(os.path.join(dir, file), self.hp_server.data_dir)
                for (dir, _, files) in os.walk(self.hp_server.data_dir)
                for file in files
            }
            self.headers = {}

        def render(self, request):
            client_ip, headers = get_headers_and_ip_from_request(
                request, self.hp_server.options
            )

            if self.hp_server.mocking_server != "":
                request.responseHeaders.removeHeader("Server")
                request.responseHeaders.addRawHeader(
                    "Server", self.hp_server.mocking_server
                )

            log_data = {
                "action": request.method.decode(),
                "path": request.path,
                "args": {
                    param.decode(): [arg.decode() for arg in args]
                    for param, args in request.args.items()
                },
                "src_ip": client_ip,
                "src_port": request.getClientAddress().port,
            }
            if "capture_commands" in self.hp_server.options:
                log_data["headers"] = {
                    check_bytes(k): check_bytes(v)
                    for k, v in request.getAllHeaders().items()
                }
            self.hp_server.log(log_data)

            if request.method != b"GET":
                request.setResponseCode(405)
                return b"<html><body>Method not allowed</body></html>"

            file = request.path.decode("utf-8").strip("/")

            if file == "":
                file = "index.html"

            if file == "sitemap.xml":
                request.responseHeaders.addRawHeader(
                    "Content-Type", "application/xml; charset=utf-8"
                )
                return (
                    b'<?xml version="1.0" encoding="UTF-8"?>\n'
                    + b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                    + "\n".join(
                        f"<url><loc>/{file}</loc></url>" for file in self.files
                    ).encode("utf-8")
                    + b"</urlset>"
                )

            if file not in self.files:
                file = file + ".html"

            if file not in self.files:
                request.setResponseCode(404)
                if "404.html" in self.files:
                    request.responseHeaders.addRawHeader(
                        "Content-Type", "text/html; charset=utf-8"
                    )
                    with open(
                        os.path.join(self.hp_server.data_dir, "404.html"), "rb"
                    ) as f:
                        return f.read()
                else:
                    return b"<html><body>Not Found</body></html>"

            typ, enc = mimetypes.guess_type(file)
            if typ is not None:
                if enc is not None:
                    typ += "; " + enc
                request.responseHeaders.addRawHeader("Content-Type", typ)
            with open(os.path.join(self.hp_server.data_dir, file), "rb") as f:
                return f.read()
