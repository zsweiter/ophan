const fs = require("fs");
const http = require("http");

const socketArg = process.argv.find((arg) => arg.startsWith("--socket="));
const SOCKET_PATH = socketArg ? socketArg.split("=")[1] : null;

// node server.js --socket=/tmp/echo.sock
const server = http.createServer((req, res) => {
    const host = req.headers.host || "localhost";
    const url = new URL(req.url, `http://${host}`);

    console.log(
        `[${new Date().toISOString()}] Request: ${req.method} ${req.url}`,
    );

    if (url.pathname === "/echo") {
        res.writeHead(200, {
            "Content-Type": "application/json",
        });

        res.end(
            JSON.stringify({
                message: "echo",
                method: req.method,
                path: url.pathname,
                query: Object.fromEntries(url.searchParams),
                headers: req.headers,
            }),
        );
        return;
    }

    const userMatch = url.pathname.match(/^\/users\/([^/]+)$/);

    if (userMatch) {
        res.writeHead(200, {
            "Content-Type": "application/json",
        });

        res.end(
            JSON.stringify({
                message: `Hello ${userMatch[1]}`,
            }),
        );
        return;
    }

    res.writeHead(404, {
        "Content-Type": "application/json",
    });

    res.end(
        JSON.stringify({
            error: "Not found",
            path: url.pathname,
        }),
    );
});

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.maxRequestsPerSocket = 0;

const cleanSocket = () => {
    if (SOCKET_PATH && fs.existsSync(SOCKET_PATH)) {
        try {
            fs.unlinkSync(SOCKET_PATH);
        } catch (err) {
            console.error(`Error eliminando socket: ${err.message}`);
        }
    }
};

["SIGINT", "SIGTERM"].forEach((signal) => {
    process.on(signal, () => {
        server.close(() => {
            cleanSocket();
            process.exit(0);
        });
    });
});

if (SOCKET_PATH) {
    cleanSocket();

    server.listen(SOCKET_PATH, () => {
        try {
            fs.chmodSync(SOCKET_PATH, 0o666);
            console.log(`Listening on unix://${SOCKET_PATH}`);
        } catch (err) {
            console.error(
                `Error configurando permisos en el socket: ${err.message}`,
            );
        }
    });
} else {
    const PORT = 3000;
    server.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}
