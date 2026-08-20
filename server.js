const express = require("express");
const path = require("path");
const http = require("http");
const crypto = require("crypto");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const users = [];
const messages = [];
const onlineUsers = new Map();
const sessions = new Map();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");
}

function createSession(email) {
    const token = crypto.randomBytes(48).toString("hex");

    sessions.set(token, {
        email,
        createdAt: Date.now()
    });

    return token;
}

function getSession(req) {
    const cookieHeader = req.headers.cookie || "";

    const cookies = {};

    cookieHeader.split(";").forEach(cookie => {
        const index = cookie.indexOf("=");

        if (index === -1) {
            return;
        }

        const key = cookie.slice(0, index).trim();
        const value = cookie.slice(index + 1).trim();

        cookies[key] = decodeURIComponent(value);
    });

    const token = cookies.ec_session;

    if (!token) {
        return null;
    }

    const session = sessions.get(token);

    if (!session) {
        return null;
    }

    return {
        token,
        ...session
    };
}

function setSessionCookie(res, token) {
    res.setHeader(
        "Set-Cookie",
        `ec_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800`
    );
}

function clearSessionCookie(res) {
    res.setHeader(
        "Set-Cookie",
        "ec_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"
    );
}

function getAuthenticatedUser(req) {
    const session = getSession(req);

    if (!session) {
        return null;
    }

    return users.find(user => user.email === session.email) || null;
}

function loginPage(error = "", email = "") {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>E-Chat Login</title>
<style>
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
    font-family: system-ui, sans-serif;
}

body {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #fef3c7;
    color: #451a03;
    padding: 20px;
}

.login-box {
    width: 100%;
    max-width: 420px;
    background: white;
    border: 1px solid #fde68a;
    border-radius: 18px;
    padding: 30px;
    box-shadow: 0 15px 40px rgba(120, 53, 15, 0.12);
}

h1 {
    margin-bottom: 8px;
    color: #92400e;
}

p {
    color: #78350f;
    margin-bottom: 24px;
}

label {
    display: block;
    margin-bottom: 7px;
    font-weight: 600;
}

input {
    width: 100%;
    padding: 13px 14px;
    margin-bottom: 16px;
    border: 1px solid #fcd34d;
    border-radius: 10px;
    outline: none;
    font-size: 15px;
}

input:focus {
    border-color: #f59e0b;
    box-shadow: 0 0 0 3px rgba(245, 158, 11, .12);
}

button {
    width: 100%;
    border: 0;
    border-radius: 10px;
    padding: 13px;
    background: #d97706;
    color: white;
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
}

button:hover {
    background: #b45309;
}

.error {
    background: #fee2e2;
    color: #991b1b;
    border: 1px solid #fecaca;
    padding: 11px;
    border-radius: 9px;
    margin-bottom: 18px;
}
</style>
</head>
<body>

<div class="login-box">
    <h1>E-Chat</h1>
    <p>Sign in to continue to your account.</p>

    ${error ? `<div class="error">${error}</div>` : ""}

    <form method="POST" action="/auth/login">
        <input
            type="hidden"
            name="redirect"
            value="/chat?user=${encodeURIComponent(email)}"
        >

        <label>Email</label>
        <input
            type="email"
            name="email"
            value="${email.replace(/"/g, "&quot;")}"
            required
            autocomplete="email"
        >

        <label>Password</label>
        <input
            type="password"
            name="password"
            required
            autocomplete="current-password"
        >

        <button type="submit">Login</button>
    </form>
</div>

</body>
</html>
`;
}

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/auth/register", (req, res) => {
    const { email, name, password } = req.body;

    if (!email || !name || !password) {
        return res.status(400).send(
            "<h1>Error: All fields are required!</h1>"
        );
    }

    const cleanEmail = email.toLowerCase().trim();
    const cleanName = name.trim();

    if (!cleanEmail || !cleanName || !password) {
        return res.status(400).send(
            "<h1>Error: Invalid input!</h1>"
        );
    }

    const emailExists = users.some(
        user => user.email === cleanEmail
    );

    if (emailExists) {
        return res.status(400).send(
            "<h1>Error: Email already exists!</h1>"
        );
    }

    const newUser = {
        email: cleanEmail,
        name: cleanName,
        password: hashPassword(password),
        connections: []
    };

    users.push(newUser);

    const token = createSession(cleanEmail);

    setSessionCookie(res, token);

    res.redirect(
        "/chat?user=" + encodeURIComponent(cleanEmail)
    );
});

app.post("/auth/regestor", (req, res) => {
    const { email, name, password } = req.body;

    if (!email || !name || !password) {
        return res.status(400).send(
            "<h1>Error: All fields are required!</h1>"
        );
    }

    const cleanEmail = email.toLowerCase().trim();
    const cleanName = name.trim();

    const emailExists = users.some(
        user => user.email === cleanEmail
    );

    if (emailExists) {
        return res.status(400).send(
            "<h1>Error: Email already exists!</h1>"
        );
    }

    users.push({
        email: cleanEmail,
        name: cleanName,
        password: hashPassword(password),
        connections: []
    });

    const token = createSession(cleanEmail);

    setSessionCookie(res, token);

    res.redirect(
        "/chat?user=" + encodeURIComponent(cleanEmail)
    );
});

app.get("/auth/login", (req, res) => {
    const email = String(req.query.user || "")
        .toLowerCase()
        .trim();

    const user = users.find(
        user => user.email === email
    );

    if (!user) {
        return res.status(404).send(
            "<h1>User not found</h1>"
        );
    }

    const authenticatedUser = getAuthenticatedUser(req);

    if (authenticatedUser && authenticatedUser.email === email) {
        return res.redirect(
            "/chat?user=" + encodeURIComponent(email)
        );
    }

    res.send(loginPage(
        onlineUsers.has(email)
            ? "This account is already active on another device. Please sign in to authorize this device."
            : "",
        email
    ));
});

app.post("/auth/login", (req, res) => {
    const email = String(req.body.email || "")
        .toLowerCase()
        .trim();

    const password = String(req.body.password || "");

    if (!email || !password) {
        return res.status(400).send(
            loginPage(
                "Email and password are required.",
                email
            )
        );
    }

    const user = users.find(
        user => user.email === email
    );

    if (!user) {
        return res.status(401).send(
            loginPage(
                "Invalid email or password.",
                email
            )
        );
    }

    const passwordHash = hashPassword(password);

    if (user.password !== passwordHash) {
        return res.status(401).send(
            loginPage(
                "Invalid email or password.",
                email
            )
        );
    }

    const oldSession = getSession(req);

    if (oldSession) {
        sessions.delete(oldSession.token);
    }

    const token = createSession(user.email);

    setSessionCookie(res, token);

    const redirect =
        typeof req.body.redirect === "string" &&
        req.body.redirect.startsWith("/chat")
            ? req.body.redirect
            : "/chat?user=" + encodeURIComponent(user.email);

    res.redirect(redirect);
});

app.get("/auth/logout", (req, res) => {
    const session = getSession(req);

    if (session) {
        sessions.delete(session.token);
    }

    clearSessionCookie(res);

    res.redirect("/");
});

app.get("/chat", (req, res) => {
    const requestedEmail = String(req.query.user || "")
        .toLowerCase()
        .trim();

    const authenticatedUser = getAuthenticatedUser(req);

    if (!requestedEmail) {
        return res.redirect("/");
    }

    if (!authenticatedUser) {
        return res.redirect(
            "/auth/login?user=" +
            encodeURIComponent(requestedEmail)
        );
    }

    if (authenticatedUser.email !== requestedEmail) {
        return res.status(403).send(
            "<h1>Unauthorized</h1><p>You are not authorized to access this account.</p>"
        );
    }

    res.sendFile(
        path.join(__dirname, "public", "chat.html")
    );
});

app.get("/api/users", (req, res) => {
    const currentUserEmail = String(req.query.user || "")
        .toLowerCase()
        .trim();

    const authenticatedUser = getAuthenticatedUser(req);

    if (
        !authenticatedUser ||
        authenticatedUser.email !== currentUserEmail
    ) {
        return res.status(401).json({
            error: "Unauthorized"
        });
    }

    const currentUser = users.find(
        user => user.email === currentUserEmail
    );

    if (!currentUser) {
        return res.status(404).json({
            error: "User not found"
        });
    }

    const list = users
        .filter(user => user.email !== currentUserEmail)
        .map(user => ({
            email: user.email,
            name: user.name,
            isOnline: onlineUsers.has(user.email),
            isConnected: currentUser.connections.includes(
                user.email
            )
        }));

    res.json(list);
});

app.get("/api/history", (req, res) => {
    const user = String(req.query.user || "")
        .toLowerCase()
        .trim();

    const target = String(req.query.target || "")
        .toLowerCase()
        .trim();

    const authenticatedUser = getAuthenticatedUser(req);

    if (
        !authenticatedUser ||
        authenticatedUser.email !== user
    ) {
        return res.status(401).json({
            error: "Unauthorized"
        });
    }

    const currentUser = users.find(
        currentUser => currentUser.email === user
    );

    if (!currentUser) {
        return res.status(404).json({
            error: "User not found"
        });
    }

    if (!currentUser.connections.includes(target)) {
        return res.status(403).json({
            error: "Users are not connected"
        });
    }

    const history = messages.filter(message =>
        (message.sender === user &&
            message.receiver === target) ||
        (message.sender === target &&
            message.receiver === user)
    );

    history.forEach(message => {
        if (message.receiver === user) {
            message.read = true;
        }
    });

    res.json(history);
});

function getUser(email) {
    return users.find(
        user => user.email === email
    );
}

function areConnected(emailA, emailB) {
    const userA = getUser(emailA);

    return Boolean(
        userA &&
        userA.connections.includes(emailB)
    );
}

function emitStatus(email, online) {
    io.emit("status-update", {
        email,
        online
    });
}

io.on("connection", socket => {
    let currentEmail = null;

    socket.on("register-online", email => {
        if (!email) {
            return;
        }

        const cleanEmail = String(email)
            .toLowerCase()
            .trim();

        const user = getUser(cleanEmail);

        if (!user) {
            return;
        }

        const authenticatedUser = getAuthenticatedUserFromSocket(
            socket
        );

        if (!authenticatedUser) {
            return;
        }

        if (authenticatedUser.email !== cleanEmail) {
            return;
        }

        currentEmail = cleanEmail;

        if (!onlineUsers.has(cleanEmail)) {
            onlineUsers.set(
                cleanEmail,
                new Set()
            );
        }

        onlineUsers
            .get(cleanEmail)
            .add(socket.id);

        emitStatus(cleanEmail, true);
    });

    socket.on("send-connect-request", data => {
        if (!currentEmail || !data || !data.targetEmail) {
            return;
        }

        const targetEmail = String(data.targetEmail)
            .toLowerCase()
            .trim();

        const sender = getUser(currentEmail);
        const target = getUser(targetEmail);

        if (
            !sender ||
            !target ||
            sender.email === target.email
        ) {
            return;
        }

        if (sender.connections.includes(targetEmail)) {
            return;
        }

        const targetSockets =
            onlineUsers.get(targetEmail);

        if (!targetSockets) {
            return;
        }

        targetSockets.forEach(socketId => {
            io.to(socketId).emit(
                "receive-connect-request",
                {
                    fromEmail: currentEmail
                }
            );
        });
    });

    socket.on("confirm-connection", data => {
        if (!currentEmail || !data || !data.targetEmail) {
            return;
        }

        const targetEmail = String(data.targetEmail)
            .toLowerCase()
            .trim();

        const userA = getUser(currentEmail);
        const userB = getUser(targetEmail);

        if (
            !userA ||
            !userB ||
            userA.email === userB.email
        ) {
            return;
        }

        if (!userA.connections.includes(targetEmail)) {
            userA.connections.push(targetEmail);
        }

        if (!userB.connections.includes(currentEmail)) {
            userB.connections.push(currentEmail);
        }

        const targetSockets =
            onlineUsers.get(targetEmail);

        if (targetSockets) {
            targetSockets.forEach(socketId => {
                io.to(socketId).emit(
                    "connection-established"
                );
            });
        }

        socket.emit(
            "connection-established"
        );
    });

    socket.on("send-chat-message", data => {
        if (
            !currentEmail ||
            !data ||
            !data.targetEmail ||
            !data.text
        ) {
            return;
        }

        const targetEmail = String(data.targetEmail)
            .toLowerCase()
            .trim();

        const text = String(data.text).trim();

        if (!text) {
            return;
        }

        if (
            !areConnected(
                currentEmail,
                targetEmail
            )
        ) {
            return;
        }

        const msgObject = {
            sender: currentEmail,
            receiver: targetEmail,
            text,
            timestamp: new Date().toLocaleTimeString(
                [],
                {
                    hour: "2-digit",
                    minute: "2-digit"
                }
            ),
            read: false
        };

        messages.push(msgObject);

        const targetSockets =
            onlineUsers.get(targetEmail);

        if (targetSockets) {
            targetSockets.forEach(socketId => {
                io.to(socketId).emit(
                    "receive-chat-message",
                    msgObject
                );
            });
        }

        socket.emit(
            "message-sent-confirmation",
            msgObject
        );
    });

    socket.on("mark-as-read", data => {
        if (
            !currentEmail ||
            !data ||
            !data.targetEmail
        ) {
            return;
        }

        const targetEmail = String(data.targetEmail)
            .toLowerCase()
            .trim();

        if (
            !areConnected(
                currentEmail,
                targetEmail
            )
        ) {
            return;
        }

        messages.forEach(message => {
            if (
                message.sender === targetEmail &&
                message.receiver === currentEmail
            ) {
                message.read = true;
            }
        });

        const targetSockets =
            onlineUsers.get(targetEmail);

        if (targetSockets) {
            targetSockets.forEach(socketId => {
                io.to(socketId).emit(
                    "messages-were-read",
                    {
                        byUser: currentEmail
                    }
                );
            });
        }
    });

    socket.on("disconnect", () => {
        if (!currentEmail) {
            return;
        }

        const sockets =
            onlineUsers.get(currentEmail);

        if (!sockets) {
            return;
        }

        sockets.delete(socket.id);

        if (sockets.size === 0) {
            onlineUsers.delete(currentEmail);

            emitStatus(
                currentEmail,
                false
            );
        }
    });
});

function getAuthenticatedUserFromSocket(socket) {
    return users.find(user => {
        return Array.from(sessions.values()).some(
            session =>
                session.email === user.email
        );
    });
}

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
    console.log(
        `Server running on port ${PORT}`
    );
});
