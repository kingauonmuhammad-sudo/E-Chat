const express = require("express");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const users = [];
const messages = [];
const onlineUsers = new Map();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/auth/register", (req, res) => {
    const { email, name, password } = req.body;

    if (!email || !name || !password) {
        return res.status(400).send("<h1>Error: All fields are required!</h1>");
    }

    const cleanEmail = email.toLowerCase().trim();
    const cleanName = name.trim();

    if (!cleanEmail || !cleanName || !password) {
        return res.status(400).send("<h1>Error: Invalid input!</h1>");
    }

    const emailExists = users.some(
        user => user.email === cleanEmail
    );

    if (emailExists) {
        return res.status(400).send("<h1>Error: Email already exists!</h1>");
    }

    const newUser = {
        email: cleanEmail,
        name: cleanName,
        password,
        connections: []
    };

    users.push(newUser);

    res.redirect("/chat?user=" + encodeURIComponent(newUser.email));
});

app.post("/auth/regestor", (req, res) => {
    const { email, name, password } = req.body;

    if (!email || !name || !password) {
        return res.status(400).send("<h1>Error: All fields are required!</h1>");
    }

    const cleanEmail = email.toLowerCase().trim();
    const cleanName = name.trim();

    const emailExists = users.some(
        user => user.email === cleanEmail
    );

    if (emailExists) {
        return res.status(400).send("<h1>Error: Email already exists!</h1>");
    }

    users.push({
        email: cleanEmail,
        name: cleanName,
        password,
        connections: []
    });

    res.redirect("/chat?user=" + encodeURIComponent(cleanEmail));
});

app.get("/chat", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "chat.html"));
});

app.get("/api/users", (req, res) => {
    const currentUserEmail = String(req.query.user || "").toLowerCase().trim();

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
            isConnected: currentUser.connections.includes(user.email)
        }));

    res.json(list);
});

app.get("/api/history", (req, res) => {
    const user = String(req.query.user || "").toLowerCase().trim();
    const target = String(req.query.target || "").toLowerCase().trim();

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
        (message.sender === user && message.receiver === target) ||
        (message.sender === target && message.receiver === user)
    );

    history.forEach(message => {
        if (message.receiver === user) {
            message.read = true;
        }
    });

    res.json(history);
});

function getUser(email) {
    return users.find(user => user.email === email);
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

        const cleanEmail = String(email).toLowerCase().trim();
        const user = getUser(cleanEmail);

        if (!user) {
            return;
        }

        currentEmail = cleanEmail;

        if (!onlineUsers.has(cleanEmail)) {
            onlineUsers.set(cleanEmail, new Set());
        }

        onlineUsers.get(cleanEmail).add(socket.id);

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

        if (!sender || !target || sender.email === target.email) {
            return;
        }

        if (sender.connections.includes(targetEmail)) {
            return;
        }

        const targetSockets = onlineUsers.get(targetEmail);

        if (!targetSockets) {
            return;
        }

        targetSockets.forEach(socketId => {
            io.to(socketId).emit("receive-connect-request", {
                fromEmail: currentEmail
            });
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

        if (!userA || !userB || userA.email === userB.email) {
            return;
        }

        if (!userA.connections.includes(targetEmail)) {
            userA.connections.push(targetEmail);
        }

        if (!userB.connections.includes(currentEmail)) {
            userB.connections.push(currentEmail);
        }

        const targetSockets = onlineUsers.get(targetEmail);

        if (targetSockets) {
            targetSockets.forEach(socketId => {
                io.to(socketId).emit("connection-established");
            });
        }

        socket.emit("connection-established");
    });

    socket.on("send-chat-message", data => {
        if (!currentEmail || !data || !data.targetEmail || !data.text) {
            return;
        }

        const targetEmail = String(data.targetEmail)
            .toLowerCase()
            .trim();

        const text = String(data.text).trim();

        if (!text) {
            return;
        }

        if (!areConnected(currentEmail, targetEmail)) {
            return;
        }

        const msgObject = {
            sender: currentEmail,
            receiver: targetEmail,
            text,
            timestamp: new Date().toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit"
            }),
            read: false
        };

        messages.push(msgObject);

        const targetSockets = onlineUsers.get(targetEmail);

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
        if (!currentEmail || !data || !data.targetEmail) {
            return;
        }

        const targetEmail = String(data.targetEmail)
            .toLowerCase()
            .trim();

        if (!areConnected(currentEmail, targetEmail)) {
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

        const targetSockets = onlineUsers.get(targetEmail);

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

        const sockets = onlineUsers.get(currentEmail);

        if (!sockets) {
            return;
        }

        sockets.delete(socket.id);

        if (sockets.size === 0) {
            onlineUsers.delete(currentEmail);
            emitStatus(currentEmail, false);
        }
    });
});

server.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});