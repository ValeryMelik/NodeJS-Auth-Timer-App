const express = require("express");
const nunjucks = require("nunjucks");
const { nanoid } = require("nanoid");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");

const fs = require("fs");
const path = require("path");

class db {
  constructor(dbName, initialData = []) {
    this.dbName = dbName;
    this.initialData = initialData;
    this.dirPath = path.resolve(__dirname, "db");
    this.filePath = path.join(this.dirPath, `${dbName}.json`);
    this.createDB();
  }

  createDB() {
    if (!fs.existsSync(this.dirPath)) {
      fs.mkdirSync(this.dirPath);
    }
    if (!fs.existsSync(this.filePath)) {
      fs.writeFileSync(this.filePath, JSON.stringify(this.initialData), "utf-8");
    }
  }

  read() {
    this.createDB();
    const data = fs.readFileSync(this.filePath, "utf-8");
    return JSON.parse(data);
  }

  write(data) {
    const newData = JSON.stringify(data, null, 2);
    fs.writeFileSync(this.filePath, newData, "utf-8");
  }
}

const TIMERS = new db("timers");
const USERS = new db("users");
const SESSIONS = new db("sessions", {});

function updateSession(user) {
  const sessionId = nanoid();
  const sessions = SESSIONS.read();
  sessions[sessionId] = { userId: user._id };
  SESSIONS.write(sessions);

  return sessionId;
}

function checkSession(req, res) {
  const sessionId = req.cookies?.sessionId;
  const sessions = SESSIONS.read();
  const session = sessions[sessionId];

  if (!sessionId || !session) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  return session;
}

const app = express();

nunjucks.configure("views", {
  autoescape: true,
  express: app,
  tags: {
    blockStart: "[%",
    blockEnd: "%]",
    variableStart: "[[",
    variableEnd: "]]",
    commentStart: "[#",
    commentEnd: "#]",
  },
});

app.set("view engine", "njk");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(cookieParser());

app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  const users = USERS.read();

  const existingUser = users.find((user) => user.username === username);
  if (existingUser) {
    return res.status(409).json({ message: "Username already taken" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      _id: nanoid(),
      username,
      password: hashedPassword,
    };

    users.push(newUser);
    USERS.write(users);

    const sessionId = updateSession(newUser);
    res.cookie("sessionId", sessionId, {
      httpOnly: true,
      // secure: true,
      sameSite: "Strict",
    });

    // res.status(201).json({ message: "Signup successful", user: { username: newUser.username } });
    res.redirect("/");
  } catch (error) {
    res.status(500).json({ message: "Error creating user", error });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  const users = USERS.read();

  const user = users.find((user) => user.username === username);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  try {
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ message: "Incorrect password" });
    }

    const sessionId = updateSession(user);

    res.cookie("sessionId", sessionId, {
      httpOnly: true,
      // secure: true,
      sameSite: "Strict",
    });

    // res.status(200).json({ message: "Login successful", user: { username: user.username } });
    res.redirect("/");
  } catch (error) {
    res.status(500).json({ message: "Error during login", error });
  }
});

app.get("/logout", (req, res) => {
  const session = checkSession(req, res);
  if (!session) return;

  const sessions = SESSIONS.read();

  delete sessions[req.cookies.sessionId];
  SESSIONS.write(sessions);

  res.clearCookie("sessionId", {
    httpOnly: true,
    // secure: true,
    sameSite: "Strict",
  });

  // res.status(200).json({ message: "Logged out successfully" });
  res.redirect("/");
});

app.get("/", (req, res) => {
  const sessionId = req.cookies?.sessionId;
  let user = null;

  if (sessionId) {
    const sessions = SESSIONS.read();
    const session = sessions[sessionId];
    if (session) {
      user = USERS.read().find((user) => user._id === session.userId);
    }
  }

  res.render("index", {
    user: user,
    authError: req.query.authError === "true" ? "Wrong username or password" : req.query.authError,
  });
});

app.get("/api/timers", (req, res) => {
  const session = checkSession(req, res);
  if (!session) return;

  const { isActive } = req.query;
  const isActiveBool = isActive === "true";
  const timers = TIMERS.read();

  const filteredTimers = timers.filter((timer) => timer.isActive === isActiveBool && timer.userId === session.userId);
  res.json(filteredTimers);
});

app.post("/api/timers", (req, res) => {
  const session = checkSession(req, res);
  if (!session) return;

  try {
    const { description } = req.body;
    if (!description) {
      throw new Error("Description is required");
    }

    const newTimer = {
      id: nanoid(),
      start: Date.now(),
      description: description,
      isActive: true,
      userId: session.userId,
      progress: 0,
    };

    const timers = TIMERS.read();

    timers.push(newTimer);
    TIMERS.write(timers);

    res.status(201).json(newTimer);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.post("/api/timers/:id/stop", (req, res) => {
  const session = checkSession(req, res);
  if (!session) return;

  const id = req.params.id;
  const timers = TIMERS.read();

  const timer = timers.find((t) => t.id === id && t.userId === session.userId);

  if (!timer) {
    return res.status(403).send("Access denied");
  }

  timer.isActive = false;
  timer.end = Date.now();
  timer.duration = timer.end - timer.start;

  TIMERS.write(timers);

  res.status(200).json(timer);
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`  Listening on http://localhost:${port}`);
});
