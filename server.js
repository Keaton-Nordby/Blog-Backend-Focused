const bcrypt = require("bcrypt")
const express = require("express");
const db = require("better-sqlite3")("ourApp.db")
db.pragma("journal_mode = WAL")

// database set up starts here

const createTables = db.transaction(() => {
    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
        `).run()

})

createTables()

// database set up ends here
const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

// setting up middleware
app.use(function (req, res, next) {
    res.locals.errors = []

    next()
})

app.get("/", (req, res) => {
    res.render("homepage", { errors: [] }); // Ensure errors is always defined
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/register", (req, res) => {
    const errors = [];

    if (typeof req.body.username !== "string") req.body.username = "";
    if (typeof req.body.password !== "string") req.body.password = "";

    req.body.username = req.body.username.trim();

    if (!req.body.username) errors.push("You must provide a username.");
    if (req.body.username.length < 3) errors.push("Username must be greater than three characters long.");
    if (req.body.username.length > 10) errors.push("Username must not exceed ten characters.");
    if (!req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only consist of letters and numbers.");

    if (!req.body.password) errors.push("You must provide a password.");
    if (req.body.password.length < 12) errors.push("Password must be greater than than twelve characters long.");
    if (req.body.password.length > 50) errors.push("Password must not exceed seventy characters.");

    if (errors.length) {
        return res.render("homepage", { errors });
    } else {
        
        // save the new user into the database
        // hashing passwords for privacy reasons (10) = 10 passes
        const salt = bcrypt.genSaltSync(10)
        // now this is what will be saved into the database
        req.body.password = bcrypt.hashSync(req.body.password, salt)


        const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
        ourStatement.run(req.body.username, req.body.password)

        // log the user in by giving them a cookie
        res.cookie("ourSimpleApp", "supertopsecretvalue", {
            // makes sure that client side js cannot access cookie in the browser
            httpOnly: true,
            secure: true,
            // helps to prevent cross site attacks or cross site cookie token attacks, unless you had a malicious sub domain
            sameSite: "strict",
            // this lets the cookie be good for one day, (measured in ms) hence why it starts with 1000
            maxAge: 1000 * 60 * 60 * 24
        })

        res.send("Thank you!")
    }
});

app.listen(4000, () => {
    console.log("Running on http://localhost:4000");
});
