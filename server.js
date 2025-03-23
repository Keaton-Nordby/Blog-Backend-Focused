require("dotenv").config()
const cookieParser = require("cookie-parser")
const sanitizeHTML = require("sanitize-html")
const marked = require("marked")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const express = require("express")
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

    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body TEXT NOT NULL,
        authorid INTEGER,
        FOREIGN KEY (authorid) REFERENCES users (id)
        )
        `).run()

})

createTables()

// database set up ends here
const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(cookieParser())

// setting up middleware
app.use(function (req, res, next) {

    // make our markdown function available
    res.locals.filterUserHTML = function(content)  {
        return sanitizeHTML(marked.parse(content), { 
            allowedTags: ["p", "br", "ul", "li", "ol", "strong", "bold", "i", "em", "h1", "h2", "h3", "h4", "h5", "h6"],
            allowedAttributes: {}
        })
    }

    res.locals.errors = []
    // try to decode incoming cookie

    try {
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
        req.user = decoded

    } catch(err) {
        req.user = false
    }

    res.locals.user = req.user
    console.log(req.user)
    next()
})

app.get("/", (req, res) => {
    if (req.user) {
        const postsStatement = db.prepare("SELECT * FROM posts WHERE authorid = ? ORDER BY createdDate DESC");
        const posts = postsStatement.all(req.user.userid);
        return res.render("dashboard", { posts })
    }
    res.render("homepage", { errors: [] }); // Ensure errors is always defined
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/logout", (req, res) => {
    res.clearCookie("ourSimpleApp")
    res.redirect("/")
})

app.post("/login", (req, res) => {
    let errors = [];

    if (typeof req.body.username !== "string") req.body.username = "";
    if (typeof req.body.password !== "string") req.body.password = "";

    if (req.body.username.trim() == "") errors = ["Invalid username / password."]
    if (req.body.password == "") errors = ["Invalid username / password."]

        if (errors.length) {
            return res.render("login", { errors })
        }

        const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
        const userInQuestion = userInQuestionStatement.get(req.body.username)

        if (!userInQuestion) {
            errors = ["Invalid username / password."]
            return res.render("login", { errors })
        }

        const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
        if (!matchOrNot) {
            errors = ["Invalid username / password."]
            return res.render("login", { errors })
        }

        // if its true give them a cookie and redirect them to the home page
        const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, userid: userInQuestion.id, username: userInQuestion.username }, process.env.JWTSECRET)

        res.cookie("ourSimpleApp", ourTokenValue, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 1000 * 60 * 60 * 24
        })

        res.redirect("/")
})

function mustBeLoggedIn(req, res, next) {
    if (req.user) {
        return next();
    }
    return res.redirect("/");

}

app.get("/create-post", mustBeLoggedIn, (req, res) => {
    res.render("create-post");
})

function sharedPostValidation(req) {
    const errors = [];

    if (typeof req.body.title !== "string") req.body.title = "";
    if (typeof req.body.body !== "string") req.body.body = "";

    // trim - sanitize or strip out html
    req.body.title = sanitizeHTML(req.body.title.trim(), { allowedTags: [], allowedAttributes: {}});
    req.body.body = sanitizeHTML(req.body.body.trim(), { allowedTags: [], allowedAttributes: {}});

    if (!req.body.title) errors.push("You must provide a title.")
    if (!req.body.body) errors.push("You must provide a title.")

    return errors
}

app.get("/edit-post/:id", mustBeLoggedIn, (req, res) => {
    // try to look up the post in question 
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
    const post = statement.get(req.params.id);

    if (!post) {
        return res.redirect("/");
    }

    // if you are not the author just redirect them to the homepage
    if (post.authorid !== req.user.userid) {
        return res.redirect("/");
    }



    // otherwise we will render the edit post template
    res.render("edit-post", { post });
})

app.post("/edit-post/:id", mustBeLoggedIn, (req, res) => {

    const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
    const post = statement.get(req.params.id);

    if (!post) {
        return res.redirect("/");
    }

    if (post.authorid !== req.user.userid) {
        return res.redirect("/");
    }

    const errors = sharedPostValidation(req);

    if (errors.length) {
        return res.render("edit-post", { errors });
    }

    const updateStatement = db.prepare("UPDATE posts SET title = ?, body = ? WHERE id = ?");
    updateStatement.run(req.body.title, req.body.body, req.params.id);

    res.redirect(`/post/${req.params.id}`);
})

app.post("/delete-post/:id", mustBeLoggedIn, (req, res) => {
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
    const post = statement.get(req.params.id);

    if (!post) {
        return res.redirect("/");
    }

    if (post.authorid !== req.user.userid) {
        return res.redirect("/");
    }

    const deleteStatement = db.prepare("DELETE FROM posts WHERE id = ?");
    deleteStatement.run(req.params.id);

    res.redirect("/");
})

app.get("/post/:id", (req, res) => {
    const statement = db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?");
    const post = statement.get(req.params.id);

    if (!post) {
        return res.redirect("/");
    }

    const isAuthor = post.authorid === req.user.userid;

    res.render("single-post", { post, isAuthor });
})

app.post("/create-post", mustBeLoggedIn, (req, res) => {
    const errors = sharedPostValidation(req);

    if(errors.length) {
        return res.render("create-post", { errors });
    }

    // if no errors we save the post into the database
    const ourStatement = db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)");
    const result = ourStatement.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString());

    const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?");
    const realPost = getPostStatement.get(result.lastInsertRowid);

    res.redirect(`/post/${realPost.id}`);
})

app.post("/register", (req, res) => {
    const errors = [];

    if (typeof req.body.username !== "string") req.body.username = "";
    if (typeof req.body.password !== "string") req.body.password = "";

    req.body.username = req.body.username.trim();

    if (!req.body.username) errors.push("You must provide a username.");
    if (req.body.username.length < 3) errors.push("Username must be greater than three characters long.");
    if (req.body.username.length > 10) errors.push("Username must not exceed ten characters.");
    if (!req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only consist of letters and numbers.");


    // check if username already exists
    const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?");
    const usernameCheck = usernameStatement.get(req.body.username);

    if (usernameCheck) errors.push("That username is already taken.");


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
        const result = ourStatement.run(req.body.username, req.body.password)

        const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
        const ourUser = lookupStatement.get(result.lastInsertRowid)

        // log the user in by giving them a cookie
        const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, userid: ourUser.id, username: ourUser.username }, process.env.JWTSECRET)


        res.cookie("ourSimpleApp", ourTokenValue, {
            // makes sure that client side js cannot access cookie in the browser
            httpOnly: true,
            secure: true,
            // helps to prevent cross site attacks or cross site cookie token attacks, unless you had a malicious sub domain
            sameSite: "strict",
            // this lets the cookie be good for one day, (measured in ms) hence why it starts with 1000
            maxAge: 1000 * 60 * 60 * 24
        })

        res.redirect("/")
    }
});

app.listen(4000, () => {
    console.log("Running on http://localhost:4000");
});
