const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static("public")); // pour servir index.html et login.html

// Connexion MongoDB
mongoose.connect("mongodb://127.0.0.1:27017/notesDB");

// ================= MODELES =================

// User
const User = mongoose.model("User", {
    email: String,
    password: String
});

// Note (lié à un utilisateur 🔥)
const Note = mongoose.model("Note", {
    title: String,
    content: String,
    userId: String
});

// ================= MIDDLEWARE AUTH =================

function auth(req, res, next) {
    const token = req.headers.authorization;

    if (!token) return res.status(401).send("Accès refusé");

    try {
        const decoded = jwt.verify(token, "SECRET_KEY");
        req.user = decoded;
        next();
    } catch {
        res.status(400).send("Token invalide");
    }
}

// ================= AUTH ROUTES =================

// REGISTER
app.post("/register", async (req, res) => {
    const { email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
        email,
        password: hashedPassword
    });

    await user.save();

    res.send({ message: "Utilisateur créé" });
});

// LOGIN
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        return res.status(400).send({ message: "Utilisateur non trouvé" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        return res.status(400).send({ message: "Mot de passe incorrect" });
    }

    const token = jwt.sign({ id: user._id }, "SECRET_KEY");

    res.send({ token });
});

// ================= NOTES ROUTES =================

// Ajouter une note (liée au user)
app.post("/notes", auth, async (req, res) => {
    const note = new Note({
        title: req.body.title,
        content: req.body.content,
        userId: req.user.id
    });

    await note.save();
    res.send(note);
});

// Voir SES notes uniquement 🔥
app.get("/notes", auth, async (req, res) => {
    const notes = await Note.find({ userId: req.user.id });
    res.send(notes);
});

// Supprimer UNE note du user
app.delete("/notes/:id", auth, async (req, res) => {
    await Note.findOneAndDelete({
        _id: req.params.id,
        userId: req.user.id
    });

    res.send({ message: "Supprimé" });
});

// ================= SERVER =================

app.listen(3000, () => console.log("Serveur lancé sur port 3000"));