const express = require("express")
const db = require("./db")
const app = express()

const PORT = 3000
const SECRET = "123321123"


app.post("/auth/signup", (req, res) => {
    try {
        console.log(req.body);
        const { username, password, email } = req.body

        if (!username || !password) {
            return res.status(400).json({ error: "." })
        }

        if (username.length < 3) {
            return res.status(400).json({ error: "Недостаточно символов в пароле" })
        }
        if (password.length < 6) {
            return res.status(400).json({ error: "Недостаточно символов в пароле" })
        }

        const existing = db.prepare(
            "SELECT id FROM users WHERE username = ?"
        ).get(username)

        if (existing) return res.status(409).json({ error: "Пользователь уже существует" })

        const salt = bcr.genSaltSync(10)
        const hash = bcr.hashSync(password, salt)
        const role = "user"

        const info = db.prepare(`INSERT INTO users (username, email, password, role)
            VALUES(?,?,?,?)`).run(username.trim(), email.trim(), hash, role)

        const newUser = db.prepare(`SELECT * FROM users WHERE id = ?`).get(info.lastInsertRowid)

        const { password: _, ...safeUser } = newUser

        const token = jwt.sign({ ...safeUser }, SECRET, { expiresIn: "24h" })
        res.status(201).json({ success: true, token, user: safeUser })
    } catch (err) {
        console.error(err)
        return res.status(500).json({ error: "Failed to create" })
    }
})

app.listen(PORT)