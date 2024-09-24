/* imports */
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Config json response
app.use(express.json());

// Models
const User = require('./model/User');

// Open route - public route
app.get('/', (req, res) => {
    res.status(200).json({ message: 'Bem-vindo à nossa API' });
});

// Private route
app.get('/user/:id', async (req, res) => {
    const id = req.params.id;

    // Check if user exists
    const user = await User.findById(id, '-password');

    if (!user) {
        return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    return res.status(200).json({ user });
});

// Register user
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body;

    // Validation
    if (!name) return res.status(422).json({ message: 'O nome é obrigatório.' });
    if (!email) return res.status(422).json({ message: 'O email é obrigatório.' });
    if (!password) return res.status(422).json({ message: 'A senha é obrigatória.' });
    if (password !== confirmpassword) return res.status(422).json({ message: 'As senhas não conferem.' });

    // Check if user exists
    const userExists = await User.findOne({ email: email });
    if (userExists) return res.status(422).json({ message: 'Email já cadastrado.' });

    // Create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({ name, email, password: passwordHash });
    try {
        await user.save();
        res.status(201).json({ message: 'Usuário criado com sucesso.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro no servidor.' });
    }
});

// Login user
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    // Validations
    if (!email) return res.status(422).json({ message: 'O email é obrigatório.' });
    if (!password) return res.status(422).json({ message: 'A senha é obrigatória.' });

    // Check if user exists
    const user = await User.findOne({ email: email });
    if (!user) return res.status(422).json({ message: 'Usuário não encontrado.' });

    // Check if password matches
    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) return res.status(422).json({ message: 'Senha inválida.' });

    try {
        const secret = process.env.SECRET;
        const token = jwt.sign(
            { id: user._id },
            secret,
            { expiresIn: '15m' } // Token expira em 15 minutos
        );
        res.status(200).json({ message: 'Autenticação realizada com sucesso.', token });
    } catch (error) {
        res.status(500).json({ message: 'Erro no servidor.' });
    }
});

// Credenciais
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;
mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.f1cw5.mongodb.net/user?retryWrites=true&w=majority&appName=Cluster0`)
    .then(() => {
        app.listen(4000);
        console.log('Conectou ao banco de dados.');
    })
    .catch((err) => console.log(err));
