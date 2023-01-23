require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const User = require('./models/user')
const app = express()

app.use(express.json())

app.get('/', (req, res) => {
  res.status(200).json({ message: 'Bem vindo a nossa   api' })
})
app.get('/user/id', async (req, res) => {
  const id = req.params.id

  const user = await User.findById(id, '-password')

  if (!user) {
    return res.status(404).json({ message: 'Usuário nao encontrado!' })
  }

  res.status(200).json({ user })
})
app.post('/auth/register', async (req, res) => {
  const { name, email, password, confirmpassword } = req.body

  if (!name) {
    return res.status(422).json({ message: 'O nome é obrigatório!' })
  }

  if (!email) {
    return res.status(422).json({ message: 'O email é obrigatório!' })
  }

  if (!password) {
    return res.status(422).json({ message: 'A senha é obrigatória!' })
  }

  if (password !== confirmpassword) {
    return res.status(422).json({ message: ':/' })
  }

  const userExists = await User.findOne({ email })

  if (userExists) {
    return res.status(422).json({ message: 'Por favor, utilize outro wmail' })
  }

  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  const user = new User({
    name,
    email,
    password: passwordHash
  })

  try {
    await user.save()

    res.status(201).json({ message: 'Usuario criado com sucesso' })
  } catch (error) {
    res.status(500).json({ msg: 'Erro no server ' })
  }
})
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body

  if (!email) {
    return res.status(422).json({ message: 'O email é obrigatório!' })
  }

  if (!password) {
    return res.status(422).json({ message: 'A senha é obrigatória!' })
  }

  const user = await User.findOne({ email })

  if (!user) {
    return res.status(422).json({ message: 'nao encontrado!' })
  }

  const checkPassword = await bcrypt.compare(password, user.password)
  if (!checkPassword) {
    return res.status(404).json({ message: 'senha errada' })
  }
  try {
    const secret = process.env.SECRET

    const token = jwt.sign({
      id: user._id
    },
    secret
    )
    res.status(200).json({ message: 'Autenticação Realizada', token })
  } catch (err) {
    res.status(500).json({ msg: 'Erro no server ' })
  }
})

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.lrjsbbk.mongodb.net/?retryWrites=true&w=majority`)
  .then(() => {
    app.listen(3000)
    console.log('conected')
  }).catch((err) => console.log(err))
