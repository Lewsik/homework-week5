'use strict'

const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const Sequelize = require('sequelize')

// read the DB password from environment variable
const dbPassword = process.env.DB_PASS
if (dbPassword == null || dbPassword === '') {
  console.error('DB_PASS environment variable must be set!')
  // exit program with an error
  process.exit(1)
}

const sequelize = new Sequelize(
  `postgres://postgres:${dbPassword}@localhost:5432/spotify`
)

// read JWT secret from environment variable
const jwtSecret = process.env.JWT_SECRET
if (jwtSecret == null || jwtSecret === '') {
  console.error('JWT_SECRET environment variable must be set!')
  // exit program with an error
  process.exit(1)
}

function toJWT(data) {
  return jwt.sign(data, jwtSecret, { expiresIn: '2h' })
}

function toData(token) {
  return jwt.verify(token, jwtSecret)
}

const express = require('express')

const User = sequelize.define('user', {
  email: Sequelize.TEXT,
  password: Sequelize.TEXT
}, {
  timestamps: false
})

// sequelize define creates a model
const Playlist = sequelize.define('playlist', {
  name: Sequelize.TEXT
}, {
  timestamps: false
})

const Song = sequelize.define('song', {
  title: Sequelize.TEXT,
  artist: Sequelize.TEXT,
  album: Sequelize.TEXT,
}, {
  timestamps: false
})

User.hasMany(Playlist);
Playlist.hasMany(Song);

// create express app
const app = express()
const port = 3000

async function main() {
  await User.sync()
  await Playlist.sync()
  await Song.sync()

  app.use(express.json())

  function auth(req, res, next) {
    const auth = req.headers.authorization
      && req.headers.authorization.split(' ')
    if (auth && auth[0] === 'Bearer' && auth[1]) {
      try {
        const data = toData(auth[1])
        User.findByPk(data.userId)
          .then(user => {
            if (user == null)
              return next('User does not exist')

            req.user = user
            next()
          })
          .catch(next)
      }
      catch(error) {
        res.status(400).send({
          error: `Error ${error.name}: ${error.message}`,
        })
      }
    }
    else {
      res.status(401).send({
        error: 'Unauthorized'
      })
    }
  }

  app.get('/playlists', auth, async (req, res) => {
    const playlists = await Playlist.findAll({
      where: {
        userId: req.user.id
      },
      attributes: [ 'id', 'name' ]
      // If we want to include songs in all playlists route:
      // include: [{ model: Song, attributes: [
      //   'id',
      //   'title',
      //   'album',
      //   'artist'
      // ] }]
    });

    res.json(playlists)
  })

  app.get('/playlists/:id', auth, async (req, res) => {
    const playlist = await Playlist.findOne({
      where: {
        userId: req.user.id,
        id: req.params.id
      },
      attributes: [ 'id', 'name' ],
      include: [{ model: Song, attributes: [
        'id',
        'title',
        'album',
        'artist'
      ] }]
    })

    if (playlist == null) {
      return res.status(404).json({
        error: 'Not found'
      })
    }

    res.json(playlist)
  })

  app.post('/playlists', auth, async (req, res) => {
    const playlist = await Playlist.create({
      name: req.body.name,
      userId: req.user.id
    })

    res.status(201).json(playlist);
  })

  app.delete('/playlists/:id', auth, async (req, res) => {
    const playlist = await Playlist.destroy({
      where: {
        userId: req.user.id,
        id: req.params.id
      }
    })

    if (playlist === 0) {
      return res.status(404).json({
        error: 'Not found'
      })
    }

    res.json(playlist)
  })

  app.post('/playlists/:id/songs', auth, async (req, res) => {
    const playlist = await Playlist.findOne({
      where: {
        userId: req.user.id,
        id: req.params.id
      }
    })

    if (playlist == null) {
      return res.status(422).json({
        error: 'Not found'
      })
    }

    const song = await Song.create({
      title: req.body.title,
      artist: req.body.artist,
      album: req.body.album,

      playlistId: playlist.id
    })

    res.status(201).json(song)
  })

  // creating users
  app.post('/users', async (req, res) => {
    if (req.body.password !== req.body.password_confirmation) {
      return res.json({
        error: "Passwords need to match!"
      })
    }

    const user = await User.create({
      email: req.body.email,
      password: bcrypt.hashSync(req.body.password, 10)
    })

    // Don't return user password hash
    const _user = await User.findByPk(user.id, {
      attributes: [ 'id', 'email' ]
    })

    res.status(201).json(_user)
  });

  // authentication
  app.post('/tokens', async (req, res) => {
    const user = await User.findOne({
      where: {
        email: req.body.email
      },
      attributes: [ 'id', 'password' ]
    })

    if (user == null || !bcrypt.compareSync(req.body.password, user.password)) {
      return res.status(401).json({
        error: 'Unauthorized'
      })
    }

    res.json({
      token: toJWT({
        userId: user.id
      })
    })
  });

  app.listen(port, () => {
    console.log(`Example app listening on port ${port}!`)
  })
}

main();
