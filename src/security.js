/*
    Fails Components (Fancy Automated Internet Lecture System - Components)
    Copyright (C)  2015-2017 (original FAILS), 
                   2021- (FAILS Components)  Marten Richter <marten.richter@freenet.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import jwt from 'jsonwebtoken'
import Redlock from 'redlock'
import jwtexpress from 'express-jwt'
import { promisify } from 'util'
import { generateKeyPair, createHash } from 'crypto'
import signer from 'url-signer'
import { writeFile, mkdir, rm } from 'fs/promises'

// this function converts a new redis object to an old one usable with redlock

export function RedisRedlockProxy(server) {
  const retobj = {
    _failsredisserver: server, // we do not need this but...
    evalsha: async (hash, args, callback) => {
      try {
        const result = await server.evalSha(hash, args)
        callback(undefined, result)
      } catch (error) {
        callback(error)
      }
    },
    eval: async (hash, args, callback) => {
      try {
        const result = await server.eval(args)
        callback(null, result)
      } catch (error) {
        callback(error)
      }
    }
  }
  return retobj
}

export class FailsJWTSigner {
  constructor(args) {
    this.redis = args.redis // redis database holding the keys
    this.type = args.type // e.g. screen, notepad, screen etc.
    this.expiresIn = args.expiresIn // the lifetime of the generated JWT
    this.keys = [] // cache keys
    this.keychecktime = 0

    this.secret = args.secret

    this.redlock = new Redlock([RedisRedlockProxy(this.redis)], {
      driftFactor: 0.01, // multiplied by lock ttl to determine drift time

      retryCount: 10,

      retryDelay: 200, // time in ms
      retryJitter: 200 // time in ms
    })

    this.signToken = this.signToken.bind(this)
  }

  async signToken(token) {
    const time = Date.now()
    if (
      this.keys.length === 0 ||
      this.keys[0].expire < time ||
      this.keychecktime + 1000 * 60 * 60 * 12 < time
    ) {
      // rotate every 12 h
      await this.recheckKeys()
    }
    // now hopefully we have working keys
    return jwt.sign(
      { ...token, kid: this.keys[0].id },
      this.secret
        ? { key: this.keys[0].privatekey, passphrase: this.secret }
        : this.keys[0].privatekey,
      { expiresIn: this.expiresIn, keyid: this.keys[0].id, algorithm: 'ES512' }
    )
  }

  async recheckKeys() {
    await this.keysUpdateInt()
    let lock = null

    if (this.keys.length === 0) {
      // ok again, but this time with locking to make sure no other process is generating keys, while we do
      lock = await this.redlock.lock('keys:' + this.type + ':loadlock', 2000)
      await this.keysUpdateInt()
      // do we still need a new key
      if (this.keys.length === 0) {
        console.log('Generate private public key pair for ' + this.type)
        const id = Math.random().toString(36).substr(2, 9) // not the best for crypto, but does not matter
        const pgenerateKeyPair = promisify(generateKeyPair)

        try {
          const result = await pgenerateKeyPair('ec', {
            namedCurve: 'P-521',
            publicKeyEncoding: {
              type: 'spki',
              format: 'pem'
            },
            privateKeyEncoding: {
              type: 'pkcs8',
              format: 'pem',
              cipher: 'aes-256-cbc',
              passphrase: this.secret
            }
          })
          await Promise.all([
            this.redis.set(
              'JWTKEY:' + this.type + ':private:' + id,
              result.privateKey,
              'EX',
              60 * 60 * 12
            ),
            this.redis.set(
              'JWTKEY:' + this.type + ':public:' + id,
              result.publicKey,
              'EX',
              60 * 60 * 24
            )
          ])
        } catch (error) {
          console.log('recheckKeys error key create', error)
        }
      }

      if (lock) lock.unlock()
      await this.keysUpdateInt()
    }
    this.keychecktime = Date.now()
  }

  async keysUpdateInt() {
    // ok first we get all keys in data base
    this.keys = []

    let cursor = 0

    try {
      const promstore = []
      console.log('redis scan', this.redis.scan, this.redis)
      do {
        const scanret = await this.redis.scan(cursor, {
          MATCH: 'JWTKEY:' + this.type + ':private:*',
          COUNT: 1000
        }) // keys are seldom

        console.log('show scanret', scanret)
        const myprom = scanret[1].map((el2) => {
          return Promise.all([el2, this.redis.get(el2)])
        })
        promstore.push(...myprom)

        cursor = scanret[0]
      } while (cursor !== '0')
      const keyres = await Promise.all(promstore)
      const idoffset = ('JWTKEY:' + this.type + ':private:').length
      this.keys = keyres
        .filter((el) => el.length === 2)
        .map((el) => ({ id: el[0].substr(idoffset), privatekey: el[1] }))
    } catch (error) {
      console.log('keysUpdateInt error', error)
    }
  }
}

export class FailsJWTVerifier {
  constructor(args) {
    this.redis = args.redis // redis database holding the keys
    this.type = args.type // e.g. screen, notepad, screen etc.
    this.keys = {}
    this.keyschecktime = 0

    this.socketauthorize = this.socketauthorize.bind(this)
    this.fetchKey = this.fetchKey.bind(this)
  }

  socketauthorize() {
    return async (socket, next) => {
      // console.log("auth attempt");
      if (socket.handshake.auth && socket.handshake.auth.token) {
        const decoded = jwt.decode(socket.handshake.auth.token)
        if (!decoded) return next(new Error('Authentification Error'))
        const keyid = decoded.kid
        const time = Date.now()
        if (
          !this.keys[keyid] ||
          this.keys[keyid].fetched + 60 * 1000 * 10 < time
        ) {
          await this.fetchKey(keyid)
        }
        // console.log("keys",keyid, this.type, this.keys[keyid]);
        jwt.verify(
          socket.handshake.auth.token,
          this.keys[keyid].publicKey /* TODO */,
          { algorithms: ['ES512'] },
          (err, decoded) => {
            if (err) {
              return next(new Error('Authentification Error'))
            }
            socket.decoded_token = decoded
            console.log('socket authorize worked!')
            next()
          }
        )
      } else {
        next(new Error('Authentification error'))
      }
    }
  }

  async fetchKey(key) {
    delete this.keys[key] // delete, important for key expiry
    const name = 'JWTKEY:' + this.type + ':public:' + key
    try {
      let publick = this.redis.get(name)
      publick = await publick
      // console.log("public",publick,name);
      if (!publick) return // not found
      this.keys[key] = {}
      this.keys[key].publicKey = publick
      this.keys[key].fetch = Date.now()
    } catch (err) {
      console.log('Error fetchKey', err)
    }
  }

  express() {
    const secretCallback = async (req, payload, done) => {
      const keyid = payload.kid
      const time = Date.now()

      if (
        !this.keys[keyid] ||
        this.keys[keyid].fetched + 60 * 1000 * 10 < time
      ) {
        await this.fetchKey(keyid)
        if (!this.keys[keyid])
          return done(new Error('unknown or expired key or db error'))
      }
      done(null, this.keys[keyid].publicKey)
    }
    return jwtexpress({
      secret: secretCallback,
      algorithms: ['ES512'],
      requestProperty: 'token'
    })
  }
}

export class FailsAssets {
  constructor(args) {
    this.datadir = args.datadir ? args.datadir : 'files'
    this.dataurl = args.dataurl
    this.webservertype = args.webservertype ? args.webservertype : 'local'
    this.privateKey = args.privateKey
    this.savefile = args.savefile
    if (!this.privateKey) throw new Error('No private key for assets')

    if (this.webservertype === 'local') {
      // signed url, better use an nginx and its secure url scheme or signed urls for an S3 bucket.
      // url-signer only allows global settings, this is not pretty
      signer.init({
        privateKey: this.privateKey,
        algorithm: 'sha512',
        digest: 'base64',
        ttl: 60 * 24 // just one day, maximum time for a lecture
      })
    }

    this.shatofilenameLocal = this.shatofilenameLocal.bind(this)
    this.getFileURL = this.getFileURL.bind(this)
    this.saveFile = this.saveFile.bind(this)
    this.shadeletelocal = this.shadeletelocal.bind(this)
  }

  getFileURL(sha, mimetype) {
    if (this.webservertype === 'local') {
      return (
        this.dataurl +
        signer.getSignedUrl('/' + this.shatofilenameLocal(sha, mimetype))
      )
    } else if (this.webservertype === 'nginx') {
      const url = '/' + this.shatofilenameLocal(sha, mimetype)
      const expires = new Date().getTime() + 1000 * 60 * 60 * 24
      const input = expires + url + ' ' + this.privateKey
      const binaryHash = createHash('md5').update(input).digest()
      const base64Value = Buffer.from(binaryHash).toString('base64')
      const mdhash = base64Value
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')

      let mydataurl = this.dataurl
      if (mydataurl === '/') mydataurl = ''

      return mydataurl + url + '?md5=' + mdhash + '&expires=' + expires
    }
  }

  localServer() {
    return this.webservertype === 'local'
  }

  getLocalVerifier() {
    return signer.verifier()
  }

  shatofilenameLocal(sha, mime) {
    const shahex = sha.toString('hex')
    const dir =
      this.datadir + '/' + shahex.substr(0, 2) + '/' + shahex.substr(2, 4)
    return dir + '/' + shahex + this.mimeToExtension(mime)
  }

  async shadeletelocal(shahex, ext) {
    const dir =
      this.datadir + '/' + shahex.substr(0, 2) + '/' + shahex.substr(2, 4)
    await rm(dir + '/' + shahex + '.' + ext)
  }

  async shamkdirLocal(sha) {
    const shahex = sha.toString('hex')
    const dir =
      this.datadir + '/' + shahex.substr(0, 2) + '/' + shahex.substr(2, 4)
    await mkdir(dir, { recursive: true })
  }

  async saveFile(blob, sha, mime) {
    if (this.savefile === 'fs') {
      await this.shamkdirLocal(sha)
      const filename = this.shatofilenameLocal(sha, mime)

      await writeFile(filename, blob)
    } else throw new Error('unsupported savefile method ' + this.savefile)
  }

  mimeToExtension(mime) {
    switch (mime) {
      case 'application/pdf':
        return '.pdf'
      case 'image/jpeg':
        return '.jpg'
      case 'image/png':
        return '.png'
      default:
        return ''
    }
  }
}
