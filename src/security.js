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
import { expressjwt as jwtexpress } from 'express-jwt'
import { promisify } from 'util'
import { generateKeyPair, createHash, createHmac } from 'node:crypto'
import { Transform } from 'node:stream'
import { writeFile, mkdir, rm, stat, readdir, open, rename } from 'fs/promises'
import axios from 'axios'
import { XMLParser } from 'fast-xml-parser'
import { randomUUID } from 'crypto'
import { finished } from 'stream/promises'

// this function converts a new redis object to an old one usable with redlock

export function RedisRedlockProxy(server) {
  const retobj = {
    _failsredisserver: server, // we do not need this but...
    evalsha: async (hash, args, callback) => {
      try {
        const targs = args.map((el) => el.toString())
        const result = await server.sendCommand(['EVALSHA', hash, ...targs])
        callback(null, result)
      } catch (error) {
        callback(error)
      }
    },
    eval: async (args, callback) => {
      try {
        const targs = args.map((el) => el.toString())
        const result = await server.sendCommand(['EVAL', ...targs])
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
        console.log('new key id:', id)

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
              { EX: 60 * 60 * 12 }
            ),
            this.redis.set(
              'JWTKEY:' + this.type + ':public:' + id,
              result.publicKey,
              { EX: 60 * 60 * 24 }
            )
          ])
          console.log('new key stored:', id, Date.now())
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
      do {
        const scanret = await this.redis.scan(cursor, {
          MATCH: 'JWTKEY:' + this.type + ':private:*',
          COUNT: 1000
        }) // keys are seldom

        const myprom = scanret.keys.map((el2) => {
          return Promise.all([el2, this.redis.get(el2)])
        })
        promstore.push(...myprom)

        cursor = scanret.cursor
      } while (cursor !== 0)
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
        if (!this.keys[keyid]) {
          console.log('unknown key abort', keyid, this.type, time)
          return next(
            new Error('Authentification Error, unknown keyid ' + keyid)
          )
        }
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
      // console.log('public', publick, name)
      if (!publick) return // not found
      this.keys[key] = {}
      this.keys[key].publicKey = publick
      this.keys[key].fetch = Date.now()
    } catch (err) {
      console.log('Error fetchKey', err)
    }
  }

  async getPublicKey(keyid) {
    const time = Date.now()

    if (!this.keys[keyid] || this.keys[keyid].fetched + 60 * 1000 * 10 < time) {
      await this.fetchKey(keyid)
      if (!this.keys[keyid]) return null
    }
    return this.keys[keyid].publicKey
  }

  express() {
    const secretCallback = async (req, { header, payload }) => {
      const keyid = payload.kid
      const time = Date.now()

      if (
        !this.keys[keyid] ||
        this.keys[keyid].fetched + 60 * 1000 * 10 < time
      ) {
        await this.fetchKey(keyid)
        if (!this.keys[keyid])
          throw new Error('unknown or expired key or db error')
      }
      return this.keys[keyid].publicKey
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
    this.webservertype = args.webservertype

    this.savefile = args.savefile
    this.privateKey = args.privateKey
    if (this.webservertype === 'nginx') {
      if (!this.privateKey) throw new Error('No private key for assets')
    }

    if (
      this.webservertype === 'openstackswift' ||
      this.savefile === 'openstackswift'
    ) {
      // TODO check if credentials are passed

      this.swiftaccount = args.swift?.account
      this.swiftcontainer = args.swift?.container
      this.swiftkey = args.swift?.key
      this.swiftbaseurl = args.swift?.baseurl
      this.swiftauthbaseurl = args.swift?.authbaseurl
      if (
        !this.swiftaccount ||
        !this.swiftcontainer ||
        !this.swiftkey ||
        !this.swiftbaseurl
      ) {
        throw new Error('Swift credentials incomplete!')
      }
      if (this.savefile === 'openstackswift') {
        this.swiftusername = args.swift?.username
        this.swiftpassword = args.swift?.password
        this.swiftdomain = args.swift?.domain
        this.swiftproject = args.swift?.project
        if (
          !this.swiftusername ||
          !this.swiftpassword ||
          !this.swiftdomain ||
          !this.swiftproject ||
          !this.swiftauthbaseurl
        )
          throw new Error('Swift save credentials incomplete!')
      }
    }
    if (this.webservertype === 's3' || this.savefile === 's3') {
      this.s3AK = args.s3?.AK
      this.s3SK = args.s3?.SK
      this.s3region = args.s3?.region
      this.s3bucket = args.s3?.bucket
      this.s3host = args.s3?.host
      this.s3alturl = args.s3?.alturl
      if (
        !this.s3AK ||
        !this.s3SK ||
        !this.s3region ||
        !this.s3bucket ||
        !this.s3host
      )
        throw new Error('S3 parameters missing')
    }

    this.shatofilenameLocal = this.shatofilenameLocal.bind(this)
    this.getFileURL = this.getFileURL.bind(this)
    this.saveFile = this.saveFile.bind(this)
    this.saveFileStream = this.saveFileStream.bind(this)
    this.shadelete = this.shadelete.bind(this)
    this.setupAssets = this.setupAssets.bind(this)

    this.emptyhash = createHash('sha256').update('').digest('hex')
    this.xmlparser = new XMLParser()
  }

  async setupAssets() {
    console.log('setting up assets')
    if (this.savefile === 'openstackswift') {
      console.log('configuring open stack headers')
      // first get auth token
      const authtoken = await this.openstackToken()

      let response
      try {
        const path = '/v1/' + this.swiftaccount + '/' + this.swiftcontainer
        response = await axios.post(
          this.swiftbaseurl + path,
          {},
          {
            headers: {
              'X-Auth-Token': authtoken,
              'X-Container-Meta-Temp-URL-Key': this.swiftkey,
              'X-Container-Meta-Access-Control-Allow-Origin': '*'
            }
          }
        )
        if (response?.status !== 204) {
          console.log('axios response', response)
          throw new Error('setup assests for openstack failed')
        }
      } catch (error) {
        console.log('axios response', response)
        console.log('problem axios setup', error)
        throw new Error('setup assests for openstack failed')
      }
    }
  }

  async getAssetList() {
    if (this.savefile === 's3') {
      let marker
      const fslist = []
      while (true) {
        const host = this.s3bucket + '.' + this.s3host
        const uri = '/'
        let path = 'https://' + host + uri
        const date = new Date()
        const headers = {
          Date: date.toUTCString(),
          Host: host,
          'x-amz-content-sha256': this.emptyhash
        }
        let response
        let query
        if (marker) {
          query = 'marker=' + marker
          path += '?' + query
        }
        try {
          headers.Authorization = this.s3AuthHeader({
            headers,
            uri,
            verb: 'GET',
            query,
            hashedpayload: this.emptyhash,
            date
          })
          response = await axios.get(path, {
            headers
          })
          if (response?.status !== 200) {
            console.log('axios response', response)
            if (response?.status === 404) break
            throw new Error('get list failed')
          }
          if (response.data) {
            const contents = this.xmlparser.parse(response.data)
              ?.ListBucketResult?.Contents
            if (contents) {
              fslist.push(
                ...contents.map((el) => ({
                  id: el.Key,
                  size: el.Size
                }))
              )
              marker = contents[contents.length - 1].Key
            } else break
          } else break // no further data
        } catch (error) {
          console.log('axios response', response)
          console.log('problem axios get', error)
          throw error
        }
      }
      return fslist
    } else if (this.savefile === 'openstackswift') {
      let marker
      const fslist = []
      while (true) {
        let response
        try {
          const path =
            '/v1/' +
            this.swiftaccount +
            '/' +
            this.swiftcontainer +
            (marker ? '?marker=' + marker : '')
          response = await axios.get(this.swiftbaseurl + path, {
            headers: { 'X-Auth-Token': await this.openstackToken() }
          })
          if (response?.status !== 200) {
            console.log('axios response', response)
            if (response?.status === 404) break
            throw new Error('get list failed')
          }
          if (response.data?.length) {
            fslist.push(
              ...response.data.map((el) => ({
                id: el.name,
                size: el.bytes,
                mime: el.content_type
              }))
            )
            marker = response.data[response.data.length - 1].name
          } else break // no further data
        } catch (error) {
          console.log('axios response', response)
          console.log('problem axios get', error)
          throw error
        }
      }
      return fslist
    } else if (this.savefile === 'fs') {
      console.log('datadir', this.datadir)
      const startsearch = this.datadir + '/'
      const fslist = []
      const searchdir = async (path) => {
        const dirfiles = await readdir(path)
        for await (const file of dirfiles) {
          const curstat = await stat(path + file)
          if (curstat.isFile()) {
            const finfo = file.split('.')
            fslist.push({
              id: finfo[0],
              size: curstat.size,
              mime:
                finfo.length > 1 ? this.extensionToMime(finfo[1]) : undefined
            })
          } else if (curstat.isDirectory()) {
            await searchdir(path + file + '/')
          }
        }
      }
      await searchdir(startsearch)
      return fslist
    } else throw new Error('undefined or unknown save type')
  }

  // now we skip URIencode and restrict names thus to number and normal letter,
  // which is sufficient for our application
  s3CalculateSignature({
    iso8601date,
    sdate,
    verb,
    headers,
    signedheaders,
    uri,
    query = '',
    scope,
    hashedpayload
  }) {
    const cheaders = Object.entries(headers)
      .map(([key, value]) => key.toLowerCase() + ':' + value.trim() + '\n')
      .join('')

    const canonicalRequest =
      verb +
      '\n' +
      uri +
      '\n' +
      query +
      '\n' +
      cheaders +
      '\n' +
      signedheaders +
      '\n' +
      hashedpayload
    const stringToSign =
      'AWS4-HMAC-SHA256' +
      '\n' +
      iso8601date +
      '\n' +
      scope +
      '\n' +
      createHash('sha256').update(canonicalRequest).digest('hex')
    // console.log('Canonical Request:\n', canonicalRequest)
    // console.log('stringToSign:\n', stringToSign)

    const DateKey = createHmac('sha256', 'AWS4' + this.s3SK)
      .update(sdate, 'utf8')
      .digest()

    const DateRegionKey = createHmac('sha256', DateKey)
      .update(this.s3region, 'utf8')
      .digest()
    const DateRegionServiceKey = createHmac('sha256', DateRegionKey)
      .update('s3', 'utf8')
      .digest()
    const SigningKey = createHmac('sha256', DateRegionServiceKey)
      .update('aws4_request', 'utf8')
      .digest()

    return createHmac('sha256', SigningKey)
      .update(stringToSign, 'utf8')
      .digest('hex')
  }

  s3Dates(date) {
    const wdate = date || new Date()
    const twodigits = (inp) => ('0' + inp).slice(-2)
    const sdate =
      wdate.getUTCFullYear() +
      twodigits(wdate.getUTCMonth() + 1) +
      twodigits(wdate.getUTCDate())
    const iso8601date =
      sdate +
      'T' +
      twodigits(wdate.getUTCHours()) +
      twodigits(wdate.getUTCMinutes()) +
      twodigits(wdate.getUTCSeconds()) +
      'Z'

    return { sdate, iso8601date }
  }

  s3AuthHeader(args) {
    const { headers } = args
    const signedheaders = Object.keys(headers)
      .map((el) => el.toLowerCase())
      .join(';')

    const { sdate, iso8601date } = this.s3Dates(args.date)

    const scope = sdate + '/' + this.s3region + '/s3/aws4_request'
    return (
      'AWS4-HMAC-SHA256' +
      ' Credential=' +
      this.s3AK +
      '/' +
      scope +
      ',' +
      'SignedHeaders=' +
      signedheaders +
      ',' +
      'Signature=' +
      this.s3CalculateSignature({
        sdate,
        iso8601date,
        headers,
        signedheaders,
        scope,
        ...args
      })
    )
  }

  // may be should go to security
  async openstackToken() {
    let token = await this.ostoken
    if (!token || token.expire < Date.now() - 60 * 60 * 1000) {
      let myres, myrej
      this.ostoken = new Promise((resolve, reject) => {
        myres = resolve
        myrej = reject
      })
      try {
        const ret = await axios.post(
          this.swiftauthbaseurl + '/v3/auth/tokens',
          {
            auth: {
              identity: {
                methods: ['password'],
                password: {
                  user: {
                    name: this.swiftusername,
                    password: this.swiftpassword,
                    domain: {
                      id: this.swiftdomain
                    }
                  }
                },
                scope: {
                  project: {
                    name: this.swiftproject,
                    domain: { id: this.swiftdomain }
                  }
                }
              }
            }
          },
          {
            header: {
              'Content-Type': 'application/json;charset=utf8'
            }
          }
        )
        if (
          ret &&
          ret?.status === 201 &&
          ret?.data?.token?.expires_at &&
          ret?.headers?.['x-subject-token']
        ) {
          token = {
            token: ret.headers['x-subject-token'],
            tokeninfo: ret.data.token,
            expire: new Date(ret.data.token.expires_at).getTime()
          }
          myres(token)
        } else {
          console.log('axios response', ret)
          myrej(new Error('problem getting token'))
        }
      } catch (error) {
        myrej(error)
      }
    }
    return token?.token
  }

  getFileURL(sha, mimetype) {
    if (this.webservertype === 's3') {
      const host = this.s3bucket + '.' + this.s3host
      const shahex = sha.toString('hex')
      const uri = '/' + shahex
      const path = 'https://' + (this.s3alturl || host) + uri
      const headers = { Host: this.s3alturl || host }

      const expiresInSeconds = 60 * 60 * 24
      const signedheaders = Object.keys(headers)
        .map((el) => el.toLowerCase())
        .join(';')
      const { sdate, iso8601date } = this.s3Dates()
      const scope = sdate + '/' + this.s3region + '/s3/aws4_request'
      const scopeurl = sdate + '%2F' + this.s3region + '%2Fs3%2Faws4_request'
      const query =
        'X-Amz-Algorithm=AWS4-HMAC-SHA256' +
        '&X-Amz-Credential=' +
        this.s3AK +
        '%2F' +
        scopeurl +
        '&X-Amz-Date=' +
        iso8601date +
        '&X-Amz-Expires=' +
        expiresInSeconds +
        '&X-Amz-SignedHeaders=' +
        signedheaders

      const signature = this.s3CalculateSignature({
        hashedpayload: 'UNSIGNED-PAYLOAD',
        sdate,
        iso8601date,
        headers,
        signedheaders,
        scope,
        query,
        uri,
        verb: 'GET'
      })
      return path + '?' + query + '&X-Amz-Signature=' + signature
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
    } else if (this.webservertype === 'openstackswift') {
      const expires = Math.floor(Date.now() / 1000) + 60 * 60 * 24
      const shahex = sha.toString('hex')
      const path =
        '/v1/' + this.swiftaccount + '/' + this.swiftcontainer + '/' + shahex
      const key = this.swiftkey
      const hmacBody = 'GET\n' + expires + '\n' + path
      const signature = createHmac('sha256', key)
        .update(hmacBody, 'utf8')
        .digest('hex')

      return (
        this.swiftbaseurl +
        path +
        '?temp_url_sig=' +
        signature +
        '&temp_url_expires=' +
        expires +
        '&filename=' +
        shahex.substr(0, 16) +
        this.mimeToExtension(mimetype)
      )
    } else
      throw new Error('unsupported webservertype assets:' + this.webservertype)
  }

  shatofilenameLocal(sha, mime) {
    const shahex = sha.toString('hex')
    const dir =
      this.datadir + '/' + shahex.substr(0, 2) + '/' + shahex.substr(2, 4)
    return dir + '/' + shahex + this.mimeToExtension(mime)
  }

  async tempmkdirLocal() {
    await mkdir(this.datadir + '/temp', { recursive: true })
  }

  tempFileLocal() {
    const dir = this.datadir + '/temp/upload-' + randomUUID() + '.tmp'
    return dir
  }

  async shadelete(shahex, ext) {
    if (this.savefile === 'fs') {
      const dir =
        this.datadir + '/' + shahex.substr(0, 2) + '/' + shahex.substr(2, 4)
      await rm(dir + '/' + shahex + '.' + ext)
    } else if (this.savefile === 's3') {
      const host = this.s3bucket + '.' + this.s3host
      const uri = '/' + shahex
      const path = 'https://' + host + uri
      const date = new Date()
      const headers = {
        Date: date.toUTCString(),
        Host: host,
        'x-amz-content-sha256': this.emptyhash
      }
      let response
      try {
        headers.Authorization = this.s3AuthHeader({
          headers,
          uri,
          verb: 'DELETE',
          date,
          hashedpayload: this.emptyhash
        })
        response = await axios.delete(path, {
          headers
        })
        if (response?.status !== 204) {
          console.log('axios response', response)
          throw new Error('delete failed for' + shahex)
        }
      } catch (error) {
        console.log('axios response', response)
        console.log('problem axios delete', error)
        throw error
      }
    } else if (this.savefile === 'openstackswift') {
      let response
      try {
        const path =
          '/v1/' + this.swiftaccount + '/' + this.swiftcontainer + '/' + shahex
        response = await axios.delete(this.swiftbaseurl + path, {
          headers: { 'X-Auth-Token': await this.openstackToken() }
        })
        if (response?.status !== 204) {
          console.log('axios response', response)
          throw new Error('delete failed for' + shahex)
        }
      } catch (error) {
        console.log('axios response', response)
        console.log('problem axios delete', error)
        throw error
      }
    } else {
      throw new Error('unimplemented delete assets:' + this.savefile)
    }
  }

  async shamkdirLocal(sha) {
    const shahex = sha.toString('hex')
    const dir =
      this.datadir + '/' + shahex.substr(0, 2) + '/' + shahex.substr(2, 4)
    await mkdir(dir, { recursive: true })
  }

  async readFileStream(sha, mime) {
    if (this.savefile === 'fs') {
      const filename = this.shatofilenameLocal(sha, mime)
      const fd = await open(filename)
      const stream = fd.createReadStream()
      return stream
    } else if (this.savefile === 's3') {
      const host = this.s3bucket + '.' + this.s3host
      const shahex = sha.toString('hex')
      const uri = '/' + shahex
      const path = 'https://' + host + uri
      const date = new Date()
      const headers = {
        Date: date.toUTCString(),
        Host: host,
        'x-amz-content-sha256': this.emptyhash
      }
      let response
      try {
        headers.Authorization = this.s3AuthHeader({
          headers,
          uri,
          verb: 'GET',
          date,
          hashedpayload: this.emptyhash
        })
        response = await axios.get(path, {
          headers,
          responseType: 'stream'
        })
        if (response?.status !== 200) {
          console.log('axios response', response)
          throw new Error('read failed for' + shahex)
        }
        // in the S3 case, mime is a callback
        if (response?.headers?.['content-type']) {
          mime(response?.headers?.['content-type'])
        } else throw new Error('no mime type from s3')
      } catch (error) {
        console.log('axios response', response)
        console.log('problem axios get', error)
        throw error
      }
      return response?.data
    } else if (this.savefile === 'openstackswift') {
      let response
      try {
        const shahex = sha.toString('hex')
        const path =
          '/v1/' + this.swiftaccount + '/' + this.swiftcontainer + '/' + shahex
        const config = {
          headers: {
            'X-Auth-Token': await this.openstackToken(),
            'Content-Type': mime
          },
          responseType: 'stream'
        }
        response = await axios.get(this.swiftbaseurl + path, config)
        if (response?.status !== 200) {
          console.log('axios response', response)
          throw new Error('read failed for' + shahex)
        }
      } catch (error) {
        console.log('axios response', response)
        console.log('problem axios get', error)
        throw error
      }
      return response?.data
    }
  }

  async saveFile(input, sha, mime, size) {
    // size is optional
    if (this.savefile === 'fs') {
      await this.shamkdirLocal(sha)
      const filename = this.shatofilenameLocal(sha, mime)

      await writeFile(filename, input)
    } else if (this.savefile === 's3') {
      const host = this.s3bucket + '.' + this.s3host
      const shahex = sha.toString('hex')
      const uri = '/' + shahex
      const path = 'https://' + host + uri
      const date = new Date()
      const length = input?.length || size
      const headers = {
        'Content-Length': String(length),
        'Content-Type': mime,
        Date: date.toUTCString(),
        Host: host,
        'x-amz-content-sha256': shahex
      }
      let response
      try {
        headers.Authorization = this.s3AuthHeader({
          headers,
          uri,
          verb: 'PUT',
          date,
          hashedpayload: shahex
        })
        response = await axios.put(path, input, {
          headers
        })
        if (response?.status !== 200) {
          console.log('axios response', response)
          throw new Error('save failed for' + shahex)
        }
      } catch (error) {
        console.log('axios response', response)
        console.log('problem axios save', error)
        throw error
      }
    } else if (this.savefile === 'openstackswift') {
      let response
      try {
        const shahex = sha.toString('hex')
        const path =
          '/v1/' + this.swiftaccount + '/' + this.swiftcontainer + '/' + shahex
        const config = {
          headers: {
            'X-Auth-Token': await this.openstackToken(),
            'Content-Type': mime
          }
        }
        response = await axios.put(this.swiftbaseurl + path, input, config)
        if (response?.status !== 201) {
          console.log('axios response', response)
          throw new Error('save failed for' + shahex)
        }
      } catch (error) {
        console.log('axios response', response)
        console.log('problem axios save', error)
        throw error
      }
    } else throw new Error('unsupported savefile method ' + this.savefile)
  }

  async saveFileStream(inputStream, mime, size) {
    const filehash = createHash('sha256')

    const digest = {}
    digest.promise = new Promise((resolve, reject) => {
      digest.resolve = resolve
      digest.reject = reject
    })
    let lengthCount = 0
    const hashstream = new Transform({
      transform(data, encoding, callback) {
        filehash.update(data)
        lengthCount += data.length
        if (lengthCount > size) {
          callback(
            new Error(
              'Specified length is exceeded in incoming request exceeding:' +
                size
            )
          )
        } else {
          callback(null, data)
        }
      },
      flush(callback) {
        digest.resolve(filehash.digest())
        callback()
      }
    })

    const outputstream = inputStream.pipe(hashstream)

    // size is optional
    if (this.savefile === 'fs') {
      await this.tempmkdirLocal()
      const tempFileName = this.tempFileLocal()
      const fh = await open(tempFileName, 'w')
      const writeStream = fh.createWriteStream()

      outputstream.pipe(writeStream)
      await finished(writeStream)
      writeStream.end()
      await fh.close()

      const sha = await digest.promise
      await this.shamkdirLocal(sha)
      const filename = this.shatofilenameLocal(sha, mime)
      await rename(tempFileName, filename)
    } else if (this.savefile === 's3') {
      const host = this.s3bucket + '.' + this.s3host
      // first step upload file
      const uuid = randomUUID()
      const tempUri = '/temp-' + uuid
      const tempPath = 'https://' + host + tempUri
      let response
      try {
        const date = new Date()
        const length = size
        const unsignedHash = 'UNSIGNED-PAYLOAD'
        const headers = {
          'Content-Length': String(length),
          'Content-Type': mime,
          Date: date.toUTCString(),
          Host: host,
          'x-amz-content-sha256': unsignedHash
        }

        headers.Authorization = this.s3AuthHeader({
          headers,
          uri: tempUri,
          verb: 'PUT',
          date,
          hashedpayload: unsignedHash
        })
        response = await axios.put(tempPath, outputstream, {
          headers
        })
        if (response?.status !== 200) {
          console.log('axios response', response)
          throw new Error('save failed for temp upload')
        }
      } catch (error) {
        console.log('axios response #1', response)
        console.log('problem axios save #1', error)
        throw error
      }
      response = undefined // clear the response
      const sha = await digest.promise
      // second step copy file
      const shahex = sha.toString('hex')
      const shaUri = '/' + shahex
      const shaPath = 'https://' + host + shaUri
      try {
        const date = new Date()
        const headers = {
          /* 'Content-Length': String(length), 
          'Content-Type': mime, */
          Date: date.toUTCString(),
          Host: host,
          'x-amz-copy-source': this.s3bucket + tempUri,
          'x-amz-content-sha256': this.emptyhash
        }

        headers.Authorization = this.s3AuthHeader({
          headers,
          uri: shaUri,
          verb: 'PUT',
          date,
          hashedpayload: this.emptyhash
        })
        response = await axios.put(shaPath, {
          headers
        })
        if (response?.status !== 200) {
          console.log('axios response', response)
          throw new Error('save copy failed for' + shahex)
        }
      } catch (error) {
        console.log('axios response #2', response)
        console.log('problem axios save #2', error)
        throw error
      }
      response = undefined // clear the response
      // third step remove temp file
      try {
        const date = new Date()
        const headers = {
          Date: date.toUTCString(),
          Host: host,
          'x-amz-content-sha256': this.emptyhash
        }

        headers.Authorization = this.s3AuthHeader({
          headers,
          uri: tempUri,
          verb: 'DELETE',
          date,
          hashedpayload: this.emptyhash
        })
        response = await axios.delete(tempPath, {
          headers
        })
        if (response?.status !== 204) {
          console.log('axios response', response)
          throw new Error('save failed for' + shahex)
        }
      } catch (error) {
        console.log('axios response #3', response)
        console.log('problem axios save #3', error)
        throw error
      }
    } else if (this.savefile === 'openstackswift') {
      let response
      // upload temp file
      const uuid = randomUUID()
      const tempPath =
        '/v1/' + this.swiftaccount + '/' + this.swiftcontainer + '/temp-' + uuid
      try {
        const config = {
          headers: {
            'X-Auth-Token': await this.openstackToken(),
            'Content-Type': mime
          }
        }
        response = await axios.put(
          this.swiftbaseurl + tempPath,
          outputstream,
          config
        )
        if (response?.status !== 201) {
          console.log('axios response', response)
          throw new Error('save failed for temp upload ' + uuid)
        }
      } catch (error) {
        console.log('axios response to problem', response)
        console.log('problem axios save #1 ', error)
        throw error
      }
      const sha = await digest.promise

      const shahex = sha.toString('hex')
      // const shaPath =
      //  '/v1/' + this.swiftaccount + '/' + this.swiftcontainer + '/' + shahex

      // copy temp file to final file
      try {
        const config = {
          headers: {
            'X-Auth-Token': await this.openstackToken(),
            Destination: this.swiftcontainer + '/' + shahex,
            'Content-Type': mime
          },
          method: 'COPY',
          url: this.swiftbaseurl + tempPath
        }
        response = await axios(config)
        if (response?.status !== 201) {
          console.log('axios response to problem', response)
          throw new Error('copy failed for' + shahex)
        }
      } catch (error) {
        console.log('axios response to problem', response)
        console.log('problem axios save #2', error)
        throw error
      }

      // delete temp file
      try {
        const config = {
          headers: {
            'X-Auth-Token': await this.openstackToken()
          }
        }
        response = await axios.delete(this.swiftbaseurl + tempPath, config)
        if (response?.status !== 204) {
          console.log('axios response', response)
          throw new Error('save failed for' + shahex + 'at delete operation')
        }
      } catch (error) {
        console.log('axios response', response)
        console.log('problem axios save #3', error)
        throw error
      }
    } else throw new Error('unsupported savefile method ' + this.savefile)
    return { sha256: await digest.promise }
  }

  mimeToExtension(mime) {
    switch (mime) {
      case 'application/pdf':
        return '.pdf'
      case 'image/jpeg':
        return '.jpg'
      case 'image/png':
        return '.png'
      case 'image/gif':
        return '.gif'
      default:
        return ''
    }
  }

  mimeToExtensionwoDot(mime) {
    switch (mime) {
      case 'application/pdf':
        return 'pdf'
      case 'image/jpeg':
        return 'jpg'
      case 'image/png':
        return 'png'
      case 'image/gif':
        return 'gif'
      default:
        return ''
    }
  }

  extensionToMime(ext) {
    switch (ext) {
      case 'pdf':
        return 'application/pdf'
      case 'jpg':
        return 'image/jpeg'
      case 'png':
        return 'image/png'
      case 'gif':
        return 'image/gif'
      default:
        return ''
    }
  }
}
