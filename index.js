'use strict'

const afs = require('alex-async-fs');
const path = require('path');
const crypto = require('crypto');

function cipher(key32, key16, input, format) {
    let sha256 = crypto.createHash('sha256');
    sha256.update(key32);
    let keyBuffer = Buffer.from(sha256.digest('latin1'), 'latin1');
    let md5 = crypto.createHash('md5').update(key16).digest('latin1');
    let ivBuffer = Buffer.from(md5, 'latin1')
    let caes = crypto.createCipheriv('aes-256-cbc', keyBuffer, ivBuffer);
    let result = caes.update(input, 'utf8', format);
    return result + caes.final(format);
}

function decipher(key32, key16, input, format) {
    let sha256 = crypto.createHash('sha256').update(key32).digest('latin1');
    let keyBuffer = Buffer.from(sha256, 'latin1');
    let md5 = crypto.createHash('md5').update(key16).digest('latin1');
    let ivBuffer = Buffer.from(md5, 'latin1')
    let daes = crypto.createDecipheriv('aes-256-cbc', keyBuffer, ivBuffer);
    let result = daes.update(input, format, 'utf8');
    return result + daes.final('utf8');
}

class Koauth {
    /**
     * Creates an instance of Koauth.
     * @param {Function} getUserById
     * @param {Function} signInUser
     * @param {Function} signOutUser
     * @param {Object} options
     * @param {String} options.tokenName
     * @param {'cookie' | 'header'} options.mode
     * @param {String} options.header
     * @param {'fs' | 'custom'} options.sessionStorage
     * @param {String} options.sessionDirPath
     * @param {Function} options.getSessionByUserId
     * @param {Function} options.setSessionByUserId
     * @param {Function} options.removeSessionByUserId
     * @param {Number} options.maxAge
     * @param {Boolean} options.autoUpdate
     * @param {Number} options.autoUpdateTimeout
     * @param {'hex' | 'base64'} options.format
     * @param {String} options.key32
     * @param {String} options.key16
     */
    constructor(getUserById, signInUser, signOutUser, options = {}) {
        if (typeof options != 'object') {
            options = {};
        }
        this._private = {};
        this._private.getUserById = getUserById;
        this._private.signInUser = signInUser;
        this._private.signOutUser = signOutUser;
        this._private.options = options;
        if (!this._private.options.tokenName) {
            this._private.options.tokenName = 'auth';
        }
        if (!this._private.options.mode) {
            this._private.options.mode = 'cookie';
        }
        if (!this._private.options.allowMultipleSessions) {
            this._private.options.allowMultipleSessions = false;
        }
        if (!this._private.options.header) {
            this._private.options.header = 'Authorization';
        }
        if (!this._private.options.sessionStorage) {
            this._private.options.sessionStorage = 'fs';
        }
        if (!this._private.options.sessionDirPath) {
            this._private.options.sessionDirPath = path.join(__dirname, 'sessions');
        }
        if (!this._private.options.getSessionByUserId) {
            this._private.options.getSessionByUserId = () => { };
        }
        if (!this._private.options.setSessionByUserId) {
            this._private.options.setSessionByUserId = () => { };
        }
        if (!this._private.options.removeSessionTokenByUserId) {
            this._private.options.removeSessionTokenByUserId = () => { };
        }
        if (!this._private.options.maxAge) {
            this._private.options.maxAge = 86400000;
        }
        if (!this._private.options.autoUpdate) {
            this._private.options.autoUpdate = true;
        }
        if (!this._private.options.autoUpdateTimeout) {
            this._private.options.autoUpdateTimeout = 43200000;
        }
        if (!this._private.options.format) {
            this._private.options.format = 'base64';
        }
        if (!this._private.options.key32) {
            this._private.options.key32 = '' + Math.random();
        }
        if (!this._private.options.key16) {
            this._private.options.key16 = '' + Math.random();
        }
        switch (this._private.options.mode) {
            case 'cookie':
                this._private.getToken = (ctx) => {
                    return ctx.cookies.get(this._private.options.tokenName);
                }
                this._private.setToken = (ctx, token) => {
                    ctx.cookies.set(this._private.options.tokenName, token, { overwrite: true, httpOnly: true, maxAge: this._private.options.maxAge });
                }
                break;
            case 'header':
                this._private.getToken = (ctx) => {
                    return ctx.headers[this._private.options.header];
                }
                this._private.setToken = () => { }
                break;
            default:
                throw new Error('Invalid mode');
        }
        switch (this._private.options.sessionStorage) {
            case 'fs':
                this._private.getSessionToken = async (userId, dir) => {
                    let data = await afs.readFileAsync(path.join(dir, '' + userId), { encoding: 'utf8' });
                    let parts = data.split(':');
                    if (parts.length != 2) {
                        return null;
                    }
                    return {
                        key: parts[0],
                        expires: parts[1]
                    }
                }
                this._private.setSessionToken = async (userId, key, expires, dir) => {
                    let data = '' + key + ':' + expires;
                    await afs.writeFileAsync(path.join(dir, '' + userId), data, { encoding: 'utf8' });
                }
                this._private.removeSessionToken = async (userId, dir) => {
                    if (await afs.existsAsync(path.join(dir, '' + userId))) {
                        await afs.unlinkAsync(path.join(dir, '' + userId));
                    }
                }
                break;
            case 'custom':
                this._private.getSessionToken = async (userId) => {
                    let res = this._private.options.getSessionByUserId(userId);
                    if (res instanceof Promise) {
                        res = await res;
                    }
                    if (!res) {
                        return null;
                    }
                    let parts = res.split(':');
                    if (parts.length != 2) {
                        return null;
                    }
                    return {
                        key: parts[0],
                        expires: parts[1]
                    }
                }
                this._private.setSessionToken = async (userId, key, expires) => {
                    let session = '' + key + ':' + expires;
                    let res = this._private.options.setSessionByUserId(userId, session);
                    if (res instanceof Promise) {
                        res = await res;
                    }
                    return res;
                }
                this._private.removeSessionToken = async (userId) => {
                    let res = this._private.options.removeSessionTokenByUserId(userId);
                    if (res instanceof Promise) {
                        res = await res;
                    }
                    return res;
                }
                break;
            default:
                throw new Error('Invalid session storage');
        }
    }

    /**
     * Signs in user.
     * @param {Object} ctx - Koa context
     * @param  {...any} params
     */
    async signIn(ctx, ...params) {
        let userId = this._private.signInUser(ctx, ...params);
        if (userId instanceof Promise) {
            userId = await userId;
        }
        if (!userId) {
            return null;
        }
        let key = '';
        if (this._private.options.allowMultipleSessions) {
            let session = await this._private.getSessionToken(userId, this._private.options.sessionDirPath);
            if (session && session.key) {
                key = session.key;
            }
            else {
                key = crypto.createHash('sha256').update('' + Math.random()).digest('base64');
            }
        }
        else {
            key = crypto.createHash('sha256').update('' + Math.random()).digest('base64');
        }
        let expires = Date.now() + (this._private.options.maxAge);
        await this._private.setSessionToken(userId, key, expires, this._private.options.sessionDirPath)
        let token = {
            user: userId,
            key
        }
        let ctoken = cipher(this._private.options.key32, this._private.options.key16, JSON.stringify(token), this._private.options.format);
        this._private.setToken(ctx, ctoken);
        return {
            user: userId,
            token: ctoken
        };
    }

    /**
     * Signs out user.
     * @param {Object} ctx - Koa context
     * @param  {...any} params
     */
    async signOut(ctx, ...params) {
        let result = this._private.signOutUser(ctx, ...params);
        if (result instanceof Promise) {
            await result;
        }
        let ctoken = this._private.getToken(ctx);
        if (!ctoken) {
            return;
        }
        let token = null;
        try {
            token = JSON.parse(decipher(this._private.options.key32, this._private.options.key16, ctoken, this._private.options.format));
        }
        catch (err) {
            return;
        }
        if (!token) {
            return;
        }
        this._private.setToken(ctx, '');
        if (!this._private.options.allowMultipleSessions) {
            await this._private.removeSessionToken(token.user, this._private.options.sessionDirPath);
        }
    }

    /**
     * Updates user session.
     * @param {Object} ctx - Koa context
     */
    async updateSession(ctx) {
        let ctoken = this._private.getToken(ctx);
        if (!ctoken) {
            return null;
        }
        let token = null;
        try {
            token = JSON.parse(decipher(this._private.options.key32, this._private.options.key16, ctoken, this._private.options.format));
        }
        catch (err) {
            return null;
        }
        if (!token) {
            return null;
        }
        let key = '';
        if (this._private.options.allowMultipleSessions) {
            let session = await this._private.getSessionToken(token.user, this._private.options.sessionDirPath);
            if (session && session.key) {
                key = session.key;
            }
            else {
                key = crypto.createHash('sha256').update('' + Math.random()).digest('base64');
            }
        }
        else {
            key = crypto.createHash('sha256').update('' + Math.random()).digest('base64');
        }
        let expires = Date.now() + (this._private.options.maxAge);
        await this._private.setSessionToken(token.user, key, expires, this._private.options.sessionDirPath);
        token = {
            user: token.user,
            key
        }
        ctoken = cipher(this._private.options.key32, this._private.options.key16, JSON.stringify(token), this._private.options.format);
        this._private.setToken(ctx, ctoken);
        return ctoken;
    }

    /**
     * Remove user session from server.
     * @param {Number} userId
     */
    async forceSessionRemove(userId) {
        await this._private.removeSessionToken(userId, this._private.options.sessionDirPath);
    }

    /**
     * Get user from client session.
     * @param {Object} ctx - Koa context
     */
    async getUser(ctx) {
        let ctoken = this._private.getToken(ctx);
        if (!ctoken) {
            return null;
        }
        let token = null;
        try {
            token = JSON.parse(decipher(this._private.options.key32, this._private.options.key16, ctoken, this._private.options.format));
        }
        catch (err) {
            return null;
        }
        if (!token || !token.user || !token.key) {
            return null;
        }
        let now = Date.now();
        let session = await this._private.getSessionToken(token.user, this._private.options.sessionDirPath);
        if (!session || now > session.expires || now < session.expires - this._private.options.maxAge || token.key != session.key) {
            return null;
        }
        let result = this._private.getUserById(token.user);
        if (result instanceof Promise) {
            result = await result;
        }
        if (this._private.options.autoUpdate) {
            if (now > session.expires - this._private.options.maxAge + this._private.options.autoUpdateTimeout) {
                let user = token.user;
                let key = crypto.createHash('sha256').update('' + Math.random()).digest('base64');
                let expires = Date.now() + (this._private.options.maxAge);
                await this._private.setSessionToken(user, key, expires, this._private.options.sessionDirPath);
                token = {
                    user,
                    key
                }
                ctoken = cipher(this._private.options.key32, this._private.options.key16, JSON.stringify(token), this._private.options.format);
                this._private.setToken(ctx, ctoken);
            }
        }
        return result;
    }

    /**
     * Free disk space from old sessions.
     */
    async freeSessions() {
        let files = await afs.readDirAsync(this._private.options.sessionDirPath);
        let now = Date.now();
        for (let i in files) {
            let data = await afs.readFileAsync(path.join(this._private.options.sessionDirPath, files[i]));
            let parts = data.split(':');
            if (!parts[1] || now > parts[1]) {
                await afs.unlinkAsync(path.join(this._private.options.sessionDirPath, files[i]));
            }
        }
    }
}

module.exports = Koauth;

