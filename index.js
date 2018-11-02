'use strict'

const fs = require('fs');
const afs = require('alex-async-fs');
const path = require('path');
const crypto = require('crypto');

function cipher(key32, key16, input, format)
{
    let sha256 = crypto.createHash('sha256');
    sha256.update(key32);
    let keyBuffer = Buffer.from(sha256.digest('latin1'), 'latin1');
    let md5 = crypto.createHash('md5').update(key16).digest('latin1');
    let ivBuffer = Buffer.from(md5, 'latin1')
    let caes = crypto.createCipheriv('aes-256-cbc', keyBuffer, ivBuffer);
    let result = caes.update(input, 'utf8', format);
    return result + caes.final(format);
}

function decipher(key32, key16, input, format)
{
    let sha256 = crypto.createHash('sha256').update(key32).digest('latin1');
    let keyBuffer = Buffer.from(sha256, 'latin1');
    let md5 = crypto.createHash('md5').update(key16).digest('latin1');
    let ivBuffer = Buffer.from(md5, 'latin1')
    let daes = crypto.createDecipheriv('aes-256-cbc', keyBuffer, ivBuffer);
    let result = daes.update(input, format, 'utf8');
    return result + daes.final('utf8');
}

async function getSession(dir, userId)
{
    let data = await afs.readFileAsync(path.join(dir, '' + userId), { encoding: 'utf8' });
    let parts = data.split(':');
    if (parts.length != 2)
    {
        console.log('RETARD ALERT', data);
    }
    return {
        key: parts[0],
        expires: parts[1]
    }
}

async function setSession(dir, userId, key, expires)
{
    let data = '' + key + ':' + expires;
    await afs.writeFileAsync(path.join(dir, '' + userId), data, { encoding: 'utf8' });
}

async function removeSession(dir, userId)
{
    await afs.unlinkAsync(path.join(dir, '' + userId));
}

class Koauth
{
    constructor(getUserById, signInUser, signOutUser, sessionDirPath, options = {})
    {
        if (typeof options != 'object')
        {
            options = {};
        }
        this._private = {};
        this._private.getUserById = getUserById;
        this._private.signInUser = signInUser;
        this._private.signOutUser = signOutUser;
        this._private.sessionDirPath = sessionDirPath;
        this._private.options = options;
        if (!this._private.options.tokenName)
        {
            this._private.options.tokenName = 'auth';
        }
        if (!this._private.options.mode)
        {
            this._private.options.mode = 'cookie';
        }
        if (!this._private.options.header)
        {
            this._private.options.header = 'Authorization';
        }
        if (!this._private.options.maxAge)
        {
            this._private.options.maxAge = 86400000;
        }
        if (!this._private.options.autoUpdate)
        {
            this._private.options.autoUpdate = true;
        }
        if (!this._private.options.autoUpdateTimeout)
        {
            this._private.options.autoUpdateTimeout = 43200000;
        }
        if (!this._private.options.format)
        {
            this._private.options.format = 'base64';
        }
        if (!this._private.options.key32)
        {
            this._private.options.key32 = '' + Math.random();
        }
        if (!this._private.options.key16)
        {
            this._private.options.key16 = '' + Math.random();
        }
        switch (this._private.options.mode)
        {
            case 'cookie':
                this._private.getToken = (ctx) =>
                {
                    return ctx.cookies.get(this._private.options.tokenName);
                }
                this._private.setToken = (ctx, token) =>
                {
                    ctx.cookies.set(this._private.options.tokenName, token, { overwrite: true, httpOnly: true, maxAge: this._private.options.maxAge });
                }
                break;
            case 'header':
                this._private.getToken = (ctx) =>
                {
                    return ctx.headers[this._private.options.header];
                }
                this._private.setToken = () => { }
                break;
            default:
                throw new Error('Invalid mode');
        }
    }

    async signIn(ctx, ...params)
    {
        let user = this._private.signInUser(ctx, ...params);
        if (user instanceof Promise)
        {
            user = await user;
        }
        if (!user)
        {
            return null;
        }
        let key = crypto.createHash('sha256').update('' + Math.random()).digest('base64');
        let expires = Date.now() + (this._private.options.maxAge);
        await setSession(this._private.sessionDirPath, user, key, expires)
        let token = {
            user,
            key
        }
        let ctoken = cipher(this._private.options.key32, this._private.options.key16, JSON.stringify(token), this._private.options.format);
        this._private.setToken(ctx, ctoken);
        return ctoken;
    }

    async signOut(ctx, ...params)
    {
        let result = this._private.signOutUser(ctx, ...params);
        if (result instanceof Promise)
        {
            await result;
        }
        let ctoken = this._private.getToken(ctx);
        if (!ctoken)
        {
            return;
        }
        let token = null;
        try
        {
            token = JSON.parse(decipher(this._private.options.key32, this._private.options.key16, ctoken, this._private.options.format));
        }
        catch (err)
        {
            return;
        }
        if (!token)
        {
            return;
        }
        await removeSession(this._private.sessionDirPath, token.user)
        this._private.setToken(ctx, '');
    }

    async updateSession(ctx)
    {
        let ctoken = this._private.getToken(ctx);
        if (!ctoken)
        {
            return null;
        }
        let token = null;
        try
        {
            token = JSON.parse(decipher(this._private.options.key32, this._private.options.key16, ctoken, this._private.options.format));
        }
        catch (err)
        {
            return null;
        }
        if (!token)
        {
            return null;
        }
        let key = crypto.createHash('sha256').update('' + Math.random()).digest('base64');
        let expires = Date.now() + (this._private.options.maxAge);
        await setSession(this._private.sessionDirPath, token.user, key, expires);
        token = {
            user,
            key
        }
        ctoken = cipher(this._private.options.key32, this._private.options.key16, JSON.stringify(token), this._private.options.format);
        this._private.setToken(ctx, ctoken);
        return ctoken;
    }

    async forceSessionRemove(userId)
    {
        if (await afs.existsAsync(path.join(this._private.sessionDirPath, '' + userId)))
        {
            await afs.unlinkAsync(path.join(this._private.sessionDirPath, '' + userId));
        }
    }

    async getUser(ctx)
    {
        let ctoken = this._private.getToken(ctx);
        if (!ctoken)
        {
            return null;
        }
        let token = null;
        try
        {
            token = JSON.parse(decipher(this._private.options.key32, this._private.options.key16, ctoken, this._private.options.format));
        }
        catch (err)
        {
            return null;
        }
        if (!token || !token.user || !token.key)
        {
            return null;
        }
        let now = Date.now();
        let session = await getSession(this._private.sessionDirPath, token.user);
        if (now > session.expires || now < session.expires - this._private.options.maxAge)
        {
            return null;
        }
        let result = this._private.getUserById(token.user);
        if (result instanceof Promise)
        {
            result = await result;
        }
        if (this._private.options.autoUpdate)
        {
            console.log('checkinf for update');
            if (now > session.expires - this._private.options.maxAge + this._private.options.autoUpdateTimeout)
            {
                console.log('updating')
                let user = token.user;
                let key = crypto.createHash('sha256').update('' + Math.random()).digest('base64');
                let expires = Date.now() + (this._private.options.maxAge);
                await setSession(this._private.sessionDirPath, user, key, expires);
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

    async freeSessions()
    {
        let files = await afs.readDirAsync(this._private.sessionDirPath);
        let now = Date.now();
        for (let i in files)
        {
            let data = await afs.readFileAsync(path.join(this._private.sessionDirPath, files[i]));
            let parts = data.split(':');
            if (!parts[1] || now > parts[1])
            {
                await afs.unlinkAsync(path.join(this._private.sessionDirPath, files[i]));
            }
        }
    }
}

module.exports = Koauth;

// let text = 'abcdefghijkladfggbakjggbntkjbnkjbgiurshgurghgudrghughsoihgtoidgthsithmn';
// console.log(text);
// let ctext = cipher('12345', '123', text, 'latin1');
// console.log(ctext);
// let dtext = decipher('12345', '123', ctext, 'latin1');
// console.log(dtext);
