'use strict'

const EventEmitter = require('events');
const Koa = require('koa');

class Koauth extends EventEmitter
{
    constructor(koa_app, app_keys, session_options, async_get_user_by_id_function, async_check_user_function)
    {
        super();

        this.get_user = async_get_user_by_id_function;
        this.check_user = async_check_user_function;

        this.app = koa_app;

        this.session = require('koa-session');
        this.app.keys = app_keys;
        this.app.use(this.session(session_options, this.app));

        this.passport = require('koa-passport');

        this.passport.serializeUser(async function (user, done)
        {
            done(null, user.id);
        })

        this.passport.deserializeUser(async function (id, done)
        {
            try
            {
                const user = await async_get_user_by_id_function({ id: id });
                // console.log('func:', async_get_user_by_id_function);
                // console.log('id:', id);
                // console.log('user:', user);
                done(null, user);
            }
            catch (err)
            {
                done(err);
            }
        })

        this.LocalStrategy = require('passport-local').Strategy;

        this.passport.use(new this.LocalStrategy(async function (username, password, done)
        {
            try
            {
                let res = await async_check_user_function({ username: username, password: password });
                if (res)
                {
                    done(null, res);
                }
                else
                {
                    done(null, false);
                }
            }
            catch (err)
            {
                done(err);
            }
        }))

        this.app.use(this.passport.initialize());
        this.app.use(this.passport.session());
    }

    async authenticate(ctx)
    {
        let self = this;
        return this.passport.authenticate('local', function (err, user, info, status)
        {
            if (err)
            {
                self.emit('error', err);
                return;
            }
            if (user)
            {
                self.emit('auth-success', user);
                return ctx.login(user, {});
            }
            self.emit('auth-fail', ctx.request.body);
            return;
        })(ctx);
    }

    async logout(ctx)
    {
        let self = this;
        ctx.session = null;
        ctx.logout();
        self.emit('logout');
        return;
    }

    async check(ctx, level)
    {
        let self = this;
        return new Promise(async (resolve, reject) =>
        {
            try
            {
                if (!ctx.isAuthenticated())
                {
                    resolve({ access: false, id: null });
                    self.emit('access-deny', { id: null, reason_id: 1, reason: 'No authorization', method: ctx.method, path: ctx.path });
                    return;
                }
                let id = ctx.session.passport.user;
                if (level === undefined || level === null)
                {
                    resolve({ access: true, id: id });
                    self.emit('access-grant', { id: id, method: ctx.method, path: ctx.path });
                    return;
                }
                let user = await self.get_user({ id: ctx.session.passport.user });
                if (!user || user.level === undefined || user.level === null || user.level === false)
                {
                    reject('async_get_user_by_id_function returned no valid result');
                    self.emit('error', 'async_get_user_by_id_function returned no valid result');
                    return;
                }
                if (+user.level <= +level)
                {
                    resolve({ access: true, id: id });
                    self.emit('access-grant', { id: id, method: ctx.method, path: ctx.path });
                    return;
                }
                resolve({ access: false, id: id, user_level: +user.level });
                self.emit('access-deny', { id: id, reason_id: 2, reason: 'Not enough rights', method: ctx.method, path: ctx.path });
                return;
            }
            catch (err)
            {
                reject(err);
                return;
            }
        })
    }
}

module.exports = Koauth;
