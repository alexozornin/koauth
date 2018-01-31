# koauth

koauth экспортирует класс, предназначенный для аутентификации и проверки пользователей в koa.


## Подключение koauth:

```javascript
const Koauth = require('koauth');
```

Создание экземпляра класса Koauth включает подключение к приложению koa модулей koa-session, koa-passport, passport-local.

Конструктор koauth принимает аргументы:

koa_app - рабочий экземкляр класса Koa (приложение koa)

app_keys - ключи приложения koa

session options - опции модуля koa-session (key, maxAge, overwrite, httpOnly, signed, rolling, renew)

async_get_user_by_id_function - асинхронная функция получения пользоватея по id, входные данные: { id }, выходные данные { id, username, password, level }.

async_check_user_function - асинхронная функция проверки пользователя, входные данные: { username, password }, выходные данные { id, username, password, level } при совпадении пароля или null при несовпадении.

Пример конструктора:
```javascript
const koauth = new Koauth(app, ['secret'], { key: 'my_app' }, getuser, checkuser);
```

## Функционал koauth:

Аутентификация пользователя:

```javascript
async authenticate(ctx)
```

ctx.request.body должно содержать поля username, password.

В случае успешной аутентификации пользователя, будет создана его сессия. Состояние аутентификации можно проверить в контексте запроса

```javascript
ctx.isAuthenticated()
```

Выход пользователя:

```javascript
async logout(ctx)
```

Проверка пользователя:

```javascript
async check(ctx, level)
```

level - уровень прав пользователя, необходимый для совершения действия. Чем ниже значение level, тем выше уровень прав. Аргумент level не является обязательным (он может не использоваться или иметь значения undefined / null).

В случае, если level не используется, проверка будет успешна для любого авторизованного пользователя. При использовании level проверка будет успешна только для пользователей с достаточным уровнем прав.

Результат для успешной проверки: { access: true, id: id }, результат для неавторизованного пользователя: { access: false, id: null }, результат при недостаточном уровне прав: { access: false, id: id, user_level: +user.level }.

## События

Класс Koauth издает ряд событий с одним аргументом или без них.

'error' происходит при ошибке и содержит информацию об ошибке

'auth-success' происходит при успешной аутентификации пользователя и содержит объект с информацией о пользователе

'auth-fail' происходит при ошибке аутентификации и содержит объект ctx.request.body

'logout' происходит при выходе пользователя и не имеет аргументов

'access-grant' происходит при успешной проверке пользователя и предоставлении доступа, содержит объект { id, method, path }

'access-deny' происходит в случае отказа в доступе пользователю и содержит объект { id, reason_id, reason, method, path }, reason_id - идентификатор причины отказа (1 - пользователь не авторизован, 2 - недостаточно прав)

## Пример работы с koauth

Инициализация модуля:

```javascript
const fs = require('fs');
const path = require('path');
const db = require('./fakedbwrap.js');
const Koauth = require('koauth');

const Koa = require('koa');
const app = new Koa();
app.proxy = true;

const bodyparser = require('koa-bodyparser');
app.use(bodyparser());

const koauth = new Koauth(app, ['secret'], { key: 'tst' }, db.getuser, db.check);

koauth.on('error', function (err)
{
    console.log('error', err);
})

koauth.on('auth-success', function (user)
{
    console.log('auth', user);
})

koauth.on('auth-fail', function (data)
{
    console.log('auth-fail', data);
})

koauth.on('access-deny', function (data)
{
    console.log('access-deny', data);
})
```

Работа с модулем:

```javascript
app.use(route.get('/login', function (ctx)
{
    ctx.type = 'html';
    ctx.body = fs.createReadStream(path.join(__dirname, "static", "login", "index.html"));
}))

app.use(route.post('/login', async function (ctx)
{
    console.log(ctx.request.body);
    await koauth.authenticate(ctx);
    if (ctx.isAuthenticated())
    {
        ctx.redirect('/');
        return;
    }
    ctx.redirect('/login');
}))

app.use(route.get('/', function (ctx)
{
    ctx.type = 'html';
    ctx.body = fs.createReadStream(path.join(__dirname, "static", "index.html"));
}))

app.use(route.get('/topsecret', async function (ctx)
{
    let res = await koauth.check(ctx, 0);
    if(!res.access)
    {
        ctx.redirect('/');
        return;
    }
    ctx.body = 'top secret';
}))

app.use(route.get('/bottomsecret', async function (ctx)
{
    let res = await koauth.check(ctx);
    if(!res.access)
    {
        ctx.redirect('/');
        return;
    }
    ctx.body = 'bottom secret';
}))
```
