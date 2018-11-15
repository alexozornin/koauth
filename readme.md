# koauth 2

koauth экспортирует класс, предназначенный для аутентификации пользователей и работы с сессиями в koa.


## Подключение koauth:

```javascript
const Koauth = require('koauth');
```

## Api

### Конструктор koauth принимает аргументы:

<table>
    <tr style="font-weight:bold">
        <td>Аргумент</td>
        <td>Тип данных</td>
        <td>Описание</td>
    </tr>
    <tr>
        <td>getUserById</td>
        <td>function</td>
        <td>Синхронная или асинхронная функция, получающая информацию о пользователе по его идентификатору.</td>
    </tr>
    <tr>
        <td>signInUser</td>
        <td>function</td>
        <td>Синхронная или асинхронная функция, выполняющаяся при аутентификации и возвращающая идентификатор пользователя при успешной аутентификации или null в противном случае.</td>
    </tr>
    <tr>
        <td>signOutUser</td>
        <td>function</td>
        <td>Синхронная или асинхронная функция, выполняющаяся при выходе пользователя, может не возвращать значение.</td>
    </tr>
    <tr>
        <td>options</td>
        <td>object</td>
        <td>Набор необязательных опций.</td>
    </tr>
</table>

### Опции

<table>
    <tr style="font-weight:bold">
        <td>Опция</td>
        <td>Тип данных</td>
        <td>Значение по умолчанию</td>
        <td>Описание</td>
    </tr>
    <tr>
        <td>tokenName</td>
        <td>string</td>
        <td>'auth'</td>
        <td>Название токена.</td>
    </tr>
    <tr>
        <td>mode</td>
        <td>string</td>
        <td>'cookie'</td>
        <td>Режим работы: 'cookie' | 'header'. Режим 'cookie' использует cookie для хранения токена сессии, он полностью автоматический и не требует дополнительного функционала. Режим 'header' предназначен для передачи токена в качестве HTTP-заголовка, при этом токен необходимо передать клиенту вручную.</td>
    </tr>
    <tr>
        <td>header</td>
        <td>string</td>
        <td>'Authorization'</td>
        <td>Название HTTP-заголовка при использовании режима 'header'.</td>
    </tr>
    <tr>
        <td>sessionStorage</td>
        <td>string</td>
        <td>'fs'</td>
        <td>Тип хранения сессий: 'fs' | 'custom'. Тип 'fs' - хранение в файловой системе, 'custom' - собственная реализация.</td>
    </tr>
    <tr>
        <td>sessionDirPath</td>
        <td>string</td>
        <td>''</td>
        <td>Путь до директории для хранения сессий при типе хранения 'fs'.</td>
    </tr>
    <tr>
        <td>getSessionByUserId</td>
        <td>function</td>
        <td>() => { }</td>
        <td>Синхронная или асинхронная функция, получающая сессию пользователя по его идентификатору при типе хранения 'custom'.</td>
    </tr>
    <tr>
        <td>setSessionByUserId</td>
        <td>function</td>
        <td>() => { }</td>
        <td>Синхронная или асинхронная функция, задающая сессию пользователя по его идентификатору при типе хранения 'custom'.</td>
    </tr>
    <tr>
        <td>maxAge</td>
        <td>number</td>
        <td>86400000</td>
        <td>Максимальное время жизни сессии в милисекундах.</td>
    </tr>
    <tr>
        <td>autoUpdate</td>
        <td>boolean</td>
        <td>true</td>
        <td>Необходимо ли автоматически обновлять сессию.</td>
    </tr>
    <tr>
        <td>autoUpdateTimeout</td>
        <td>number</td>
        <td>43200000</td>
        <td>Время перед автоматическим обновлением сессии в милисекундах.</td>
    </tr>
    <tr>
        <td>format</td>
        <td>string</td>
        <td>'base64'</td>
        <td>Формат данных токена 'hex' | 'base64'.</td>
    </tr>
    <tr>
        <td>key32</td>
        <td>string</td>
        <td>[random]</td>
        <td>Первый ключ шифрования токена. Максимально эффективный размер - 32 байта.</td>
    </tr>
    <tr>
        <td>key16</td>
        <td>string</td>
        <td>[random]</td>
        <td>Второй ключ шифрования токена. Максимально эффективный размер - 16 байт.</td>
    </tr>
</table>

Пример конструктора:
```javascript

async function getUserById(id) {
    // Получение данных о пользователе
    return user;
}

async function signInUser(ctx, ...params) {
    // Проверка пароля и получение идентификатора пользователя
    return userId || null;
}

function signOutUser(ctx, ...params) {
    // Обработка выхода пользователя
}

const sessionDirPath = path.join(__dirname, 'sessions');

const koauth = new Koauth(getUserById, signInUser, signOutUser, {
    name: 'myAuth'
})
```

### Методы

<table>
    <tr style="font-weight:bold">
        <td>Метод</td>
        <td>Принимаемые аргументы</td>
        <td>Тип возвращаемого значения</td>
        <td>Описание</td>
    </tr>
    <tr>
        <td>signIn</td>
        <td>ctx, ...params</td>
        <td>Promise&lt;object&gt;</td>
        <td>Аутентификация пользователя. Аргументы (ctx, ...params) также передаются в функцию signInUser, указанную в конструкторе. Возвращает объект, содержащий поля userId и token при успешной аутентификации или null в противном случае. В случае успеха создается сессия пользователя.</td>
    </tr>
    <tr>
        <td>signOut</td>
        <td>ctx, ...params</td>
        <td>Promise&lt;void&gt;</td>
        <td>Выход пользователя. Аргументы (ctx, ...params) также передаются в функцию signInUser, указанную в конструкторе.</td>
    </tr>
    <tr>
        <td>updateSession</td>
        <td>ctx</td>
        <td>Promise&lt;string&gt;</td>
        <td>Ручное обновление сессии. Возвращает новый токен при успешной аутентификации или null в противном случае.</td>
    </tr>
    <tr>
        <td>forceSessionRemove</td>
        <td>userId</td>
        <td>Promise&lt;void&gt;</td>
        <td>Принудительное удаление сессии пользователя.</td>
    </tr>
    <tr>
        <td>getUser</td>
        <td>ctx</td>
        <td>Promise&lt;object&gt;</td>
        <td>Получение данных о пользователе. В случае успешной проверки сессии возвращается результат выполнения функции getUserById, указанной в конструкторе, или null в противном случае. В случае успеха, если необходимо, будет автоматически обновлена сессия.</td>
    </tr>
    <tr>
        <td>freeSessions</td>
        <td></td>
        <td>Promise&lt;void&gt;</td>
        <td>Освобождение дискового пространства от неактуальных сессий.</td>
    </tr>
</table>
