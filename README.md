# AVB Test - OAuth Authentication Project

Проект для тестирования OAuth аутентификации через социальные сети (Google, Facebook, LinkedIn) с использованием Go backend и Keycloak.

## Структура проекта

```
AVBTest/
├── main.go          # Go backend сервер
├── go.mod           # Go модули
├── go.sum           # Go зависимости
├── frontend/        # Frontend файлы
│   ├── index.html   # Главная страница
│   ├── callback.html # Страница обработки OAuth callback
│   └── style.css    # Стили
└── .gitignore       # Git ignore файл
```

## Требования

- Go 1.19+
- Keycloak сервер
- Google Cloud Console проект с настроенным OAuth 2.0

## Настройка

### 1. Переменные окружения

Создайте файл `.env` в корне проекта со следующими переменными:

```bash
# Keycloak Configuration
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=avbinvest
CLIENT_ID=frontend-client
CLIENT_SECRET=your-client-secret-here

# Redirect URI for OAuth
REDIRECT_URI=http://localhost:8080/realms/avbinvest/broker/google/endpoint

# JWT Secret for signing tokens
JWT_SECRET=your-super-secret-jwt-key-here

# Server Configuration
SERVER_PORT=8081
```

### 2. Google Cloud Console

1. Перейдите в [Google Cloud Console](https://console.cloud.google.com/)
2. Создайте новый проект или выберите существующий
3. Включите Google+ API
4. Создайте OAuth 2.0 Client ID
5. Добавьте в **Authorized redirect URIs**:
   ```
   http://localhost:8080/realms/avbinvest/broker/google/endpoint
   ```

### 3. Keycloak

1. Запустите Keycloak сервер
2. Создайте realm `avbinvest`
3. Создайте client `frontend-client`
4. Настройте Identity Provider для Google
5. Укажите правильный redirect URI

## Запуск

### 1. Backend

```bash
go run main.go
```

Сервер запустится на порту 8081 (или указанном в .env)

### 2. Frontend

Откройте `frontend/index.html` в браузере или используйте Live Server.

## API Endpoints

- `POST /auth/social/login` - Аутентификация через социальные сети
- `GET /auth/user-info` - Получение информации о пользователе
- `POST /auth/refresh` - Обновление токена

## Безопасность

- Никогда не коммитьте `.env` файл в Git
- Используйте сильные секретные ключи
- Настройте CORS правильно для production
- Валидируйте все входящие данные

## Устранение неполадок

### Ошибка redirect_uri_mismatch

Убедитесь, что URL перенаправления в Google Cloud Console точно совпадает с настройками в Keycloak.

### CORS ошибки

Проверьте настройки CORS в `main.go` и убедитесь, что frontend origin разрешен.

## Лицензия

MIT
