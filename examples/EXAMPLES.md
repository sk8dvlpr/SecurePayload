# Examples Guide

Contoh integrasi **server-side verification** sebelum controller/handler dieksekusi:
- **Laravel** → `examples/laravel/SecurePayloadMiddleware.php`
- **CodeIgniter 4** → `examples/ci4/SecurePayloadFilter.php`
- **Slim (PSR-15)** → `examples/slim/SecurePayloadMiddleware.php`
- **Symfony** → `examples/symfony/SecurePayloadSubscriber.php`
- **Lumen** → `examples/lumen/SecurePayloadMiddleware.php`

## Registrasi Singkat

### Laravel
1. Simpan file ke `app/Http/Middleware/SecurePayloadMiddleware.php`
2. Daftarkan di `app/Http/Kernel.php` pada `$routeMiddleware` atau `$middleware`.

### CodeIgniter 4
1. Simpan ke `app/Filters/SecurePayloadFilter.php`
2. Tambahkan alias di `app/Config/Filters.php`, lalu pasang pada routes/group.

### Slim (PSR-15)
1. Simpan ke `src/Middleware/SecurePayloadMiddleware.php`
2. Tambahkan ke app container/route group:
   ```php
   $app->add(new \App\Middleware\SecurePayloadMiddleware());
   ```

### Symfony
1. Simpan ke `src/EventSubscriber/SecurePayloadSubscriber.php`
2. Pastikan service auto-discovery aktif (default di Symfony Flex). Kalau manual:
   ```yaml
   # config/services.yaml
   services:
     App\EventSubscriber\SecurePayloadSubscriber:
       tags: ['kernel.event_subscriber']
   ```

### Lumen
1. Simpan ke `app/Http/Middleware/SecurePayloadMiddleware.php`
2. Registrasi di `bootstrap/app.php`:
   ```php
   $app->routeMiddleware([
       'securepayload' => App\Http\Middleware\SecurePayloadMiddleware::class,
   ]);
   // Lalu di routes: $router->group(['middleware' => 'securepayload'], function () { ... });
   ```
