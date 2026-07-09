<?php
declare(strict_types=1);

namespace SecurePayload\Laravel;

use Illuminate\Support\ServiceProvider;
use SecurePayload\SecurePayload;

final class SecurePayloadServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/securepayload.php', 'securepayload');

        $this->app->singleton('securepayload.server', function ($app): SecurePayload {
            $config = $app['config']->get('securepayload', []);
            $pdo = null;
            if (($config['server']['key_provider'] ?? 'env') === 'db' && $app->bound('db')) {
                $pdo = $app['db']->connection()->getPdo();
            }

            return SecurePayloadFactory::createServer($config, $pdo);
        });

        $this->app->singleton('securepayload.client', function ($app): SecurePayload {
            return SecurePayloadFactory::createClient($app['config']->get('securepayload', []));
        });

        $this->app->singleton(Services\SecurePayloadClient::class, function ($app): Services\SecurePayloadClient {
            return new Services\SecurePayloadClient(
                $app->make('securepayload.client'),
                (string) $app['config']->get('securepayload.client.base_url', '')
            );
        });

        if ($this->app->runningInConsole()) {
            $this->commands([
                Console\GenerateKeysCommand::class,
                Console\RotateKeyCommand::class,
            ]);
        }
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/securepayload.php' => config_path('securepayload.php'),
        ], 'securepayload-config');

        $this->app->when(Http\Middleware\VerifySecurePayload::class)
            ->needs(SecurePayload::class)
            ->give(fn ($app) => $app->make('securepayload.server'));
    }
}
