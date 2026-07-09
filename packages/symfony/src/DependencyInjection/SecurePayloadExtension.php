<?php
declare(strict_types=1);

namespace SecurePayload\Symfony\DependencyInjection;

use SecurePayload\Symfony\EventSubscriber\VerifySecurePayloadSubscriber;
use SecurePayload\SecurePayload;
use SecurePayload\Symfony\SecurePayloadFactory;
use SecurePayload\Symfony\Service\SecurePayloadClient;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Reference;

final class SecurePayloadExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $config = $this->processConfiguration(new Configuration(), $configs);
        $container->setParameter('securepayload.config', $config);

        $serverDef = new Definition(SecurePayload::class);
        $serverDef->setFactory([SecurePayloadFactory::class, 'createServer']);
        $serverDef->setArguments([$config, null]);
        if (($config['server']['key_provider'] ?? 'env') === 'db' && !empty($config['server']['pdo_service'])) {
            $serverDef->replaceArgument(1, new Reference($config['server']['pdo_service']));
        }
        $container->setDefinition('securepayload.server', $serverDef);

        $clientDef = new Definition(SecurePayload::class);
        $clientDef->setFactory([SecurePayloadFactory::class, 'createClient']);
        $clientDef->setArguments([$config]);
        $container->setDefinition('securepayload.client', $clientDef);

        $container->register(SecurePayloadClient::class)
            ->setAutowired(true)
            ->setArgument('$client', new Reference('securepayload.client'))
            ->setArgument('$baseUrl', $config['client']['base_url'] ?? '');

        $container->register(VerifySecurePayloadSubscriber::class)
            ->setAutowired(false)
            ->setArgument('$server', new Reference('securepayload.server'))
            ->addTag('kernel.event_subscriber');
    }

    public function getAlias(): string
    {
        return 'securepayload';
    }
}
