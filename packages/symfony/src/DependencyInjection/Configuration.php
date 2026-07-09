<?php
declare(strict_types=1);

namespace SecurePayload\Symfony\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $tree = new TreeBuilder('securepayload');
        $root = $tree->getRootNode();
        if (!$root instanceof ArrayNodeDefinition) {
            throw new \LogicException('securepayload config root must be an array node.');
        }

        $root
            ->children()
                ->scalarNode('mode')->defaultValue('both')->end()
                ->scalarNode('version')->defaultValue('3')->end()
                ->scalarNode('sign_alg')->defaultValue('hmac')->end()
                ->booleanNode('derive_keys')->defaultFalse()->end()
                ->integerNode('replay_ttl')->defaultValue(120)->end()
                ->integerNode('clock_skew')->defaultValue(60)->end()
                ->arrayNode('bind_headers')->prototype('scalar')->end()->defaultValue([])->end()
                ->arrayNode('server')
                    ->children()
                        ->scalarNode('key_provider')->defaultValue('env')->end()
                        ->scalarNode('pdo_service')->defaultNull()->end()
                        ->arrayNode('db')
                            ->children()
                                ->scalarNode('table')->defaultValue('secure_keys')->end()
                                ->booleanNode('use_key_lifecycle')->defaultFalse()->end()
                                ->booleanNode('use_ed25519')->defaultFalse()->end()
                                ->booleanNode('use_ed25519_server')->defaultFalse()->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('client')
                    ->children()
                        ->scalarNode('base_url')->defaultValue('')->end()
                        ->scalarNode('client_id')->defaultValue('')->end()
                        ->scalarNode('key_id')->defaultValue('')->end()
                        ->scalarNode('hmac_secret')->defaultValue('')->end()
                        ->booleanNode('hmac_secret_is_hex')->defaultFalse()->end()
                        ->scalarNode('aead_key_b64')->defaultValue('')->end()
                        ->scalarNode('ed25519_secret_b64')->defaultValue('')->end()
                        ->scalarNode('ed25519_public_server_b64')->defaultValue('')->end()
                    ->end()
                ->end()
                ->arrayNode('replay_store')
                    ->children()
                        ->scalarNode('driver')->defaultValue('file')->end()
                    ->end()
                ->end()
            ->end();

        return $tree;
    }
}
