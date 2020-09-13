<?php

namespace SocialiteProviders\Clio;

use Laravel\Socialite\Two\ProviderInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;
use Illuminate\Support\Arr;

use GuzzleHttp\ClientInterface;

class Provider extends AbstractProvider implements ProviderInterface
{
    /**
     * Unique Provider Identifier.
     */
    const IDENTIFIER = 'CLIO';

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->getAbsoluteUrl("/oauth/authorize"), $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->getAbsoluteUrl("/oauth/token");
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get($this->getAbsoluteUrl("/api/v4/users/who_am_i"), [
            'headers' => [
                'Authorization' => 'Bearer '.$token,
            ],
            'query' => [
                'fields' => implode(',', [
                    'id',
                    'etag',
                    'name',
                    'last_name',
                    'first_name',
                    'email',
                    'enabled',
                    'account_owner',
                ])
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user['data'])->map([
            'id' => Arr::get($user, 'data.id'),
            'etag' => Arr::get($user, 'data.etag'),
            'name' => Arr::get($user, 'data.name'),
            'last_name' => Arr::get($user, 'data.last_name'),
            'first_name' => Arr::get($user, 'data.first_name'),
            'email' => Arr::get($user, 'data.email'),
            'enabled' => Arr::get($user, 'data.enabled'),
            'account_owner' => Arr::get($user, 'data.account_owner'),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code'
        ]);
    }

    /**
     * Get the base URL for the API.
     *
     * @return string
     */
    protected function getBaseUrl()
    {
        return config('services.clio.base_url', 'https://app.clio.com');
    }

    /**
     * Get an absolute URL from a relative path.
     *
     * @return string
     */
    protected function getAbsoluteUrl($path)
    {
        return "{$this->getBaseUrl()}{$path}";
    }
}
