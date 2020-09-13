# socialite-clio-laravel7
Origin: [socialite-clio](https://github.com/cesarga/socialite-clio)

[Clio](https://www.clio.com/) OAuth2 [Provider](http://socialiteproviders.github.io/) for [Laravel 7 Socialite](https://laravel.com/docs/socialite).

## install

```bash
composer require skynetru/socialite-clio-laravel7
```

## register
app/Providers/EventServiceProvider.php
```php
/**
 * The event listener mappings for the application.
 *
 * @var array
*/
protected $listen = [

    // ...

    'SocialiteProviders\\Manager\\SocialiteWasCalled' => [
        'SocialiteProviders\\Clio\\ClioExtendSocialite@handle',
    ],

    // ...

];
```

## configure

config/services.php
```php
return [

    // ...

    'clio' => [
        'base_url' => env('CLIO_BASE_URL', 'https://app.clio.com'),
        'client_id' => env('CLIO_APP_KEY'),
        'client_secret' => env('CLIO_APP_SECRET'),
        'redirect' => env('CLIO_APP_REDIRECT'),
    ],

    // ...

];
```

.env
```
CLIO_BASE_URL=https://eu.app.clio.com
CLIO_APP_KEY=C8dEOljM3EHMK6h4Em8DkmZuzovW6R4JcW06RcMH
CLIO_APP_SECRET=R1bOno3oEt9qUoCYm7vlIKylfJ1nD1OJY0Jc3WVT
CLIO_APP_REDIRECT=http://laravel.local/oauth/clio/callback
```

## start building

```php
return Socialite::driver('clio')->redirect();
```