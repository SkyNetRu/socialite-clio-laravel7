<?php

namespace SocialiteProviders\Clio;

use SocialiteProviders\Manager\SocialiteWasCalled;

class ClioExtendSocialite
{
    /**
     * Execute the provider.
     *
     * @param \SocialiteProviders\Manager\SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite('clio', __NAMESPACE__.'\Provider');
    }
}
