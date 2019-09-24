<?php namespace Anomaly\ThrottleSecurityCheckExtension\Command;

use Anomaly\SettingsModule\Setting\Contract\SettingRepositoryInterface;
use Anomaly\ThrottleSecurityCheckExtension\ThrottleSecurityCheckExtension;
use Anomaly\UsersModule\User\UserAuthenticator;

/**
 * Class ThrottleLogin
 *
 * @link   http://pyrocms.com/
 * @author PyroCMS, Inc. <support@pyrocms.com>
 * @author Ryan Thompson <ryan@pyrocms.com>
 */
class ThrottleLogin
{

    /**
     * Handle the command.
     *
     * @param  UserAuthenticator $authenticator
     * @param  SettingRepositoryInterface $settings
     * @param  ThrottleSecurityCheckExtension $extension
     * @return bool
     */
    public function handle(
        UserAuthenticator $authenticator,
        SettingRepositoryInterface $settings,
        ThrottleSecurityCheckExtension $extension
    ) {
        $maxAttempts      = $settings->value('anomaly.extension.throttle_security_check::max_attempts', 5);
        $lockoutInterval  = $settings->value('anomaly.extension.throttle_security_check::lockout_interval', 1);
        $throttleInterval = $settings->value('anomaly.extension.throttle_security_check::throttle_interval', 1);

        $attempts   = cache($extension->getNamespace('attempts:' . request()->ip()), 1);
        $expiration = cache($extension->getNamespace('expiration:' . request()->ip()));

        if ($expiration || $attempts >= $maxAttempts) {
            cache([$extension->getNamespace('attempts:' . request()->ip()) => $attempts + 1], $throttleInterval);
            cache([$extension->getNamespace('expiration:' . request()->ip()) => time()], $lockoutInterval);

            $authenticator->logout(); // Just for safe measure.

            return dispatch_now(new MakeResponse());
        }

        cache([$extension->getNamespace('attempts:' . request()->ip()) => $attempts + 1], $throttleInterval);

        return true;
    }
}
