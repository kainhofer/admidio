<?php

namespace Admidio\SSO\Entity;

use League\OAuth2\Server\Entities\IdTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\IdTokenEntityTrait;

class IdTokenEntity implements IdTokenEntityInterface {
    use IdTokenEntityTrait;

    private $claims = [];

    public function addClaim($name, $value) {
        $this->claims[$name] = $value;
    }

    public function getClaims() {
        return $this->claims;
    }
}
