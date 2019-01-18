<?php

namespace JwtAuth\Models;

use yii\base\Model;
use JwtAuth\UserAuthInterface;

abstract class AbstractIdentityModel extends Model implements UserAuthInterface
{
    /**
     * @var array 自定义载荷
     */
    private $customClaims = [];

    /**
     * @var array 白名单内容
     */
    private $content = [];

    /**
     * @param array $customClaims
     */
    public function fillCustomClaims($customClaims)
    {
        $this->customClaims = $customClaims;
    }

    /**
     * @param array $content
     */
    public function fillContent($content)
    {
        $this->content = $content;
    }

    /**
     * @return array
     */
    public function getCustomClaims()
    {
        if (!isset($this->customClaims)) {
            $this->customClaims = $this->genCustomClaims();
        }
        return $this->customClaims;
    }

    /**
     * @param array $customClaims
     */
    public function setCustomClaims($customClaims)
    {
        $this->customClaims = $customClaims;
    }

    /**
     * @return array
     */
    public function getContent()
    {
        if (!isset($this->content)) {
            $this->content = $this->content();
        }
        return $this->content;
    }

    /**
     * @param array $content
     */
    public function setContent($content)
    {
        $this->content = $content;
    }
}
