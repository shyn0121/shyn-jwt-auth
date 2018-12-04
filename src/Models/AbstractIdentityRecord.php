<?php

namespace JwtAuth\Models;

use yii\db\ActiveRecord;
use JwtAuth\IdentityInterface;

abstract class AbstractIdentityRecord extends ActiveRecord implements IdentityInterface
{
    /**
     * @var array 自定义载荷
     */
    private $custom_claims = [];

    /**
     * @var array 白名单内容
     */
    private $content = [];

    /**
     * @var bool
     */
    private $has_custom_claims = false;

    /**
     * @var bool
     */
    private $has_content = false;

    /**
     * @return array 创建用户自定义载荷
     */
    abstract public function genCustomClaims();

    /**
     * @return array 创建白名单内容
     */
    abstract public function genContent();

    /**
     * @return array
     */
    public function getCustomClaims()
    {
        if ($this->has_custom_claims) {
            return $this->custom_claims;
        }
        return $this->genCustomClaims();
    }

    /**
     * @param array $custom_claims
     */
    public function setCustomClaims($custom_claims)
    {
        $this->custom_claims = $custom_claims;
        $this->markCustomClaims();
    }

    /**
     * @return array
     */
    public function getContent()
    {
        if ($this->has_content) {
            return $this->content;
        }
        return $this->genContent();
    }

    /**
     * @param array $content
     */
    public function setContent($content)
    {
        $this->content = $content;
        $this->markContent();
    }

    /**
     *
     */
    private function markCustomClaims()
    {
        $this->has_custom_claims = true;
    }

    /**
     *
     */
    private function markContent()
    {
        $this->has_content = true;
    }
}
