<?php

namespace JwtAuth;

interface IdentityInterface
{
    /**
     * 通过用户唯一标志获取用户实例,解析token时会被调用
     *
     * @param string|int $id
     * @return IdentityInterface
     */
    public static function findIdentityById($id);

    /**
     * 通过客户端上送表单获取用户实例,生成token时会被调用
     * 此方法应实现客户用户名密码的认证逻辑并返回认证后的用户实例
     *
     * @param \yii\web\Request $request
     * @return IdentityInterface
     */
    public static function findIdentityFromRequest($request);

    /**
     * 获取用户实例唯一标识，此标志默认会填充到载荷的sub字段
     *
     * @return string|int
     */
    public function getId();

    /**
     * 获取用户自定义载荷
     *
     * @return array
     */
    public function getCustomClaims();

    /**
     * 设置用户自定义载荷
     * 自定义载荷中可包含标准载荷，此时会覆盖原标准载荷默认值
     *
     * @param array $custom_claims
     */
    public function setCustomClaims($custom_claims);

    /**
     * 获取需要记录的白名单内容
     *
     * @return array
     */
    public function getContent();

    /**
     * 设置需要记录的白名单内容
     *
     * @param array $content
     */
    public function setContent($content);
}
