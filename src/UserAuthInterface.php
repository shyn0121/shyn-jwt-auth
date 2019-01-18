<?php

namespace JwtAuth;

interface UserAuthInterface
{
    /**
     * 通过用户唯一标识创建用户实例,解析token时会被调用
     *
     * @param int|string $id
     * @return UserAuthInterface
     */
    public static function getUserById($id);

    /**
     * 通过客户端上送数据创建用户实例,生成token时会被调用
     * 此方法应实现客户端用户名密码的认证逻辑并返回认证后的用户实例
     *
     * @param \yii\web\Request $request
     * @return UserAuthInterface
     */
    public static function getUserByRequest($request);

    /**
     * 获取用户实例唯一标识，此标志默认会填充到载荷的sub字段
     *
     * @return int|string
     */
    public function getId();

    /**
     * 生成用户自定义载荷
     *
     * @return array
     */
    public function genCustomClaims();

    /**
     * 填充用户自定义载荷
     * 自定义载荷中可包含标准载荷，此时会覆盖原标准载荷默认值
     * 若无自定义载荷返回空数组
     *
     * @param array $customClaims
     */
    public function fillCustomClaims($customClaims);

    /**
     * 生成需要记录的白名单内容
     *
     * @return array
     */
    public function genContent();

    /**
     * 填充白名单
     * 若无白名单返回空数组
     *
     * @param array $content
     */
    public function fillContent($content);
}
