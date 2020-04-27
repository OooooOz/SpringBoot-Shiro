package com.demo.config;

import java.util.concurrent.atomic.AtomicInteger;

import com.demo.dao.IUserMapper;
import com.demo.entity.User;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.springframework.beans.factory.annotation.Autowired;


/**
 * @description: 登陆次数限制
 */
public class RetryLimitHashedCredentialsMatcher extends HashedCredentialsMatcher {

    @Autowired
    private IUserMapper userMapper;
    private Cache<String, AtomicInteger> passwordRetryCache;
    private int retryLimitNum;

    public RetryLimitHashedCredentialsMatcher(CacheManager cacheManager) {
        passwordRetryCache = cacheManager.getCache("passwordRetryCache");
    }

    public void setRetryLimitNum(int retryLimitNum) {
        this.retryLimitNum = retryLimitNum;
    }

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {

        //获取用户名
        String username = (String)token.getPrincipal();
        //获取用户登录次数
        AtomicInteger retryCount = passwordRetryCache.get(username);
        if (retryCount == null) {
            //如果用户没有登陆过,登陆次数加1 并放入缓存
            retryCount = new AtomicInteger(0);
            passwordRetryCache.put(username, retryCount);
        }
        if (retryCount.incrementAndGet() >retryLimitNum) {
            //如果用户登陆失败次数大于retryLimitNum, 抛出锁定用户异常  并修改数据库字段
            User user = userMapper.findByUserName(username);
            if (user != null && 0==user.getStatus()){
                //数据库字段 默认为 0  就是正常状态 所以 要改为1
                //修改数据库的状态字段为锁定
                user.setStatus(1);
                userMapper.update(user);
            }
            System.out.println("锁定用户" + user.getUserName());
            //抛出用户锁定异常
            throw new LockedAccountException();
        }
        //判断用户账号和密码是否正确
        boolean matches = super.doCredentialsMatch(token, info);
        if (matches) {
            //如果正确,从缓存中将用户登录计数 清除
            passwordRetryCache.remove(username);
        }
        return matches;
    }

    /**
     * 根据用户名 解锁用户
     */
    public void unlockAccount(String username){
        User user = userMapper.findByUserName(username);
        if (user != null){
            //修改数据库的状态字段为锁定
            user.setStatus(0);
            userMapper.update(user);
            passwordRetryCache.remove(username);
        }
    }

}