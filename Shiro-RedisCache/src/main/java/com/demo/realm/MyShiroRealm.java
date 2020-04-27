package com.demo.realm;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.annotation.Resource;

import com.demo.config.MySimpleByteSource;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import com.demo.entity.Function;
import com.demo.entity.User;
import com.demo.service.IUserService;

public class MyShiroRealm extends AuthorizingRealm {

	@Resource
	IUserService userService;
	/**
	 * 授权的方法
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		System.out.println("执行了授权的方法");
		//获取用户对象
		User user = (User)principals.getPrimaryPrincipal();
		//获取用户权限列表
		List<String> perms = new ArrayList<String>();
		//根据用户id获取权限类别
		List<Function> functions = userService.findFuncByUserId(user.getUserId());
		if(functions != null){
			for(Function func : functions){
				perms.add(func.getFuncCode());
			}
		}
		SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
		authorizationInfo.addStringPermissions(perms); //把用户的所有权限类别添加到对象中
		//authorizationInfo.addRoles(roles); //把所有的用户角色添加到对象中
		return authorizationInfo;
	}

	/**
	 * 认证方法
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		System.out.println("---------执行了认证方法---------Time:"+new Date());
		String username = token.getPrincipal().toString();
		System.out.println("username:" + username);
		//需要通过用户名查询用户密码
		User user = userService.findByUsername(username);
		//把user对象封装的AuthenticationInfo中返回
		SimpleAuthenticationInfo authenticationInfo = 
//				new SimpleAuthenticationInfo(user,user.getPassword(),ByteSource.Util.bytes(user.getSalt()),"shiroRealm");
		new SimpleAuthenticationInfo(user,user.getPassword(),new MySimpleByteSource(user.getSalt()),"shiroRealm");

		return authenticationInfo;
	}
	
	
	
	/**
	 * 重写方法,清除当前用户的的 授权缓存
	 * @param principals
	 */
	@Override
	public void clearCachedAuthorizationInfo(PrincipalCollection principals) {
	    super.clearCachedAuthorizationInfo(principals);
	}

	/**
	 * 重写方法，清除当前用户的 认证缓存
	 * @param principals
	 */
	@Override
	public void clearCachedAuthenticationInfo(PrincipalCollection principals) {
	    super.clearCachedAuthenticationInfo(principals);
	}

	@Override
	public void clearCache(PrincipalCollection principals) {
	    super.clearCache(principals);
	}

	/**
	 * 自定义方法：清除所有 授权缓存
	 */
	public void clearAllCachedAuthorizationInfo() {
	    getAuthorizationCache().clear();
	}

	/**
	 * 自定义方法：清除所有认证缓存
	 */
	public void clearAllCachedAuthenticationInfo() {
	    getAuthenticationCache().clear();
	}

	/**
	 * 自定义方法：清除当前用户认证缓存
	 */
	public void clearUserCacheAuthenticationInfo() {
		getAuthenticationCache().remove(SecurityUtils.getSubject().getPrincipals());
	}
    /**
     * 自定义方法：清除当前用户授权缓存
     */
    public void clearUserCachedAuthorizationInfo() {
        User user = (User) SecurityUtils.getSubject().getPrincipal();
        getAuthorizationCache().remove(user.getUserName());
    }
	/**
	 * 自定义方法：清除所有的  认证缓存  和 授权缓存
	 */
	public void clearAllCache() {
	    clearAllCachedAuthenticationInfo();
	    clearAllCachedAuthorizationInfo();
	}
	
}
