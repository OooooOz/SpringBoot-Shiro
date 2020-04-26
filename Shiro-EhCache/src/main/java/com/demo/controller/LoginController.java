package com.demo.controller;

import java.util.List;

import javax.annotation.Resource;

import com.demo.realm.MyShiroRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import com.demo.entity.User;
import com.demo.service.IUserService;

@Controller
public class LoginController {

	@Resource
	IUserService userService;

	@RequestMapping("/toLogin.do")
	public String toLogin() {
		return "login";
	}

	@RequestMapping("/login.do")
	public String login(String username, String password,boolean rememberMe, Model model) {
		// 判断用户名密码是否为空
		if (username != null && !"".equals(username) && password != null && !"".equals(password)) {
			// 1.获取subject
			Subject subject = SecurityUtils.getSubject();
			// 2.创建验证用的令牌对象
			UsernamePasswordToken token = new UsernamePasswordToken(username, password,rememberMe);
			try {
				//3.登陆认证
				subject.login(token);
				boolean flag = subject.isAuthenticated();	//判断是否通过认证
				//4.认证结果处理
				if(flag){
					System.out.println("登录成功！");
					User user = (User)subject.getPrincipal();
					model.addAttribute("user",user);
					return "redirect:userList.do";
				}else{
					model.addAttribute("msg","登录认证失败！");
					return "login";
				}
			
			} catch (Exception e) {
				model.addAttribute("msg","登录认证失败！");
				if (e instanceof LockedAccountException) {
					model.addAttribute("msg","失败次数过多，用户已锁定，五分钟后再试");
				}
			}
		}
		return "login";
	}
	@RequestMapping("/userList.do")
	//@ResponseBody
	public String userList(Model model){
		//查询所有的用户信息并且显示到页面上
		Subject subject = SecurityUtils.getSubject();
		System.out.println("------是否通过认证:"+subject.isAuthenticated()+"------是否记住我:"+subject.isRemembered());
		List<User> list = userService.findAll();
		model.addAttribute("userList", list);
		return "userList";
	}

	@RequestMapping("/toAdd.do")
	public String addFunction(Model model){
        User user = (User) SecurityUtils.getSubject().getPrincipal();
        //添加权限
        //打断点，利用断点时间直接修改数据库，懒得写代码

		DefaultWebSecurityManager securityManager = (DefaultWebSecurityManager)SecurityUtils.getSecurityManager();
		MyShiroRealm shiroRealm = (MyShiroRealm) securityManager.getRealms().iterator().next();
		//清除当前登录者的认证缓存
        shiroRealm.getAuthenticationCache().remove(user.getUserName());
        //清除当前登录者的授权缓存
        shiroRealm.getAuthorizationCache().remove(SecurityUtils.getSubject().getPrincipals());
        List<User> list = userService.findAll();
        model.addAttribute("userList", list);
        return "userList";
	}

	@RequestMapping("/unFunc.do")
	public String noFunc(){
		return "unFunc";
	}

	@RequestMapping("/logout.do")
	public String logout(){
		//清除session
		return "login";
	}
}
