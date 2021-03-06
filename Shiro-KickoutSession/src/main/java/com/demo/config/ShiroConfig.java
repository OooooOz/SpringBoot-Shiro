package com.demo.config;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.handler.SimpleMappingExceptionResolver;

import com.demo.realm.MyShiroRealm;

import javax.servlet.Filter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

@Configuration
public class ShiroConfig {

    /**
     * Shiro 的Web过滤器ShiroFilterFactoryBean
     * 添加securityManager、过滤链等信息
     * */
	@Bean
	public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager securityManager){
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
		shiroFilterFactoryBean.setSecurityManager(securityManager);

        //loginUrl认证提交地址，如果没有认证将会请求此地址进行认证，请求此地址将由formAuthenticationFilter进行表单认证
		shiroFilterFactoryBean.setLoginUrl("/toLogin.do");
        //通过unauthorizedUrl指定没有权限操作时跳转页面
		shiroFilterFactoryBean.setUnauthorizedUrl("/unFunc.do");

        LinkedHashMap<String, Filter> filtersMap = new LinkedHashMap<>();
        filtersMap.put("kickout", kickoutSessionControlFilter());       //限制同一帐号同时在线的个数
        shiroFilterFactoryBean.setFilters(filtersMap);

		//-----------------------------过虑器链定义------------------------------//
        LinkedHashMap<String, String> perms = new LinkedHashMap<>();
        perms.put("/login.do","anon");
        //其他资源都需要认证  authc 表示需要认证才能进行访问 user表示配置记住我或认证通过可以访问的地址
//        perms.put("/*", "authc");
        perms.put("/userList.do", "user,kickout");
        perms.put("/*", "user");
		shiroFilterFactoryBean.setFilterChainDefinitionMap(perms);  //把权限过滤map设置shiroFilterFactoryBean


		return shiroFilterFactoryBean;
	}

    /**
     * Shrio的安全管理器SecurityManager
     * 注入自定义的Realm和其他属性
     * */
    @Bean(name="securityManager")
    public DefaultWebSecurityManager getDefaultWebSecurityManager(@Qualifier("shiroRealm") MyShiroRealm shiroRealm){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(shiroRealm);
        securityManager.setRememberMeManager(rememberMeManager());	    //实现记住我
        securityManager.setCacheManager(getEhCacheManager());			//实现缓存
        securityManager.setSessionManager(sessionManager());			//session管理
        return securityManager;
    }

    /**
     * 自定义Realm
     * 注入密码比较器等信息
     * */
    @Bean(name="shiroRealm")
    public MyShiroRealm getMyShiroRealm(@Qualifier("credentialsMatcher")HashedCredentialsMatcher credentialsMatcher){
        MyShiroRealm shiroRealm = new MyShiroRealm();
        shiroRealm.setCredentialsMatcher(credentialsMatcher);//设置密码比较器
        shiroRealm.setCachingEnabled(true);
        //启用身份验证缓存，即缓存AuthenticationInfo信息，默认false
        shiroRealm.setAuthenticationCachingEnabled(true);
        //缓存AuthenticationInfo信息的缓存名称 在ehcache-shiro.xml中有对应缓存的配置
        shiroRealm.setAuthenticationCacheName("authenticationCache");
        //启用授权缓存，即缓存AuthorizationInfo信息，默认true
//        shiroRealm.setAuthorizationCachingEnabled(true);
        //缓存AuthorizationInfo信息的缓存名称  在ehcache-shiro.xml中有对应缓存的配置
        shiroRealm.setAuthorizationCacheName("authorizationCache");
        return shiroRealm;
    }

    /**
     * 密码比较器的Bean
     * 设置采用的加密算法及算法迭代次数
     * */
    @Bean(name="credentialsMatcher")
    public HashedCredentialsMatcher getHashedCredentialsMatcher(){
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("md5");	//采用MD5算法加密
        hashedCredentialsMatcher.setHashIterations(1);			//算法循环次数
        return hashedCredentialsMatcher;
    }

    /**
     * 开启shiro注解模式,可以在controller中的方法前加上注解
     * 如 @RequiresPermissions("userInfo:add")
     * @param securityManager
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(@Qualifier("securityManager") SecurityManager securityManager){
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
	
	@Bean //提供对thymeleaf模板引擎的页面中的shiro自定义标签的支持
	public ShiroDialect getShiroDialect(){
		return new ShiroDialect();
	}

	/**
	 * 让某个实例的某个方法的返回值注入为Bean的实例
	 * Spring静态注入
	 * @return
	 */
	@Bean
	public MethodInvokingFactoryBean getMethodInvokingFactoryBean(@Qualifier("shiroRealm") MyShiroRealm shiroRealm){
	    MethodInvokingFactoryBean factoryBean = new MethodInvokingFactoryBean();
	    factoryBean.setStaticMethod("org.apache.shiro.SecurityUtils.setSecurityManager");
	    factoryBean.setArguments(new Object[]{getDefaultWebSecurityManager(shiroRealm)});
	    return factoryBean;
	}
    //---------------------------------------------------------记住我配置-----------------------------------------------------------------//
    /**
     * FormAuthenticationFilter 过滤器 过滤记住我
     */
    @Bean
    public FormAuthenticationFilter formAuthenticationFilter(){
        FormAuthenticationFilter formAuthenticationFilter = new FormAuthenticationFilter();
        formAuthenticationFilter.setRememberMeParam("rememberMe");	//对应前端的checkbox的name = rememberMe，默认值是rememberMe
        return formAuthenticationFilter;
    }

    /**
     * cookie管理对象;记住我功能,rememberMe管理器
     */
    @Bean
    public CookieRememberMeManager rememberMeManager(){
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        cookieRememberMeManager.setCookie(rememberMeCookie());
        //rememberMe cookie加密的密钥 建议每个项目都不一样 默认AES算法 密钥长度(128 256 512 位)
        cookieRememberMeManager.setCipherKey(Base64.decode("4AvVhmFLUs0KTA3Kprsdag=="));
        return cookieRememberMeManager;
    }

    /**
     * cookie对象;会话Cookie模板 ,默认为: JSESSIONID 问题: 与SERVLET容器名冲突,重新定义为sid或rememberMe，自定义
     */
    @Bean
    public SimpleCookie rememberMeCookie(){
        //这个参数是cookie的名称，对应前端的checkbox的name = rememberMe
        SimpleCookie simpleCookie = new SimpleCookie("rememberMe");
        simpleCookie.setHttpOnly(true);     //设为true后，只能通过http访问，javascript无法访问,防止xss读取cookie
        simpleCookie.setPath("/");
        simpleCookie.setMaxAge(60);        //记住我cookie生效时间1min ,单位秒，-1 表示浏览器关闭时失效此 Cookie;
        return simpleCookie;
    }
    //---------------------------------------------------------EhCache-----------------------------------------------------------------//
    /**
     * shiro缓存管理器;设置缓存配置文件
     */
    @Bean
    public EhCacheManager getEhCacheManager(){
        EhCacheManager cacheManager = new EhCacheManager();
        cacheManager.setCacheManagerConfigFile("classpath:cache/ehcache-shiro.xml");
        return cacheManager;
    }
    //---------------------------------------------------------Session-----------------------------------------------------------------//
    /**
     * 配置会话管理器，设定会话超时及保存
     */
    @Bean("sessionManager")
    public SessionManager sessionManager() {
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        Collection<SessionListener> listeners = new ArrayList<SessionListener>();
        listeners.add(sessionListener());                           //配置监听
        sessionManager.setSessionListeners(listeners);

        sessionManager.setSessionIdCookie(sessionIdCookie());
        sessionManager.setSessionDAO(sessionDAO());
        sessionManager.setCacheManager(getEhCacheManager());
	    sessionManager.setGlobalSessionTimeout(300000);	            //全局会话超时时间（单位毫秒），默认30分钟  暂时设置为10秒钟 用来测试
        sessionManager.setDeleteInvalidSessions(true);          	//是否开启删除无效的session对象  默认为true
//	    sessionManager.setSessionValidationSchedulerEnabled(true);  //是否开启定时调度器进行检测过期session 默认为true
        //设置session失效的扫描时间, 清理用户直接关闭浏览器造成的孤立会话 默认为 1个小时
//	    sessionManager.setSessionValidationInterval(5000);	 	    //暂时设置为 5秒 用来测试
        sessionManager.setSessionIdUrlRewritingEnabled(false);		//取消url 后面的 JSESSIONID
        return sessionManager;
    }

    /**
     * 配置session监听
     */
    @Bean("sessionListener")
    public ShiroSessionListener sessionListener(){
        ShiroSessionListener sessionListener = new ShiroSessionListener();
        return sessionListener;
    }

    /**
     * SessionDAO的作用是为Session提供CRUD并进行持久化的一个shiro组件
     * MemorySessionDAO 直接在内存中进行会话维护
     * EnterpriseCacheSessionDAO  提供了缓存功能的会话维护，默认情况下使用MapCache实现，内部使用ConcurrentHashMap保存缓存的会话。
     */
    @Bean
    public SessionDAO sessionDAO() {
        EnterpriseCacheSessionDAO enterpriseCacheSessionDAO = new EnterpriseCacheSessionDAO();
        //使用ehCacheManager
        enterpriseCacheSessionDAO.setCacheManager(getEhCacheManager());
        //设置session缓存的名字 默认为 shiro-activeSessionCache
        enterpriseCacheSessionDAO.setActiveSessionsCacheName("shiro-activeSessionCache");
        //sessionId生成器
        enterpriseCacheSessionDAO.setSessionIdGenerator(sessionIdGenerator());
        return enterpriseCacheSessionDAO;
    }

    /**
     * 配置会话ID生成器
     */
    @Bean
    public SessionIdGenerator sessionIdGenerator() {
        return new JavaUuidSessionIdGenerator();
    }

    /**
     * 查询定义sessionId的cookie，防止与SERVLET容器的冲突，默认JSESSIONID
     * 注意：这里的cookie 不是上面的记住我 cookie 记住我需要一个cookie|session管理也需要自己的cookie
     */
    @Bean("sessionIdCookie")
    public SimpleCookie sessionIdCookie(){
        SimpleCookie simpleCookie = new SimpleCookie("sid");    //cookie的名称
        simpleCookie.setHttpOnly(true); //设为true后，只能通过http访问，javascript无法访问
        simpleCookie.setPath("/");
        simpleCookie.setMaxAge(-1);     //maxAge=-1表示浏览器关闭时失效此Cookie
        return simpleCookie;
    }
    //-------------------------------------------------------session在线人数控制------------------------------------------------------//
    /**
     * 并发登录控制
     */
    @Bean
    public KickoutSessionControlFilter kickoutSessionControlFilter(){
        KickoutSessionControlFilter kickoutSessionControlFilter = new KickoutSessionControlFilter();
        //用于根据会话ID，获取会话进行踢出操作的；
        kickoutSessionControlFilter.setSessionManager(sessionManager());
        //使用cacheManager获取相应的cache来缓存用户登录的会话；用于保存用户—会话之间的关系的；
        kickoutSessionControlFilter.setCacheManager(getEhCacheManager());
        //是否踢出后来登录的，默认是false；即后者登录的用户踢出前者登录的用户；
        kickoutSessionControlFilter.setKickoutAfter(false);
        //同一个用户最大的会话数，默认1；比如2的意思是同一个用户允许最多同时两个人登录；
        kickoutSessionControlFilter.setMaxSession(1);
        //被踢出后重定向到的地址；
        kickoutSessionControlFilter.setKickoutUrl("/toLogin.do?kickout=1");
        return kickoutSessionControlFilter;
    }
}
