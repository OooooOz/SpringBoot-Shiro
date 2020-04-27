package com.demo.config;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.crazycake.shiro.RedisManager;
import org.crazycake.shiro.RedisSessionDAO;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


import com.demo.realm.MyShiroRealm;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import javax.servlet.Filter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;

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
        securityManager.setCacheManager(redisCacheManager());		    //配置 redis缓存管理器
        securityManager.setSessionManager(redisSessionManager());		//配置 redissession管理
        return securityManager;
    }

    /**
     * 自定义Realm
     * 注入密码比较器等信息
     * */
    @Bean(name="shiroRealm")
    public MyShiroRealm getMyShiroRealm(@Qualifier("credentialsMatcherLimit")HashedCredentialsMatcher credentialsMatcher){
        MyShiroRealm shiroRealm = new MyShiroRealm();
        shiroRealm.setCredentialsMatcher(credentialsMatcher);//设置自定义密码比较器，beanId=credentialsMatcherLimit
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

    //---------------------------------------------------------Session-----------------------------------------------------------------//

    /**
     * 配置session监听
     */
    @Bean("sessionListener")
    public ShiroSessionListener sessionListener(){
        ShiroSessionListener sessionListener = new ShiroSessionListener();
        return sessionListener;
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
        kickoutSessionControlFilter.setSessionManager(redisSessionManager());
        //使用cacheManager获取相应的cache来缓存用户登录的会话；用于保存用户—会话之间的关系的；
        kickoutSessionControlFilter.setCacheManager(redisCacheManager());
        //是否踢出后来登录的，默认是false；即后者登录的用户踢出前者登录的用户；
        kickoutSessionControlFilter.setKickoutAfter(false);
        //同一个用户最大的会话数，默认1；比如2的意思是同一个用户允许最多同时两个人登录；
        kickoutSessionControlFilter.setMaxSession(1);
        //被踢出后重定向到的地址；
        kickoutSessionControlFilter.setKickoutUrl("/toLogin.do?kickout=1");
        return kickoutSessionControlFilter;
    }

    //-------------------------------------------------------session登陆失败次数控制----------------------------------------------------//
    /**
     * 配置密码比较器
     */
    @Bean("credentialsMatcherLimit")
    public RetryLimitHashedCredentialsMatcher retryLimitHashedCredentialsMatcher(){
        RetryLimitHashedCredentialsMatcher retryLimitHashedCredentialsMatcher = new RetryLimitHashedCredentialsMatcher(redisCacheManager());
        retryLimitHashedCredentialsMatcher.setHashAlgorithmName("MD5");	//加密算法的名称
        retryLimitHashedCredentialsMatcher.setHashIterations(1);		//配置加密的次数
        retryLimitHashedCredentialsMatcher.setRetryLimitNum(3);		//配置加密的次数
        //retryLimitHashedCredentialsMatcher.setStoredCredentialsHexEncoded(true);//是否存储为16进制
        return retryLimitHashedCredentialsMatcher;
    }

    //-------------------------------------------------------RedisCache---------------------------------------------------//
    /**
     * 配置会话管理器，设定会话超时及保存
     */
    @Bean("redisSessionManager")
    public SessionManager redisSessionManager() {
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        Collection<SessionListener> listeners = new ArrayList<SessionListener>();
        //配置监听
        listeners.add(sessionListener());
        sessionManager.setSessionListeners(listeners);
        sessionManager.setSessionIdCookie(sessionIdCookie());
        sessionManager.setSessionDAO(redisSessionDAO());
        sessionManager.setCacheManager(redisCacheManager());
        //sessionManager.setGlobalSessionTimeout(60000);    //全局会话超时时间（单位毫秒），默认30分钟  暂时设置为10秒钟 用来测试
        sessionManager.setDeleteInvalidSessions(true);
        //取消url 后面的 JSESSIONID
        sessionManager.setSessionIdUrlRewritingEnabled(false);
        return sessionManager;

    }

    @Bean("redisSessionDAO")
    public SessionDAO redisSessionDAO() {
        RedisSessionDAO redisSessionDAO = new RedisSessionDAO();
        redisSessionDAO.setRedisManager(redisManager());
        redisSessionDAO.setExpire(3000);//session在redis中的保存时间,最好大于session会话超时时间,单位s
        return redisSessionDAO;
    }

    //redisSessionDAO需要注入redisManager
    @Bean
    public RedisManager redisManager(){
        RedisManager redisManager = new RedisManager();
        redisManager.setHost("192.168.2.104");
        redisManager.setPort(6379);
        //redisManager.setPassword("123456");
        return redisManager;
    }

    /**
     *  注入redisTemplate工具
     * */
    @Bean
    public StringRedisTemplate redisTemplate(JedisConnectionFactory jedisConnectionFactory){
        StringRedisTemplate redisTemplate = new StringRedisTemplate(jedisConnectionFactory);

        StringRedisSerializer stringRedisSerializer = new StringRedisSerializer();
        JdkSerializationRedisSerializer jdkSerializationRedisSerializer = new JdkSerializationRedisSerializer();
        GenericJackson2JsonRedisSerializer genericJackson2JsonRedisSerializer = new GenericJackson2JsonRedisSerializer();

        redisTemplate.setKeySerializer(stringRedisSerializer);              //键值序列化方式
        redisTemplate.setValueSerializer(jdkSerializationRedisSerializer);
        redisTemplate.setHashKeySerializer(stringRedisSerializer);          //绑定hash的序列化方式
        redisTemplate.setHashValueSerializer(jdkSerializationRedisSerializer);
//		redisTemplate.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        return redisTemplate;

    }
    /**
     *  Jedis连接工厂，Springboot2.0以上采用redisStandaloneConfiguration
     * */
    @Bean
    public JedisConnectionFactory jedisConnectionFactory(RedisStandaloneConfiguration redisStandaloneConfiguration){
        JedisConnectionFactory jedisConnectionFactory = new JedisConnectionFactory(redisStandaloneConfiguration);
        return jedisConnectionFactory;
    }

    //JedisConnectionFactory注入的redis配置
    @Bean
    public RedisStandaloneConfiguration redisStandaloneConfiguration(){
        RedisStandaloneConfiguration redisStandaloneConfiguration = new RedisStandaloneConfiguration();
        redisStandaloneConfiguration.setHostName("192.168.2.104");
        redisStandaloneConfiguration.setPort(6379);
        //redisStandaloneConfiguration.setPassword(RedisPassword);
        return redisStandaloneConfiguration;
    }

    /**
     *  自定义封装的redis缓存操作类
     * */
    @Bean("redisCacheManager")
    public RedisCacheManager redisCacheManager(){
        RedisCacheManager redisCacheManager = new RedisCacheManager();
        return redisCacheManager;
    }
}
