package com.demo.service.impl;

import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import com.demo.dao.IFunctionMapper;
import com.demo.dao.IUserMapper;
import com.demo.entity.Function;
import com.demo.entity.User;
import com.demo.service.IUserService;
@Service
public class UserServiceImpl implements IUserService {

	@Resource
	IUserMapper userMapper;
	@Resource
	IFunctionMapper functionMapper;
	@Override
	public User findByUsername(String username) {
		return userMapper.login(username);
	}
	@Override
	public List<User> findAll() {
		
		return userMapper.findAll();
	}
	@Override
	public List<Function> findFuncByUserId(Integer userId) {
		return functionMapper.findFunctionByUserId(userId);
	}

}
