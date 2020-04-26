package com.demo.service;

import java.util.List;

import com.demo.entity.Function;
import com.demo.entity.User;

public interface IUserService {

	public User findByUsername(String username);

	public List<User> findAll();

	public List<Function> findFuncByUserId(Integer userId);
}
