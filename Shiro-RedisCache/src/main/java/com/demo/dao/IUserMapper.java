package com.demo.dao;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

import com.demo.entity.User;

@Mapper
public interface IUserMapper {

	public User login(String username);
	
	public List<User> findAll();

	public boolean update(User user);

	public User findByUserName(String username);
}
