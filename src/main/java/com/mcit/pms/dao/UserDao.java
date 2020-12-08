package com.mcit.pms.dao;

import com.mcit.pms.model.User;

import java.util.Collection;
import java.util.List;

public interface UserDao  {

    void insertUser(User user);

    List<User> getAllUsers();

    boolean checkUserName(String username);

    User findByUserName(String username);

    void updateUser(User user);

    void deleteUser(Integer id);

    User getByUser(String username);

    User getById(Integer id);

    List<User> getunAssignedUsers(Integer projectID);

    Collection<? extends User> getAssignedUsers(Integer id);

    List<User> getMembers();
}
