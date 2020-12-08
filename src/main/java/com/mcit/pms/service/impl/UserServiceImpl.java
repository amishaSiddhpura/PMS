package com.mcit.pms.service.impl;

import com.mcit.pms.dao.UserDao;
import com.mcit.pms.model.User;
import com.mcit.pms.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;

@Service
@Transactional
public class UserServiceImpl implements UserService {

    @Autowired
    UserDao userDao;

    @Override
    public void insertUser(User user) {
        userDao.insertUser(user);
    }

    @Override
    public List<User> getAllUsers() {
        return userDao.getAllUsers();
    }

    @Override
    public boolean checkUserName(String username) {
        return userDao.checkUserName(username);
    }

    @Override
    public User findByUserName(String username) {
        return userDao.findByUserName(username);
    }

    @Override
    public void updateUser(User user) {
        userDao.updateUser(user);
    }

    @Override
    public void deleteUser(Integer id) {
        userDao.deleteUser(id);
    }

    @Override
    public User getByUser(String username) {
        return userDao.getByUser(username);
    }

    @Override
    public User getById(Integer id) {
        return userDao.getById(id);
    }

    @Override
    public List<User> getunAssignedUsers(Integer projectID) {
        return userDao.getunAssignedUsers(projectID);
    }

    @Override
    public Collection<? extends User> getAssignedUsers(Integer id) {
        return userDao.getAssignedUsers(id);
    }

    @Override
    public List<User> getMembers() {
        return userDao.getMembers();
    }
}
