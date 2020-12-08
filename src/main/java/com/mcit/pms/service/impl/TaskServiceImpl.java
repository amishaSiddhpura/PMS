package com.mcit.pms.service.impl;

import com.mcit.pms.dao.TaskDao;
import com.mcit.pms.model.Task;
import com.mcit.pms.service.TaskService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class TaskServiceImpl implements TaskService {

    @Autowired
    TaskDao taskDao;

    @Override
    public void saveTask(Task task) {
        taskDao.saveTask(task);
    }

    @Override
    public List<Task> showAllTasks() {
        return taskDao.showAllTasks();
    }

    @Override
    public Task findByTaskId(String id) {
        return taskDao.findByTaskId(id);
    }

    @Override
    public void deleteTask(Integer id) {
        taskDao.deleteTask(id);
    }

    @Override
    public List<Task> getByUserName(String name) {
        return taskDao.getByUserName(name);
    }

    @Override
    public Task getById(Integer id) {
        return taskDao.getById(id);
    }

    @Override
    public void updateStatus(Task task) {
        taskDao.updateStatus(task);
    }

    @Override
    public void updateTask(Task task) {
        taskDao.updateTask(task);
    }
}
