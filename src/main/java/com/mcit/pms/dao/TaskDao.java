package com.mcit.pms.dao;

import com.mcit.pms.model.Task;

import java.util.List;

public interface TaskDao {
    void saveTask(Task task);

    List<Task> showAllTasks();

    Task findByTaskId(String id);

    void deleteTask(Integer id);

    List<Task> getByUserName(String s);

    Task getById(Integer id);

    void updateStatus(Task task);

    void updateTask(Task task);
}
