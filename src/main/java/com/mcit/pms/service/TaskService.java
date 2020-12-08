package com.mcit.pms.service;

import com.mcit.pms.model.Task;

import java.util.List;

public interface TaskService {
    void saveTask(Task task);

    List<Task> showAllTasks();

    Task findByTaskId(String id);

    void deleteTask(Integer id);

    List<Task> getByUserName(String authenticationName);

    Task getById(Integer id);

    void updateStatus(Task task);

    void updateTask(Task task);
}
