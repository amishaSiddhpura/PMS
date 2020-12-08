package com.mcit.pms.model;

import org.hibernate.validator.constraints.NotEmpty;

import java.util.Date;

public class Task {

    @NotEmpty(message = "id is required")
    private Integer id;

    @NotEmpty(message = "title is required")
    private String title;

    @NotEmpty(message = "description is required")
    private String description;

    @NotEmpty(message = "deadline is required")
    private String deadline;

    @NotEmpty(message = "state is required")
    private String state;

    @NotEmpty(message = "user is required")
    private String user;

    private String project;

    private Integer projectId;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDeadline() {
        return deadline;
    }

    public void setDeadline(String deadline) {
        this.deadline = deadline;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getProject() {
        return project;
    }

    public void setProject(String project) {
        this.project = project;
    }

    public Integer getProjectId() {
        return projectId;
    }

    public void setProjectId(Integer projectId) {
        this.projectId = projectId;
    }
}
