package com.mcit.pms.model;

import org.hibernate.validator.constraints.NotEmpty;

import java.util.Date;

public class Project {

    @NotEmpty(message = "id is required")
    private Integer id;

    @NotEmpty(message = "title is required")
    private String title;

    @NotEmpty(message = "description is required")
    private String description;

    @NotEmpty(message = "startDate is required")
    private String startDate;

    @NotEmpty(message = "endDate is required")
    private String endDate;

    @NotEmpty(message = "createdBy is required")
    private String createdBy;

    private Integer projectMembers;

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

    public String getStartDate() {
        return startDate;
    }

    public void setStartDate(String startDate) {
        this.startDate = startDate;
    }

    public String getEndDate() {
        return endDate;
    }

    public void setEndDate(String endDate) {
        this.endDate = endDate;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public Integer getProjectMembers() {
        return projectMembers;
    }

    public void setProjectMembers(Integer projectMembers) {
        this.projectMembers = projectMembers;
    }
}
