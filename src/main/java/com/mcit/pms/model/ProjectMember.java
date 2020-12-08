package com.mcit.pms.model;

import org.hibernate.validator.constraints.NotEmpty;

public class ProjectMember {

    @NotEmpty(message = "projectID is required")
    private Integer projectID;

    @NotEmpty(message = "userID is required")
    private Integer userID;

    public Integer getUserID() {
        return userID;
    }

    public void setUserID(Integer userID) {
        this.userID = userID;
    }

    public Integer getProjectID() {
        return projectID;
    }

    public void setProjectID(Integer projectID) {
        this.projectID = projectID;
    }
}
