package com.mcit.pms.model;

import org.hibernate.validator.constraints.NotEmpty;

public class User {

    @NotEmpty(message = "id is required")
    private Integer id;

    @NotEmpty(message = "username is required")
    private String username;

    @NotEmpty(message = "password is required")
    private String password;

    private String role;

    private Boolean enable;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public Boolean getEnable() {
        return enable;
    }

    public void setEnable(Boolean enable) {
        this.enable = enable;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }
}
